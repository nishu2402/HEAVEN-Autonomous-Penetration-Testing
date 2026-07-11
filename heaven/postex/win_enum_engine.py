"""HEAVEN — self-contained Windows post-exploitation enumeration engine.

The Linux side (:mod:`heaven.postex.enum_engine`) proved the pattern: a small,
auditable battery of **read-only** commands run over one SSH connection, parsed
by a **pure, deterministic** function into structured, MITRE-tagged privilege-
escalation findings. This module does the same for Windows targets — the gap
that made HEAVEN's post-ex effectively Linux-only.

Windows 10 / Server 2019+ ship OpenSSH, so the transport is identical to the
Linux engine (``asyncssh``). The default shell is ``cmd.exe``; the battery uses
native ``cmd`` builtins plus a couple of ``powershell -NonInteractive`` one-liners
that emit pipe-delimited output the parser can split without guesswork.

What it finds (all deterministic from command output, no live host in tests):

  * **AlwaysInstallElevated** (HKLM *and* HKCU = 1) → any MSI installs as SYSTEM.
  * **Unquoted service paths** with a space in a non-Windows directory.
  * **Service binaries in user-writable locations** (ProgramData / Users / non
    Program Files roots) → SYSTEM code execution on restart.
  * **Dangerous privileges** (SeImpersonate, SeAssignPrimaryToken, SeBackup,
    SeRestore, SeTakeOwnership, SeDebug, SeLoadDriver) → token-theft / SAM read.
  * **Autologon credentials** in the Winlogon registry key.
  * **UAC disabled** (EnableLUA = 0).
  * **Saved credentials** (``cmdkey /list``) and **unattend/sysprep** files.

If the current token is already elevated (Administrators / High integrity /
SYSTEM), escalation is moot and only facts are returned — mirroring the Linux
``already_root`` short-circuit. Degrades gracefully without ``asyncssh``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.postex import mitre_attack as mitre
from heaven.utils.logger import get_logger

logger = get_logger("postex.win_enum")


def _as_text(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data or ""


# ── The command battery ─────────────────────────────────────────────────────
# Every command is read-only and self-terminating. `2>nul` suppresses errors so
# a missing key/tool yields an empty string rather than noise.
WIN_COMMAND_BATTERY: dict[str, str] = {
    # Identity, groups and privileges in one shot.
    "whoami": "whoami /all 2>nul",
    "sysinfo": "systeminfo 2>nul",
    "hostname": "hostname 2>nul",
    "users": "net user 2>nul",
    "net_listen": "netstat -ano 2>nul | findstr LISTENING",
    "net_iface": "ipconfig 2>nul",
    # AlwaysInstallElevated needs BOTH hives set to 1.
    "aie_hklm": (
        "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated 2>nul"
    ),
    "aie_hkcu": (
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated 2>nul"
    ),
    # Autologon plaintext credentials.
    "autologon": (
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Winlogon\" 2>nul"
    ),
    # UAC posture.
    "uac": (
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System /v EnableLUA 2>nul"
    ),
    # Services: Name|PathName|StartMode|StartName, one per line.
    "services": (
        "powershell -NonInteractive -NoProfile -Command "
        "\"Get-CimInstance Win32_Service | ForEach-Object "
        "{ $_.Name + '|' + $_.PathName + '|' + $_.StartMode + '|' + $_.StartName }\" "
        "2>nul"
    ),
    # Saved credentials in the vault.
    "cmdkey": "cmdkey /list 2>nul",
    # Unattended-install answer files often keep a plaintext local admin password.
    "unattend": (
        "for %f in ("
        "C:\\Windows\\Panther\\Unattend.xml "
        "C:\\Windows\\Panther\\Unattended.xml "
        "C:\\Windows\\System32\\Sysprep\\Unattend.xml "
        "C:\\Windows\\System32\\Sysprep\\Panther\\Unattend.xml "
        "C:\\unattend.xml C:\\sysprep.inf"
        ") do @if exist %f echo UNATTEND_FILE:%f"
    ),
    # Writable directories on the system PATH (icacls each; parser scans markers).
    "path_acl": (
        "powershell -NonInteractive -NoProfile -Command "
        "\"$env:PATH -split ';' | Where-Object { $_ } | ForEach-Object "
        "{ $p=$_; try { (icacls $p 2>$null) -join ' ' | "
        "ForEach-Object { if ($_ -match '(Everyone|BUILTIN\\\\Users|Authenticated Users)"
        ".*(\\(F\\)|\\(M\\)|\\(W\\))') { 'WRITABLE_PATH:' + $p } } } catch {} }\" 2>nul"
    ),
}

# Windows dirs that are trusted (a service binary here is not, on its own, a
# writable-location finding). Everything else is suspect.
_TRUSTED_ROOTS = ("c:\\windows", "c:\\program files", "c:\\program files (x86)")

# Privileges that map to a known local-escalation primitive.
_DANGEROUS_PRIVILEGES: dict[str, tuple[str, str, str]] = {
    # name (lower) -> (severity, abuse note, technique)
    "seimpersonateprivilege": (
        "high", "'Potato' family token theft → SYSTEM (JuicyPotato/PrintSpoofer)",
        mitre.T_TOKEN_IMPERSONATION),
    "seassignprimarytokenprivilege": (
        "high", "Assign a primary token → run a process as SYSTEM",
        mitre.T_TOKEN_IMPERSONATION),
    "sebackupprivilege": (
        "high", "Read any file (SAM/SYSTEM hives) → offline hash extraction",
        mitre.T_CREDS_IN_FILES),
    "serestoreprivilege": (
        "high", "Write any file → overwrite a SYSTEM-run binary/service",
        mitre.T_FILE_PERMS),
    "setakeownershipprivilege": (
        "high", "Take ownership of any object → grant yourself full control",
        mitre.T_FILE_PERMS),
    "sedebugprivilege": (
        "high", "Debug/inject into a SYSTEM process → token or code exec",
        mitre.T_TOKEN_IMPERSONATION),
    "seloaddriverprivilege": (
        "high", "Load a (vulnerable) kernel driver → ring-0 compromise",
        mitre.T_KERNEL_EXPLOIT),
    "setcbprivilege": (
        "critical", "Act as part of the OS → arbitrary token creation",
        mitre.T_TOKEN_IMPERSONATION),
}


# ── Structured result ───────────────────────────────────────────────────────
@dataclass
class WinHostFacts:
    hostname: str = ""
    os: str = ""
    build: str = ""
    username: str = ""
    is_admin: bool = False
    is_system: bool = False
    integrity: str = ""
    groups: list[str] = field(default_factory=list)
    privileges: list[str] = field(default_factory=list)  # enabled dangerous ones
    local_users: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "os": self.os, "build": self.build,
            "username": self.username, "is_admin": self.is_admin,
            "is_system": self.is_system, "integrity": self.integrity,
            "groups": self.groups, "privileges": self.privileges,
            "local_users": self.local_users,
            "listening_ports": self.listening_ports,
            "interfaces": self.interfaces,
        }


@dataclass
class WinEnumResult:
    host: str
    user: str
    success: bool
    facts: WinHostFacts = field(default_factory=WinHostFacts)
    vectors: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for v in self.vectors:
            f: dict[str, Any] = {
                "target": self.host,
                "vuln_type": "privesc",
                "title": v.get("title", "Windows privilege escalation vector"),
                "severity": v.get("severity", "high"),
                "confidence": v.get("confidence", 0.85),
                "evidence": {
                    "source": "postex.win_enum_engine",
                    "platform": "windows",
                    "user": self.user,
                    "detail": v.get("detail", ""),
                    "abuse": v.get("abuse", ""),
                    "signals": v.get("signals", []),
                    "needs_manual_confirm": v.get("needs_manual_confirm", False),
                },
            }
            mitre.tag(f, *v.get("techniques", []))
            findings.append(f)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "user": self.user, "success": self.success,
            "error": self.error, "platform": "windows",
            "facts": self.facts.to_dict(), "vectors": self.vectors,
            "vector_count": len(self.vectors),
        }


# ── Pure parser (no SSH, fully deterministic → unit-testable) ────────────────
def parse_windows_enumeration(
    host: str, user: str, outputs: dict[str, str],
) -> WinEnumResult:
    """Turn raw ``{battery_key: output}`` into a structured, scored result."""
    facts = WinHostFacts(username=user)
    vectors: list[dict[str, Any]] = []

    _parse_whoami(outputs.get("whoami", ""), facts)
    facts.hostname = _first_nonempty(outputs.get("hostname", "")) or host
    _parse_sysinfo(outputs.get("sysinfo", ""), facts)
    facts.local_users = _parse_users(outputs.get("users", ""))
    facts.listening_ports = _parse_listen(outputs.get("net_listen", ""))
    facts.interfaces = _parse_ifaces(outputs.get("net_iface", ""))

    elevated = facts.is_admin or facts.is_system

    # 1. AlwaysInstallElevated — needs BOTH hives = 1. Always report (even for an
    #    admin it confirms a mis-config), but it is an escalation only if not yet
    #    elevated, so score critical only in that case.
    if _aie_enabled(outputs.get("aie_hklm", "")) and _aie_enabled(outputs.get("aie_hkcu", "")):
        vectors.append(_vector(
            "AlwaysInstallElevated enabled (HKLM + HKCU)",
            "critical" if not elevated else "high",
            0.95 if not elevated else 0.8,
            detail="Both installer policy hives set AlwaysInstallElevated = 0x1",
            abuse="`msiexec /quiet /i evil.msi` installs a payload as SYSTEM",
            signals=["always_install_elevated"], techniques=[mitre.T_UAC_BYPASS]))

    # 2. Dangerous privileges on the current token.
    if not elevated:
        vectors.extend(_privilege_vectors(facts.privileges))

    # 3. Services — unquoted paths + user-writable binary locations.
    if not elevated:
        vectors.extend(_parse_services(outputs.get("services", "")))

    # 4. Autologon plaintext credential in the registry.
    vectors.extend(_parse_autologon(outputs.get("autologon", "")))

    # 5. UAC disabled.
    vectors.extend(_parse_uac(outputs.get("uac", "")))

    # 6. Saved credentials in the vault.
    vectors.extend(_parse_cmdkey(outputs.get("cmdkey", "")))

    # 7. Unattend / sysprep answer files.
    vectors.extend(_parse_unattend(outputs.get("unattend", "")))

    # 8. Writable directory on the system PATH.
    if not elevated:
        vectors.extend(_parse_path_acl(outputs.get("path_acl", "")))

    vectors = _dedupe_vectors(vectors)
    return WinEnumResult(host=host, user=user, success=True, facts=facts,
                         vectors=vectors,
                         raw={k: v[:8000] for k, v in outputs.items()})


# ── Field parsers ───────────────────────────────────────────────────────────
def _parse_whoami(text: str, facts: WinHostFacts) -> None:
    """Parse ``whoami /all`` — user name, group memberships and privileges."""
    low = text.lower()
    # User name: the token line under USER INFORMATION, e.g. "desktop\user  S-1-5-21-..."
    m = re.search(r"^([^\s\\]+\\[^\s]+)\s+(s-1-[\d-]+)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        facts.username = m.group(1)
        if m.group(2).lower() in ("s-1-5-18", "s-1-5-19", "s-1-5-20"):
            facts.is_system = True
    if "\\system" in low or "nt authority\\system" in low:
        facts.is_system = True

    # Admin: Administrators group present in the token.
    if "builtin\\administrators" in low or "s-1-5-32-544" in low:
        facts.is_admin = True

    # Integrity level (mandatory label). A High/System integrity token is
    # already elevated, so treat it as admin for escalation purposes.
    if "high mandatory level" in low or "system mandatory level" in low:
        facts.integrity = "High"
        facts.is_admin = True
    elif "medium mandatory level" in low:
        facts.integrity = "Medium"
    elif "low mandatory level" in low:
        facts.integrity = "Low"

    # Groups: capture BUILTIN\ / NT AUTHORITY\ / domain group names.
    groups = re.findall(r"^([A-Za-z0-9 _.\-]+\\[A-Za-z0-9 _.\-$]+)\s", text, re.MULTILINE)
    seen: list[str] = []
    for g in groups:
        g = g.strip()
        gl = g.lower()
        if gl.startswith("mandatory label") or g in seen:
            continue
        seen.append(g)
    facts.groups = seen[:40]

    # Privileges: "SeXxxPrivilege   Description   Enabled/Disabled".
    for pm in re.finditer(r"(Se[A-Za-z]+Privilege)\s+.*?\s+(Enabled|Disabled)",
                          text, re.IGNORECASE):
        name, state = pm.group(1), pm.group(2)
        if state.lower() == "enabled" and name.lower() in _DANGEROUS_PRIVILEGES:
            if name not in facts.privileges:
                facts.privileges.append(name)


def _parse_sysinfo(text: str, facts: WinHostFacts) -> None:
    for line in text.splitlines():
        if line.startswith("OS Name:"):
            facts.os = line.split(":", 1)[1].strip()
        elif line.startswith("OS Version:"):
            facts.build = line.split(":", 1)[1].strip()


def _parse_users(text: str) -> list[str]:
    users: list[str] = []
    started = False
    for line in text.splitlines():
        if set(line.strip()) == {"-"}:
            started = True
            continue
        if not started:
            continue
        if "command completed" in line.lower():
            break
        users.extend(p for p in line.split() if p)
    return users[:50]


def _parse_listen(text: str) -> list[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        m = re.search(r":(\d{1,5})\s+\S+\s+LISTENING", line)
        if m:
            p = int(m.group(1))
            if 0 < p < 65536:
                ports.add(p)
    return sorted(ports)[:60]


def _parse_ifaces(text: str) -> list[str]:
    ips: list[str] = []
    for m in re.finditer(r"IPv4 Address[^:]*:\s*([\d.]+)", text):
        ip = m.group(1)
        if ip not in ips and not ip.startswith("127."):
            ips.append(ip)
    return ips[:20]


def _aie_enabled(text: str) -> bool:
    return bool(re.search(r"AlwaysInstallElevated\s+REG_DWORD\s+0x1\b", text))


def _privilege_vectors(privileges: list[str]) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for name in privileges:
        sev, abuse, tech = _DANGEROUS_PRIVILEGES[name.lower()]
        vectors.append(_vector(
            f"Dangerous privilege held: {name}", sev, 0.85,
            detail=f"{name} is enabled on the current token", abuse=abuse,
            signals=[f"priv:{name.lower()}"], techniques=[tech]))
    return vectors


def _parse_services(text: str) -> list[dict[str, Any]]:
    """Parse ``Name|PathName|StartMode|StartName`` service rows."""
    vectors: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        path = parts[1].strip()
        start_name = parts[3].strip() if len(parts) > 3 else ""
        if not name or not path:
            continue
        # Only services that run with privilege are interesting.
        privileged = (not start_name) or start_name.lower() in (
            "localsystem", "nt authority\\system", "nt authority\\localservice",
            "nt authority\\networkservice", ".\\localsystem",
        )
        exe_path = _service_exe_path(path)
        low_exe = exe_path.lower()

        # Unquoted path with a space. The vuln is the *earlier* search paths
        # Windows tries (C:\Program.exe, C:\Program Files\Sub.exe, ...), so it
        # applies even when the real binary sits under a trusted root. Whether
        # it is exploitable depends on write access to one of those dirs, hence
        # needs_manual_confirm.
        if (not path.lstrip().startswith('"') and " " in exe_path.strip()
                and privileged):
            vectors.append(_vector(
                f"Unquoted service path: {name}", "high", 0.7,
                detail=path[:300],
                abuse="Plant C:\\Program.exe (or an earlier space-split token) to "
                      "run as the service account",
                signals=["unquoted_service_path"], needs_manual_confirm=True,
                techniques=[mitre.T_UNQUOTED_PATH]))

        # Service binary in a user-writable location (non-trusted root).
        if (low_exe.endswith(".exe") and privileged
                and not low_exe.startswith(_TRUSTED_ROOTS)
                and _in_writable_location(low_exe)):
            vectors.append(_vector(
                f"Service binary in a user-writable path: {name}", "high", 0.65,
                detail=exe_path[:300],
                abuse="Overwrite the service executable → SYSTEM code exec on restart",
                signals=["service_writable_binary"], needs_manual_confirm=True,
                techniques=[mitre.T_SERVICE_PERMS]))
    return vectors


def _parse_autologon(text: str) -> list[dict[str, Any]]:
    low = text.lower()
    has_pw = "defaultpassword" in low
    auto_on = bool(re.search(r"AutoAdminLogon\s+REG_SZ\s+1\b", text))
    if has_pw and auto_on:
        user_m = re.search(r"DefaultUserName\s+REG_SZ\s+(\S+)", text)
        who = user_m.group(1) if user_m else "(unknown)"
        return [_vector(
            "Autologon credential stored in the registry", "high", 0.9,
            detail=f"Winlogon AutoAdminLogon=1, DefaultUserName={who}, "
                   "DefaultPassword set (value redacted)",
            abuse="Read the plaintext DefaultPassword for the autologon account",
            signals=["autologon_password"], techniques=[mitre.T_CREDS_IN_REGISTRY])]
    return []


def _parse_uac(text: str) -> list[dict[str, Any]]:
    if re.search(r"EnableLUA\s+REG_DWORD\s+0x0\b", text):
        return [_vector(
            "UAC is disabled (EnableLUA = 0)", "medium", 0.85,
            detail="HKLM ... Policies\\System EnableLUA = 0x0",
            abuse="Admin-group members get a full-integrity token without a prompt",
            signals=["uac_disabled"], techniques=[mitre.T_UAC_BYPASS])]
    return []


def _parse_cmdkey(text: str) -> list[dict[str, Any]]:
    targets = re.findall(r"Target:\s*(\S+)", text)
    if targets:
        return [_vector(
            f"Saved credentials in the vault ({len(targets)})", "medium", 0.7,
            detail="cmdkey /list targets: " + ", ".join(targets[:8]),
            abuse="`runas /savecred` reuses these without knowing the password",
            signals=["saved_credentials"], needs_manual_confirm=True,
            techniques=[mitre.T_PASSWORD_STORES])]
    return []


def _parse_unattend(text: str) -> list[dict[str, Any]]:
    files = [ln.split("UNATTEND_FILE:", 1)[1].strip()
             for ln in text.splitlines() if "UNATTEND_FILE:" in ln]
    if files:
        return [_vector(
            "Unattended-install answer file present", "high", 0.75,
            detail=", ".join(files[:6]),
            abuse="Answer files often embed a base64 local-administrator password",
            signals=["unattend_file"], needs_manual_confirm=True,
            techniques=[mitre.T_CREDS_IN_FILES])]
    return []


def _parse_path_acl(text: str) -> list[dict[str, Any]]:
    dirs = [ln.split("WRITABLE_PATH:", 1)[1].strip()
            for ln in text.splitlines() if "WRITABLE_PATH:" in ln]
    risky = [d for d in dict.fromkeys(dirs) if d]
    if risky:
        return [_vector(
            f"Writable directory on the system PATH: {', '.join(risky[:3])}",
            "high", 0.75, detail=", ".join(risky),
            abuse="Plant a DLL/EXE that a privileged process loads from PATH",
            signals=["writable_path"], techniques=[mitre.T_PATH_HIJACK])]
    return []


# ── helpers ─────────────────────────────────────────────────────────────────
def _service_exe_path(path: str) -> str:
    """Extract the executable path from a service PathName (drops arguments)."""
    p = path.strip()
    if p.startswith('"'):
        end = p.find('"', 1)
        return p[1:end] if end > 0 else p[1:]
    # Unquoted: the exe ends at the first ".exe" token.
    m = re.search(r"^(.*?\.exe)\b", p, re.IGNORECASE)
    return m.group(1) if m else p.split(" ")[0]


def _in_writable_location(low_exe: str) -> bool:
    return low_exe.startswith((
        "c:\\programdata", "c:\\users", "c:\\temp", "c:\\tmp",
        "c:\\inetpub", "c:\\opt", "c:\\apps",
    ))


def _vector(title: str, severity: str, confidence: float, *, detail: str = "",
            abuse: str = "", signals: Optional[list[str]] = None,
            needs_manual_confirm: bool = False,
            techniques: Optional[list[str]] = None) -> dict[str, Any]:
    return {
        "title": title, "severity": severity, "confidence": confidence,
        "detail": detail, "abuse": abuse, "signals": signals or [],
        "needs_manual_confirm": needs_manual_confirm, "techniques": techniques or [],
    }


def _dedupe_vectors(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for v in vectors:
        key = v["title"]
        if key not in best or v["confidence"] > best[key]["confidence"]:
            best[key] = v
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(best.values(),
                  key=lambda v: (order.get(v["severity"], 5), -v["confidence"]))


def _first_nonempty(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# ── SSH runner (thin; degrades without asyncssh) ─────────────────────────────
class WindowsEnumEngine:
    """Run the Windows enumeration battery over SSH and parse it.

    Same transport as :class:`~heaven.postex.enum_engine.LinuxEnumEngine`
    (Windows 10 / Server 2019+ ship OpenSSH). Authorization-gated.
    """

    def __init__(self, authorized: bool = False):
        self.authorized = authorized

    async def enumerate(  # noqa: A003 - domain verb
        self, host: str, username: str, password: Optional[str] = None,
        private_key: Optional[str] = None, port: int = 22,
        per_command_timeout: float = 30.0,
    ) -> WinEnumResult:
        if not self.authorized:
            return WinEnumResult(host=host, user=username, success=False,
                                 error="aborted: engine not authorized")
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            return WinEnumResult(host=host, user=username, success=False,
                                 error="asyncssh not installed — pip install asyncssh")

        client_keys = [private_key] if private_key else None
        outputs: dict[str, str] = {}
        try:
            async with asyncssh.connect(  # type: ignore[attr-defined]
                host, port=port, username=username, password=password,
                client_keys=client_keys, known_hosts=None,
            ) as conn:
                for key, cmd in WIN_COMMAND_BATTERY.items():
                    try:
                        r = await conn.run(cmd, check=False, timeout=per_command_timeout)
                        outputs[key] = _as_text(r.stdout)
                    except Exception as e:  # one bad command must not abort the sweep
                        outputs[key] = ""
                        logger.debug("win enum cmd %s failed: %s", key, e)
        except Exception as e:
            return WinEnumResult(host=host, user=username, success=False,
                                 error=f"{type(e).__name__}: {e}")

        result = parse_windows_enumeration(host, username, outputs)
        logger.info("win-enum %s@%s: %d privesc vector(s)",
                    username, host, len(result.vectors))
        return result


__all__ = [
    "WindowsEnumEngine", "WinEnumResult", "WinHostFacts",
    "parse_windows_enumeration", "WIN_COMMAND_BATTERY",
]
