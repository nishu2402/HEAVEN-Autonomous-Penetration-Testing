"""HEAVEN — self-contained Linux post-exploitation enumeration engine.

The original privesc path shelled out to a downloaded ``linpeas.sh``: fragile
(needs egress to GitHub on the target), opaque (thousands of lines of someone
else's bash) and hostile to air-gapped engagements. This engine replaces that
with a small, auditable battery of **read-only** shell commands run over one SSH
connection, whose output is parsed into structured, MITRE-tagged privilege-
escalation findings scored against an offline GTFOBins catalog.

Design:

  * ``LinuxEnumEngine.enumerate(...)`` opens an SSH session, runs the battery,
    and hands the raw ``{key: output}`` dict to a **pure** parser.
  * :func:`parse_enumeration` is import-free of SSH and fully deterministic, so
    it is unit-tested against canned command output — no live host required.
  * Findings carry real confidence: a SUID binary that appears in GTFOBins *is*
    a root escalation, so it is reported at high confidence; a kernel-version
    match is a hint, so it is reported low and flagged "needs manual confirm".

Degrades gracefully: no ``asyncssh`` installed → a clear error, never a crash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.postex import mitre_attack as mitre
from heaven.postex.gtfobins import lookup as gtfo_lookup
from heaven.utils.logger import get_logger

logger = get_logger("postex.enum")


def _as_text(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data or ""


# ── The command battery ─────────────────────────────────────────────────────
# Every command is read-only, non-interactive, and self-terminating. `sudo -n`
# never prompts (returns nothing if a password is required), so nothing hangs.
COMMAND_BATTERY: dict[str, str] = {
    "id": "id 2>/dev/null; echo '::GROUPS::'; id -Gn 2>/dev/null",
    "os": "cat /etc/os-release 2>/dev/null | head -20",
    "kernel": "uname -a 2>/dev/null",
    "hostname": "hostname 2>/dev/null; cat /etc/hostname 2>/dev/null | head -1",
    "sudo": "sudo -n -l 2>/dev/null",
    "suid": "find / -perm -4000 -type f 2>/dev/null | head -200",
    "sgid": "find / -perm -2000 -type f 2>/dev/null | head -200",
    "caps": "getcap -r / 2>/dev/null | head -100",
    "sensitive_perms": (
        "ls -la /etc/passwd /etc/shadow /etc/sudoers "
        "/root/.ssh/authorized_keys 2>/dev/null"
    ),
    "docker_sock": "ls -la /var/run/docker.sock 2>/dev/null",
    "path_writable": (
        "for d in $(printf '%s' \"$PATH\" | tr ':' ' '); do "
        "[ -w \"$d\" ] && echo \"WRITABLE_PATH:$d\"; done 2>/dev/null"
    ),
    "cron": (
        "cat /etc/crontab 2>/dev/null; echo '::CRONDIR::'; "
        "ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null"
    ),
    "users": "cat /etc/passwd 2>/dev/null",
    "net_listen": "ss -tlnH 2>/dev/null || netstat -tlnp 2>/dev/null",
    "net_iface": "ip -o -4 addr show 2>/dev/null || ifconfig -a 2>/dev/null",
    "nfs": "cat /etc/exports 2>/dev/null",
}

# SUID/SGID binaries that are SUID by design and not, on their own, escalations.
# We still surface them as facts, but do not raise a finding unless GTFOBins says
# they are abusable (pkexec is special-cased for CVE-2021-4034).
_BENIGN_SUID = {
    "su", "sudo", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "fusermount", "fusermount3", "ntfs-3g",
    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "ssh-keysign",
    "chrome-sandbox", "snap-confine", "vmware-user-suid-wrapper",
}

_CRITICAL_GROUPS = {
    "docker": ("Escape to host root via the docker daemon", mitre.T_ESCAPE_TO_HOST),
    "lxd": ("Escape to host root via an LXD container mount", mitre.T_ESCAPE_TO_HOST),
    "lxc": ("Escape to host root via an LXC container mount", mitre.T_ESCAPE_TO_HOST),
}
_HIGH_GROUPS = {
    "disk": ("Read/write raw disk devices (debugfs /dev/sda → read shadow)", mitre.T_LOCAL_DATA),
    "shadow": ("Read /etc/shadow directly for offline cracking", mitre.T_CREDS_IN_FILES),
    "adm": ("Read privileged log files (credentials in logs)", mitre.T_LOCAL_DATA),
}

_DANGEROUS_CAPS = {
    "cap_setuid": "Set arbitrary UID → drop to root",
    "cap_setgid": "Set arbitrary GID",
    "cap_dac_override": "Bypass file read/write permission checks",
    "cap_dac_read_search": "Bypass file read permission checks (read /etc/shadow)",
    "cap_sys_admin": "Broad administrative capability → many escalation paths",
    "cap_sys_ptrace": "Attach to privileged processes and inject code",
    "cap_sys_module": "Load kernel modules → full kernel compromise",
    "cap_chown": "Change ownership of arbitrary files",
}

_KERNEL_RE = re.compile(r"(\d+\.\d+\.\d+)")


# ── Structured result ───────────────────────────────────────────────────────
@dataclass
class HostFacts:
    hostname: str = ""
    os: str = ""
    kernel: str = ""
    username: str = ""
    uid: Optional[int] = None
    is_root: bool = False
    groups: list[str] = field(default_factory=list)
    local_users: list[str] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    suid_binaries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname, "os": self.os, "kernel": self.kernel,
            "username": self.username, "uid": self.uid, "is_root": self.is_root,
            "groups": self.groups, "local_users": self.local_users,
            "listening_ports": self.listening_ports, "interfaces": self.interfaces,
            "suid_count": len(self.suid_binaries),
        }


@dataclass
class EnumResult:
    host: str
    user: str
    success: bool
    facts: HostFacts = field(default_factory=HostFacts)
    vectors: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_findings(self) -> list[dict[str, Any]]:
        """Convert privesc vectors to MITRE-tagged HEAVEN finding dicts."""
        findings: list[dict[str, Any]] = []
        for v in self.vectors:
            f: dict[str, Any] = {
                "target": self.host,
                "vuln_type": "privesc",
                "title": v.get("title", "Privilege escalation vector"),
                "severity": v.get("severity", "high"),
                "confidence": v.get("confidence", 0.85),
                "evidence": {
                    "source": "postex.enum_engine",
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
            "error": self.error, "facts": self.facts.to_dict(),
            "vectors": self.vectors,
            "vector_count": len(self.vectors),
        }


# ── Pure parser (no SSH, fully deterministic → unit-testable) ────────────────
def parse_enumeration(host: str, user: str, outputs: dict[str, str]) -> EnumResult:
    """Turn raw ``{battery_key: output}`` into a structured, scored result."""
    facts = HostFacts(username=user)
    vectors: list[dict[str, Any]] = []

    _parse_identity(outputs.get("id", ""), facts)
    facts.hostname = _first_nonempty(outputs.get("hostname", "")) or host
    facts.os = _parse_os(outputs.get("os", ""))
    facts.kernel = _parse_kernel(outputs.get("kernel", ""))
    facts.local_users = _parse_users(outputs.get("users", ""))
    facts.listening_ports = _parse_listen(outputs.get("net_listen", ""))
    facts.interfaces = _parse_ifaces(outputs.get("net_iface", ""))

    # If we are already root, escalation is moot — report facts only.
    already_root = facts.is_root

    # 1. Group membership → container escape / disk read
    for grp in facts.groups:
        g = grp.strip().lower()
        if g in _CRITICAL_GROUPS and not already_root:
            note, tech = _CRITICAL_GROUPS[g]
            vectors.append(_vector(
                f"User is in the '{g}' group ({note})", "critical", 0.95,
                detail=f"id groups: {', '.join(facts.groups)}", abuse=note,
                signals=[f"group:{g}"], techniques=[tech]))
        elif g in _HIGH_GROUPS and not already_root:
            note, tech = _HIGH_GROUPS[g]
            vectors.append(_vector(
                f"User is in the '{g}' group ({note})", "high", 0.85,
                detail=f"id groups: {', '.join(facts.groups)}", abuse=note,
                signals=[f"group:{g}"], techniques=[tech]))

    # 2. sudo -l → passwordless / GTFOBins-abusable sudo rules
    if not already_root:
        vectors.extend(_parse_sudo(outputs.get("sudo", "")))

    # 3. SUID binaries → GTFOBins matches (+ pkexec CVE hint)
    facts.suid_binaries, suid_vectors = _parse_suid(outputs.get("suid", ""))
    if not already_root:
        vectors.extend(suid_vectors)

    # 4. File capabilities
    if not already_root:
        vectors.extend(_parse_caps(outputs.get("caps", "")))

    # 5. Writable sensitive files (/etc/passwd, /etc/shadow, root authorized_keys)
    if not already_root:
        vectors.extend(_parse_sensitive_perms(outputs.get("sensitive_perms", ""),
                                              outputs.get("id", "")))

    # 6. Readable docker socket (even without group membership)
    if not already_root:
        vectors.extend(_parse_docker_sock(outputs.get("docker_sock", "")))

    # 7. Writable directories on PATH → binary planting
    if not already_root:
        vectors.extend(_parse_path_writable(outputs.get("path_writable", "")))

    # 8. Writable privileged cron
    if not already_root:
        vectors.extend(_parse_cron(outputs.get("cron", "")))

    # De-dupe by (title) keeping the highest confidence.
    vectors = _dedupe_vectors(vectors)
    return EnumResult(host=host, user=user, success=True, facts=facts,
                      vectors=vectors, raw={k: v[:8000] for k, v in outputs.items()})


# ── Field parsers ───────────────────────────────────────────────────────────
def _parse_identity(text: str, facts: HostFacts) -> None:
    line, _, groups_line = text.partition("::GROUPS::")
    m = re.search(r"uid=(\d+)\(([^)]+)\)", line)
    if m:
        facts.uid = int(m.group(1))
        facts.username = m.group(2)
        facts.is_root = facts.uid == 0
    gm = re.findall(r"\d+\(([^)]+)\)", line)
    groups = [g.strip() for g in groups_line.replace("\n", " ").split() if g.strip()]
    # Prefer `id -Gn` names; fall back to the gid=/groups= section of `id`.
    facts.groups = groups or gm[1:]  # gm[0] is the primary group in uid=…gid=…


def _parse_os(text: str) -> str:
    name = ver = ""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
        if line.startswith("NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION="):
            ver = line.split("=", 1)[1].strip().strip('"')
    return f"{name} {ver}".strip()


def _parse_kernel(text: str) -> str:
    m = _KERNEL_RE.search(text)
    return m.group(1) if m else ""


def _parse_users(text: str) -> list[str]:
    users = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[6].strip() not in (
            "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin",
        ):
            users.append(parts[0])
    return users[:50]


def _parse_listen(text: str) -> list[int]:
    ports: set[int] = set()
    for m in re.finditer(r"[:.](\d{1,5})\s", text):
        p = int(m.group(1))
        if 0 < p < 65536:
            ports.add(p)
    return sorted(ports)[:60]


def _parse_ifaces(text: str) -> list[str]:
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    seen: list[str] = []
    for ip in ips:
        if ip not in seen and not ip.startswith("127."):
            seen.append(ip)
    return seen[:20]


def _parse_sudo(text: str) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    if not text.strip():
        return vectors
    low = text.lower()
    # Full root: "(ALL : ALL) ALL" or "(ALL) ALL"
    if re.search(r"\(all\s*(:\s*all)?\)\s+all\b", low):
        passwordless = "nopasswd" in low
        vectors.append(_vector(
            "Sudo grants full root (ALL) ALL" + (" — NOPASSWD" if passwordless else ""),
            "critical", 0.98 if passwordless else 0.9,
            detail=_clip(text), abuse="`sudo /bin/sh` for an immediate root shell",
            signals=["sudo_all"] + (["nopasswd"] if passwordless else []),
            techniques=[mitre.T_SUDO]))
        return vectors
    # Specific NOPASSWD binaries → GTFOBins check
    for m in re.finditer(r"\(([^)]*)\)\s*(NOPASSWD:\s*)?(\S+)", text):
        nopasswd = bool(m.group(2))
        target = m.group(3).strip()
        if target.upper() in ("ALL", "NOPASSWD:"):
            continue
        entry = gtfo_lookup(target)
        if entry and entry.sudo:
            sev = "critical" if nopasswd else "high"
            conf = 0.95 if nopasswd else 0.85
            vectors.append(_vector(
                f"Sudo-allowed GTFOBins binary: {target.rsplit('/', 1)[-1]}"
                + (" (NOPASSWD)" if nopasswd else ""),
                sev, conf, detail=_clip(text), abuse=entry.note,
                signals=["sudo_gtfobins"] + (["nopasswd"] if nopasswd else []),
                techniques=[mitre.T_SUDO]))
    return vectors


def _parse_suid(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    binaries: list[str] = []
    vectors: list[dict[str, Any]] = []
    for line in text.splitlines():
        path = line.strip()
        if not path.startswith("/"):
            continue
        binaries.append(path)
        name = path.rsplit("/", 1)[-1]
        if name in _BENIGN_SUID:
            continue
        if name == "pkexec":
            vectors.append(_vector(
                "SUID pkexec present (PwnKit CVE-2021-4034 candidate)",
                "high", 0.6, detail=path,
                abuse="If unpatched, CVE-2021-4034 (PwnKit) gives instant root",
                signals=["suid_pkexec"], needs_manual_confirm=True,
                techniques=[mitre.T_KERNEL_EXPLOIT]))
            continue
        entry = gtfo_lookup(name)
        if entry and entry.suid:
            vectors.append(_vector(
                f"SUID GTFOBins binary: {name}", "high", 0.9,
                detail=path, abuse=entry.note, signals=["suid_gtfobins"],
                techniques=[mitre.T_SUID]))
    return binaries[:200], vectors


def _parse_caps(text: str) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        path, _, capspec = line.partition("=")
        path = path.strip()
        capspec_l = capspec.strip().lower()
        for cap, note in _DANGEROUS_CAPS.items():
            if cap in capspec_l:
                name = path.rsplit("/", 1)[-1]
                entry = gtfo_lookup(name)
                conf = 0.9 if (entry and entry.capabilities and cap in ("cap_setuid", "cap_setgid")) else 0.75
                sev = "critical" if cap in ("cap_setuid", "cap_sys_module", "cap_sys_admin") else "high"
                vectors.append(_vector(
                    f"File capability {cap} on {name}", sev, conf,
                    detail=line, abuse=note, signals=[f"cap:{cap}"],
                    techniques=[mitre.T_CAPABILITIES]))
                break
    return vectors


def _parse_sensitive_perms(text: str, id_text: str) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    uid_m = re.search(r"uid=(\d+)\(([^)]+)\)", id_text)
    username = uid_m.group(2) if uid_m else ""
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith(("-", "l")):
            continue
        perms = line.split()[0] if line.split() else ""
        world_writable = len(perms) >= 9 and perms[8] == "w"
        owner_writable_by_us = username and f" {username} " in f" {line} " and len(perms) >= 3 and perms[2] == "w"
        if "/etc/passwd" in line and (world_writable or owner_writable_by_us):
            vectors.append(_vector(
                "/etc/passwd is writable", "critical", 0.95, detail=line,
                abuse="Append a root-uid user with a known password hash",
                signals=["passwd_writable"], techniques=[mitre.T_FILE_PERMS]))
        elif "/etc/shadow" in line and (world_writable or _readable_by_us(perms, line, username)):
            vectors.append(_vector(
                "/etc/shadow is readable/writable", "critical", 0.95, detail=line,
                abuse="Read hashes for offline cracking, or set a known root hash",
                signals=["shadow_access"], techniques=[mitre.T_CREDS_IN_FILES]))
        elif "/etc/sudoers" in line and world_writable:
            vectors.append(_vector(
                "/etc/sudoers is writable", "critical", 0.95, detail=line,
                abuse="Grant yourself NOPASSWD ALL",
                signals=["sudoers_writable"], techniques=[mitre.T_FILE_PERMS]))
        elif "authorized_keys" in line and world_writable:
            vectors.append(_vector(
                "root authorized_keys is writable (persistence)", "high", 0.85,
                detail=line, abuse="Append your public key for persistent root SSH",
                signals=["authkeys_writable"], techniques=[mitre.T_SSH_AUTHKEYS]))
    return vectors


def _parse_docker_sock(text: str) -> list[dict[str, Any]]:
    for line in text.splitlines():
        if "docker.sock" in line and line.strip().startswith("s"):
            perms = line.split()[0]
            # world- or group-readable/writable socket
            if len(perms) >= 9 and ("w" in perms[4:9]):
                return [_vector(
                    "Writable docker.sock exposed", "critical", 0.9, detail=line.strip(),
                    abuse="`docker run -v /:/host` mounts the host filesystem as root",
                    signals=["docker_sock_writable"], techniques=[mitre.T_ESCAPE_TO_HOST])]
    return []


def _parse_path_writable(text: str) -> list[dict[str, Any]]:
    dirs = [ln.split("WRITABLE_PATH:", 1)[1].strip()
            for ln in text.splitlines() if "WRITABLE_PATH:" in ln]
    # A writable . or a writable system dir on PATH is the interesting case.
    risky = [d for d in dirs if d and d not in ("", ".")
             and (d.startswith(("/usr", "/bin", "/sbin", "/opt", "/usr/local")))]
    if risky:
        return [_vector(
            f"Writable directory on PATH: {', '.join(risky[:3])}", "high", 0.8,
            detail=", ".join(dirs), abuse="Plant a trojan binary earlier in PATH",
            signals=["writable_path"], techniques=[mitre.T_PATH_HIJACK])]
    return []


def _parse_cron(text: str) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    body, _, _dirs = text.partition("::CRONDIR::")
    # A cron line that runs a script under a world-writable path, or uses a
    # wildcard (tar/rsync wildcard injection) is the classic vector.
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"\*\s+/.+\*", line) or "tar " in line and "*" in line:
            vectors.append(_vector(
                "Cron job with wildcard argument (injection)", "high", 0.6,
                detail=line[:200], abuse="Wildcard/`--checkpoint` argument injection",
                signals=["cron_wildcard"], needs_manual_confirm=True,
                techniques=[mitre.T_CRON]))
    return vectors


# ── helpers ─────────────────────────────────────────────────────────────────
def _readable_by_us(perms: str, line: str, username: str) -> bool:
    if len(perms) >= 8 and perms[7] == "r":  # group-readable
        return True
    return bool(username and f" {username} " in f" {line} " and len(perms) >= 2 and perms[1] == "r")


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


def _clip(text: str, n: int = 400) -> str:
    return text.strip()[:n]


# ── SSH runner (thin; degrades without asyncssh) ─────────────────────────────
class LinuxEnumEngine:
    """Run the enumeration battery over SSH and parse it. Authorization-gated."""

    def __init__(self, authorized: bool = False):
        self.authorized = authorized

    async def enumerate(  # noqa: A003 - domain verb
        self, host: str, username: str, password: Optional[str] = None,
        private_key: Optional[str] = None, port: int = 22,
        per_command_timeout: float = 25.0,
    ) -> EnumResult:
        if not self.authorized:
            return EnumResult(host=host, user=username, success=False,
                              error="aborted: engine not authorized")
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            return EnumResult(host=host, user=username, success=False,
                              error="asyncssh not installed — pip install asyncssh")

        client_keys = [private_key] if private_key else None
        outputs: dict[str, str] = {}
        try:
            async with asyncssh.connect(  # type: ignore[attr-defined]
                host, port=port, username=username, password=password,
                client_keys=client_keys, known_hosts=None,
            ) as conn:
                for key, cmd in COMMAND_BATTERY.items():
                    try:
                        r = await conn.run(cmd, check=False, timeout=per_command_timeout)
                        outputs[key] = _as_text(r.stdout)
                    except Exception as e:  # one bad command must not abort the sweep
                        outputs[key] = ""
                        logger.debug("enum cmd %s failed: %s", key, e)
        except Exception as e:
            return EnumResult(host=host, user=username, success=False,
                              error=f"{type(e).__name__}: {e}")

        result = parse_enumeration(host, username, outputs)
        logger.info("enum %s@%s: %d privesc vector(s)", username, host, len(result.vectors))
        return result


__all__ = [
    "LinuxEnumEngine", "EnumResult", "HostFacts",
    "parse_enumeration", "COMMAND_BATTERY",
]
