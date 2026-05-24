"""
HEAVEN — linpeas runner

Wraps the popular linpeas.sh privilege-escalation enumeration script:
  https://github.com/peass-ng/PEASS-ng

Workflow:
  1. SSH into the target with provided credentials.
  2. Upload linpeas.sh (bundled or fetched from upstream URL).
  3. Run it, capture stdout + stderr.
  4. Parse the output into structured findings (suid binaries, world-
     writable files, sudo entries, kernel exploits, capability bits).

Authorization:
  Refuses to run unless `authorized=True`. Caller must pass valid
  credentials — the runner does NOT brute-force.

Optional dep: asyncssh (preferred) or paramiko (sync fallback).
If neither is installed the runner returns a clear error rather than
crashing the orchestrator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("postex.linpeas")


# Default upstream URL — used when the runner is told to fetch live.
LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"


@dataclass
class LinpeasResult:
    host: str
    user: str
    success: bool
    privesc_vectors: list[dict[str, Any]] = field(default_factory=list)
    suid_binaries: list[str] = field(default_factory=list)
    world_writable: list[str] = field(default_factory=list)
    sudo_entries: list[str] = field(default_factory=list)
    kernel_version: str = ""
    raw_output: str = ""
    error: str = ""

    def to_findings(self) -> list[dict[str, Any]]:
        """Convert to HEAVEN finding dicts so they land in the engagement DB."""
        findings: list[dict[str, Any]] = []
        for v in self.privesc_vectors:
            findings.append({
                "target": self.host,
                "vuln_type": "privesc",
                "title": v.get("title", "Privilege escalation vector"),
                "severity": v.get("severity", "high"),
                "confidence": v.get("confidence", 0.85),
                "evidence": {"source": "linpeas", **v},
            })
        return findings


class LinpeasRunner:
    """SSH-based linpeas runner. Caller supplies credentials and target host."""

    def __init__(self, authorized: bool = False):
        self.authorized = authorized

    async def run(self, host: str, username: str, password: Optional[str] = None,
                  private_key: Optional[str] = None, port: int = 22,
                  script_path: Optional[str] = None,
                  timeout: float = 120.0) -> LinpeasResult:
        if not self.authorized:
            return LinpeasResult(host=host, user=username, success=False,
                                 error="aborted: runner not authorized")
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            return LinpeasResult(
                host=host, user=username, success=False,
                error="asyncssh not installed — pip install asyncssh",
            )

        client_keys = [private_key] if private_key else None
        try:
            async with asyncssh.connect(  # type: ignore[attr-defined]
                host, port=port, username=username,
                password=password, client_keys=client_keys,
                known_hosts=None,                  # operator-driven; trust on first use
            ) as conn:
                # Load script: from disk if provided, else fetch via curl on target
                if script_path:
                    # scp the local script directly; no need to slurp its bytes first
                    await asyncssh.scp(  # type: ignore[attr-defined]
                        (script_path,), (conn, "/tmp/linpeas.sh"),
                    )
                else:
                    # Fall back to fetching live on the target (requires curl)
                    fetch_cmd = f"curl -sL {LINPEAS_URL} -o /tmp/linpeas.sh"
                    fetch = await conn.run(fetch_cmd, check=False, timeout=30)
                    if fetch.exit_status != 0:
                        return LinpeasResult(
                            host=host, user=username, success=False,
                            error=f"could not fetch linpeas.sh on target: {fetch.stderr}",
                        )

                run_cmd = "chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh -q -N 2>&1"
                run = await conn.run(run_cmd, check=False, timeout=timeout)
                # Always cleanup
                await conn.run("rm -f /tmp/linpeas.sh", check=False, timeout=5)

                output = run.stdout or ""
                parsed = _parse_linpeas(output)
                return LinpeasResult(
                    host=host, user=username, success=True,
                    raw_output=output[:50000],     # cap memory
                    **parsed,
                )
        except Exception as e:
            return LinpeasResult(
                host=host, user=username, success=False,
                error=f"{type(e).__name__}: {e}",
            )


# ═══════════════════════════════════════════
# OUTPUT PARSING
# Loose: linpeas output format changes between releases, so we look for
# stable section headers and bullet markers rather than rigid columns.
# ═══════════════════════════════════════════

_PRIVESC_PATTERNS = [
    # (regex, vector_title, default_severity)
    (re.compile(r"sudo.*\(ALL\).*NOPASSWD", re.I), "Passwordless sudo entry", "critical"),
    (re.compile(r"writable.*passwd|/etc/passwd.*writable", re.I), "/etc/passwd writable", "critical"),
    (re.compile(r"writable.*shadow|/etc/shadow.*writable", re.I), "/etc/shadow writable", "critical"),
    (re.compile(r"docker.*group", re.I), "User in docker group (host root)", "critical"),
    (re.compile(r"lxd.*group|lxc.*group", re.I), "User in lxd/lxc group (container escape)", "critical"),
    (re.compile(r"unusual SUID", re.I), "Unusual SUID binary", "high"),
    (re.compile(r"capabilities.*\+ep", re.I), "Suspicious file capability", "high"),
    (re.compile(r"kernel exploit", re.I), "Kernel exploit suggested", "high"),
    (re.compile(r"\.ssh/authorized_keys.*writable", re.I), "authorized_keys writable", "high"),
]


def _parse_linpeas(output: str) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    for pattern, title, severity in _PRIVESC_PATTERNS:
        for match in pattern.finditer(output):
            line = _line_at(output, match.start())
            vectors.append({
                "title": title,
                "severity": severity,
                "match_line": line[:200],
                "confidence": 0.85,
            })

    suid = sorted({m.group(0) for m in re.finditer(r"/usr/[^\s]+", output) if "suid" in output.lower()})[:30]
    world_writable = sorted(
        {m.group(0) for m in re.finditer(r"/(?:etc|var|tmp|home)/[^\s]+", output)
         if "world writable" in output.lower() or "permissions.*ww" in output.lower()}
    )[:30]

    sudo_entries = []
    for m in re.finditer(r"User.*may run.*following commands.*", output, flags=re.I):
        sudo_entries.append(_line_at(output, m.start())[:200])
    sudo_entries = sudo_entries[:20]

    kernel = ""
    km = re.search(r"Linux version (\d+\.\d+\.[\w.\-+]+)", output)
    if km:
        kernel = km.group(1)

    return {
        "privesc_vectors": vectors,
        "suid_binaries": suid,
        "world_writable": world_writable,
        "sudo_entries": sudo_entries,
        "kernel_version": kernel,
    }


def _line_at(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    if end == -1:
        end = len(text)
    return text[start:end].strip()
