"""
HEAVEN — Credential reuse validator

Takes a list of discovered (user, password) tuples and tries each one
against a list of target services to detect credential reuse — one of
the highest-impact post-ex findings.

Supported services (v1): SSH (asyncssh), HTTP Basic/Digest (aiohttp).
Add more by implementing `async def _try_<service>(host, port, user, pwd)`.

Bounded concurrency, gentle pacing, and explicit timeouts so we don't
turn the validator into a brute-force tool. The intent is to confirm
*known* credentials are reused, NOT to discover new ones via guessing.
A safety check rejects credential lists longer than the configured cap
to make accidental brute-force harder.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("postex.cred_validator")


# Safety cap: refuse to validate more than this many (cred × target) combos
# in one call without an explicit override. Keeps the tool from accidentally
# turning into a brute-force engine.
DEFAULT_COMBO_CAP = 200


@dataclass
class CredentialHit:
    host: str
    port: int
    service: str
    username: str
    notes: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationSummary:
    hits: list[CredentialHit] = field(default_factory=list)
    attempted: int = 0
    errors: list[str] = field(default_factory=list)


class CredentialValidator:
    """Cred-reuse checker. Construct with authorized=True before use."""

    def __init__(self, authorized: bool = False,
                 max_concurrency: int = 10,
                 per_attempt_timeout: float = 8.0,
                 combo_cap: int = DEFAULT_COMBO_CAP):
        self.authorized = authorized
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.timeout = per_attempt_timeout
        self.combo_cap = combo_cap

    async def validate(self,
                       credentials: list[tuple[str, str]],
                       targets: list[tuple[str, int, str]]) -> ValidationSummary:
        """Try every credential against every target.

        Args:
            credentials: list of (username, password) tuples — must be
                pre-discovered, not guessed.
            targets:     list of (host, port, service) tuples. service is
                one of: 'ssh', 'http-basic', 'http-digest'.
        """
        if not self.authorized:
            return ValidationSummary(
                errors=["aborted: validator not authorized"]
            )
        total_combos = len(credentials) * len(targets)
        if total_combos > self.combo_cap:
            return ValidationSummary(
                errors=[
                    f"refused: {total_combos} combos exceeds cap {self.combo_cap}. "
                    "Tighten credentials/targets or raise combo_cap explicitly."
                ]
            )

        summary = ValidationSummary()
        tasks = []
        for (user, pwd) in credentials:
            for (host, port, service) in targets:
                tasks.append(self._try_one(host, port, service, user, pwd, summary))
        await asyncio.gather(*tasks, return_exceptions=True)
        return summary

    async def _try_one(self, host: str, port: int, service: str,
                       user: str, pwd: str, summary: ValidationSummary) -> None:
        async with self.semaphore:
            summary.attempted += 1
            try:
                if service == "ssh":
                    hit = await self._try_ssh(host, port, user, pwd)
                elif service in ("http-basic", "http-digest"):
                    hit = await self._try_http(host, port, service, user, pwd)
                else:
                    summary.errors.append(f"unsupported service: {service}")
                    return
                if hit:
                    summary.hits.append(hit)
                    logger.warning(
                        f"cred reuse: user={user!r} hit {service} on {host}:{port}"
                    )
            except Exception as e:
                summary.errors.append(f"{host}:{port}/{service} {type(e).__name__}: {e}")

    # ── Service handlers ────────────────────────────────────────────────

    async def _try_ssh(self, host: str, port: int,
                       user: str, pwd: str) -> Optional[CredentialHit]:
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            raise RuntimeError("asyncssh not installed")

        try:
            async with asyncio.timeout(self.timeout):
                async with asyncssh.connect(  # type: ignore[attr-defined]
                    host, port=port, username=user, password=pwd,
                    known_hosts=None,
                ) as conn:
                    res = await conn.run("id", check=False)
                    return CredentialHit(
                        host=host, port=port, service="ssh", username=user,
                        notes="login succeeded; `id` output captured",
                        evidence={"id_output": (res.stdout or "")[:200]},
                    )
        except (asyncssh.PermissionDenied,                         # type: ignore[attr-defined]
                asyncssh.misc.PermissionDenied,                    # type: ignore[attr-defined]
                ConnectionRefusedError, asyncio.TimeoutError):
            return None

    async def _try_http(self, host: str, port: int, service: str,
                        user: str, pwd: str) -> Optional[CredentialHit]:
        try:
            import aiohttp
        except ImportError:
            raise RuntimeError("aiohttp not installed")
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        if service == "http-basic":
            auth = aiohttp.BasicAuth(user, pwd)
        else:
            # aiohttp doesn't ship a Digest auth client; try Basic — operator
            # can subclass to add real Digest support if they need it.
            auth = aiohttp.BasicAuth(user, pwd)
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, auth=auth, timeout=timeout) as r:
                    if r.status < 400:
                        return CredentialHit(
                            host=host, port=port, service=service, username=user,
                            notes=f"HTTP {r.status} — auth accepted",
                            evidence={
                                "status": r.status,
                                "auth_header_sent": (
                                    "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()
                                )[:60] + "…",
                            },
                        )
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None
