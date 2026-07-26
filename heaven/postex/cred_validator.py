"""
HEAVEN — Credential reuse validator

Takes a list of discovered (user, password) tuples and tries each one
against a list of target services to detect credential reuse — one of
the highest-impact post-ex findings.

Supported services: SSH (asyncssh), HTTP Basic/Digest (aiohttp),
SMB (impacket), WinRM (pywinrm), LDAP/LDAPS simple-bind (ldap3), and
Kerberos AS-REQ pre-auth (impacket). Add more by implementing
`async def _try_<service>(host, port, user, pwd)`.

Bounded concurrency, gentle pacing, and explicit timeouts so we don't
turn the validator into a brute-force tool. The intent is to confirm
*known* credentials are reused, NOT to discover new ones via guessing.
A safety check rejects credential lists longer than the configured cap
to make accidental brute-force harder.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
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
                one of: 'ssh', 'http-basic', 'http-digest', 'smb', 'winrm',
                'ldap', 'ldaps', 'kerberos'.
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
                elif service == "smb":
                    hit = await self._try_smb(host, port, user, pwd)
                elif service == "winrm":
                    hit = await self._try_winrm(host, port, user, pwd)
                elif service in ("ldap", "ldaps"):
                    hit = await self._try_ldap(host, port, service, user, pwd)
                elif service == "kerberos":
                    hit = await self._try_kerberos(host, port, user, pwd)
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

    @staticmethod
    def _split_domain(user: str) -> tuple[str, str]:
        """Split ``DOMAIN\\user`` (or ``user@domain``) into (domain, user)."""
        if "\\" in user:
            dom, _, u = user.partition("\\")
            return dom, u
        if "@" in user:
            u, _, dom = user.partition("@")
            return dom, u
        return "", user

    async def _try_smb(self, host: str, port: int,
                       user: str, pwd: str) -> Optional[CredentialHit]:
        """Validate SMB credentials with impacket (blocking → executor).

        A successful ``login`` confirms the credential is valid on the host; we
        then list shares as read-only evidence. Bad creds surface as an impacket
        ``SessionError`` (logon failure) and return ``None`` — no guessing."""
        try:
            from impacket.smbconnection import SMBConnection, SessionError  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError("impacket not installed") from e

        domain, u = self._split_domain(user)

        def _blocking() -> Optional[list[str]]:
            conn = None
            try:
                conn = SMBConnection(host, host, sess_port=port,
                                     timeout=int(self.timeout))
                conn.login(u, pwd, domain)                     # raises SessionError on bad creds
                try:
                    shares = [s["shi1_netname"][:-1] for s in conn.listShares()]
                except Exception:  # noqa: BLE001 — login already proven; shares optional
                    shares = []
                return shares
            except SessionError:
                return None
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        conn.logoff()

        loop = asyncio.get_event_loop()
        try:
            shares = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking), timeout=self.timeout + 4)
        except asyncio.TimeoutError:
            return None
        if shares is None:
            return None
        return CredentialHit(
            host=host, port=port, service="smb", username=user,
            notes=f"SMB login succeeded ({len(shares)} share(s) visible)",
            evidence={"shares": shares[:20], "domain": domain or "(local)"},
        )

    async def _try_winrm(self, host: str, port: int,
                         user: str, pwd: str) -> Optional[CredentialHit]:
        """Validate WinRM credentials with pywinrm (blocking → executor).

        Optional dependency: if ``pywinrm`` is not installed this raises so the
        caller records it as an unsupported-service note rather than a silent
        pass — HEAVEN never fabricates a WinRM result it cannot verify."""
        try:
            import winrm  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError("pywinrm not installed") from e

        scheme = "https" if port == 5986 else "http"
        endpoint = f"{scheme}://{host}:{port}/wsman"

        def _blocking() -> Optional[str]:
            try:
                session = winrm.Session(
                    endpoint, auth=(user, pwd), transport="ntlm",
                    server_cert_validation="ignore")
                res = session.run_cmd("whoami")
                if res.status_code == 0:
                    return (res.std_out or b"").decode(errors="replace").strip()
                return None
            except Exception:  # noqa: BLE001 — auth failure / transport error → not a hit
                return None

        loop = asyncio.get_event_loop()
        try:
            whoami = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking), timeout=self.timeout + 6)
        except asyncio.TimeoutError:
            return None
        if whoami is None:
            return None
        return CredentialHit(
            host=host, port=port, service="winrm", username=user,
            notes="WinRM login succeeded; `whoami` executed",
            evidence={"whoami": whoami[:200]},
        )

    async def _try_ldap(self, host: str, port: int, service: str,
                        user: str, pwd: str) -> Optional[CredentialHit]:
        """Validate a credential with an LDAP/LDAPS simple bind (ldap3).

        A successful *authenticated* bind confirms the credential against the
        directory (e.g. an AD domain controller). We refuse empty passwords:
        RFC 4513 treats a simple bind with an empty password as an anonymous
        "unauthenticated bind", which would falsely look like a success — so
        skipping it keeps the validator from ever overclaiming."""
        try:
            import ldap3  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError("ldap3 not installed") from e
        if not pwd:
            return None
        use_ssl = service == "ldaps" or port == 636

        def _blocking() -> Optional[str]:
            server = ldap3.Server(host, port=port, use_ssl=use_ssl,
                                  get_info=ldap3.NONE,
                                  connect_timeout=int(self.timeout))
            conn = ldap3.Connection(
                server, user=user, password=pwd,
                authentication=ldap3.SIMPLE, auto_bind=False,
                receive_timeout=int(self.timeout))
            try:
                if not conn.bind():                            # False on bad creds
                    return None
                try:
                    who = conn.extend.standard.who_am_i()
                except Exception:  # noqa: BLE001 — bind already proven; whoami optional
                    who = None
                return who or user
            finally:
                with contextlib.suppress(Exception):
                    conn.unbind()

        loop = asyncio.get_event_loop()
        try:
            who = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking), timeout=self.timeout + 4)
        except asyncio.TimeoutError:
            return None
        if who is None:
            return None
        return CredentialHit(
            host=host, port=port, service=service, username=user,
            notes="LDAP simple bind succeeded",
            evidence={"bound_as": who},
        )

    async def _try_kerberos(self, host: str, port: int,
                            user: str, pwd: str) -> Optional[CredentialHit]:
        """Validate a credential via Kerberos AS-REQ pre-authentication (impacket).

        Acquiring a TGT proves the password is valid against the domain WITHOUT
        touching any application service — the cleanest possible cred check.
        Needs the realm, so the username must carry a domain (``DOMAIN\\user``
        or ``user@domain``); without one we raise a clear error rather than
        guess. A wrong password surfaces as ``KDC_ERR_PREAUTH_FAILED`` → no
        hit; genuine transport/KDC errors propagate so they're recorded, never
        silently passed."""
        try:
            from impacket.krb5 import constants  # type: ignore[import-not-found]
            from impacket.krb5.kerberosv5 import (  # type: ignore[import-not-found]
                KerberosError,
                getKerberosTGT,
            )
            from impacket.krb5.types import Principal  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError("impacket not installed") from e

        domain, u = self._split_domain(user)
        if not domain:
            raise RuntimeError(
                "kerberos requires a realm — supply DOMAIN\\user or user@domain")
        if not pwd:
            return None  # empty password can't yield a valid AS-REP; never overclaim

        # Error codes that mean "the credential is simply not valid" (as opposed
        # to a network/KDC fault) — these are a clean no-hit, not an error.
        no_hit = {
            constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value,       # bad password
            constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value,  # no such user
            constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value,       # disabled/locked
        }

        def _blocking() -> Optional[bool]:
            client = Principal(
                u, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            try:
                getKerberosTGT(client, pwd, domain, "", "", "", kdcHost=host)
                return True
            except KerberosError as ke:
                if ke.getErrorCode() in no_hit:
                    return None
                raise

        loop = asyncio.get_event_loop()
        try:
            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking), timeout=self.timeout + 4)
        except asyncio.TimeoutError:
            return None
        if not ok:
            return None
        return CredentialHit(
            host=host, port=port, service="kerberos", username=user,
            notes="Kerberos pre-authentication succeeded (TGT obtained)",
            evidence={"realm": domain, "principal": u},
        )
