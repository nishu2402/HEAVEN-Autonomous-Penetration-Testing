"""HEAVEN — NTLM authentication-coercion surface detection (read-only).

Coercion attacks (PetitPotam / MS-EFSR, PrinterBug / MS-RPRN, DFSCoerce /
MS-DFSNM) force a Windows host — often a Domain Controller — to authenticate to an
attacker-chosen machine over SMB/RPC. Relayed to LDAP or to an AD CS web-enrolment
endpoint (ESC8), that machine authentication becomes full domain compromise.
HEAVEN already flags the two ends of that chain (SMB signing not required =
relay target; AD CS web enrolment = ESC8). This module detects the missing
middle: whether the RPC interfaces that trigger coercion are actually reachable.

It works by *binding* to each coercion interface over its named pipe and stopping
there. A successful DCE/RPC bind proves the interface is exposed and the coercion
call would be reachable. It never sends the coercion RPC itself
(``RpcRemoteFindFirstPrinterChangeNotification`` / ``EfsRpcOpenFileRaw`` /
``NetrDfsAddStdRoot``), so no authentication is ever coerced and nothing is
relayed — the detection is entirely non-destructive.

Binding these pipes requires an SMB session. A null/anonymous session is tried
first (it still succeeds against legacy hosts); domain credentials, when supplied,
are used otherwise. When no session can be established the host is simply not
assessable from this vantage and no finding is invented.
"""

from __future__ import annotations

import asyncio
import socket

from heaven.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from impacket.dcerpc.v5 import transport
    from impacket.uuid import uuidtup_to_bin
    HAS_IMPACKET = True
except Exception:
    HAS_IMPACKET = False

# (label, method, named-pipes-to-try, (interface-uuid, version)).
# EFSR is exposed on several pipes depending on the host role; try the common ones.
_COERCION_INTERFACES = [
    ("MS-RPRN (PrinterBug)", "SpoolSample", ["spoolss"],
     ("12345678-1234-ABCD-EF00-0123456789AB", "1.0")),
    ("MS-EFSR (PetitPotam)", "PetitPotam", ["lsarpc", "efsrpc", "samr", "netlogon", "lsass"],
     ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")),
    ("MS-DFSNM (DFSCoerce)", "DFSCoerce", ["netdfs"],
     ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0")),
]


def _try_bind(host: str, pipe: str, uuid_tuple: tuple[str, str],
              username: str, password: str, domain: str,
              timeout: float) -> bool:
    """Bind (only) to one RPC interface over a named pipe. True = interface exposed."""
    string_binding = rf"ncacn_np:{host}[\pipe\{pipe}]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    try:
        rpctransport.set_connect_timeout(timeout)
    except Exception:
        logger.debug("set_connect_timeout unsupported by this transport", exc_info=True)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(username, password, domain, "", "")
    dce = rpctransport.get_dce_rpc()
    try:
        dce.connect()
        dce.bind(uuidtup_to_bin(uuid_tuple))
        return True
    except Exception:
        return False
    finally:
        try:
            dce.disconnect()
        except Exception:
            logger.debug("dce.disconnect failed", exc_info=True)


def _probe_host(host: str, username: str, password: str, domain: str,
                timeout: float) -> list[dict]:
    """Return the coercion methods reachable on ``host`` (synchronous)."""
    available: list[dict] = []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for label, method, pipes, uuid_tuple in _COERCION_INTERFACES:
            for pipe in pipes:
                try:
                    if _try_bind(host, pipe, uuid_tuple, username, password,
                                 domain, timeout):
                        available.append({"label": label, "method": method,
                                          "pipe": pipe, "interface": uuid_tuple[0]})
                        break  # one reachable pipe is enough for this method
                except Exception:
                    logger.debug("bind attempt on pipe %s failed", pipe, exc_info=True)
                    continue
    finally:
        socket.setdefaulttimeout(old_timeout)
    return available


async def coercion_surface_probe(host: str, username: str = "", password: str = "",
                                 domain: str = "", timeout: float = 6.0) -> list[dict]:
    """Detect reachable NTLM-coercion RPC interfaces on ``host``.

    Returns a list with at most one ``ntlm_coercion`` finding dict (naming every
    reachable method). Empty when impacket is unavailable, no SMB session can be
    established, or no coercion interface is exposed.
    """
    if not HAS_IMPACKET or not host:
        return []
    try:
        available = await asyncio.to_thread(
            _probe_host, host, username, password, domain, timeout)
    except Exception:
        logger.debug("coercion probe failed for %s", host, exc_info=True)
        return []
    if not available:
        return []

    methods = ", ".join(f"{a['method']} ({a['label']})" for a in available)
    logger.info("NTLM coercion surface on %s: %s", host, methods)
    return [{
        "target": host,
        "vuln_type": "ntlm_coercion",
        "severity": "high",
        "title": f"NTLM authentication-coercion surface exposed on {host}",
        "description": (
            f"The host exposes RPC interface(s) that can be abused to coerce it into "
            f"authenticating to an attacker-controlled machine: {methods}. Relayed to "
            f"LDAP (if SMB/LDAP signing is not enforced) or to an AD CS web-enrolment "
            f"endpoint (ESC8), the coerced machine authentication leads to privilege "
            f"escalation up to full domain compromise. HEAVEN confirmed the interface "
            f"is reachable by binding to it; it did not trigger the coercion."),
        "confidence": 0.85,
        "remediation": (
            "1. Enforce SMB signing and LDAP signing + channel binding so coerced "
            "authentications cannot be relayed.\n"
            "2. Disable the Print Spooler service on Domain Controllers and servers "
            "that do not need it (mitigates MS-RPRN / PrinterBug).\n"
            "3. Apply the MS-EFSR (PetitPotam) and MS-DFSNM (DFSCoerce) patches and "
            "restrict RPC access with an RPC filter / firewall.\n"
            "4. Enable Extended Protection for Authentication (EPA) on AD CS web "
            "enrolment and LDAP."),
        "mitre_technique": "T1187 · Forced Authentication",
        "evidence": {"host": host, "methods": available,
                     "note": "interface bind only; coercion call never issued"},
    }]
