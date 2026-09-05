"""HEAVEN — UDP service scanner (privileged and unprivileged).

UDP scanning is genuinely hard: a closed UDP port stays silent unless the host
returns an ICMP port-unreachable, and firewalls routinely drop both. HEAVEN
handles it two ways so it works for everyone:

* **Privileged** (root / passwordless sudo, or Administrator): the caller uses
  nmap ``-sU`` for a full UDP state machine (open / open|filtered / closed).
* **Unprivileged** (the common case — a laptop, CI, a container without
  ``CAP_NET_RAW``): this pure-Python scanner probes each UDP port with a real,
  service-specific payload and reports a port **open only when a service actually
  answers**. That is the honest signal — a DNS server replies to a DNS query, an
  SNMP agent to a get-request, an NTP server to a time request — so a responsive
  UDP service is caught with no false positives, on any privilege level.

Silent ports (no reply, no ICMP) are ``open|filtered`` and are *counted*, not
reported as open — inventing an "open" from silence would be a false positive.
The connected-socket trick surfaces ICMP port-unreachable as ``ConnectionRefused``
where the OS delivers it, letting us mark those ports genuinely ``closed``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.udp_scanner")

# ── Service-specific UDP probes ────────────────────────────────────────────────
# A well-formed request for each protocol so a live service answers. The reply is
# what proves the port open — an empty datagram rarely elicits one, so a real
# probe is the difference between catching a UDP service and missing it.
UDP_SERVICE_PROBES: dict[int, bytes] = {
    # DNS — version.bind CH TXT query (also a plain A query many resolvers answer)
    53: (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07version\x04bind\x00\x00\x10\x00\x03"),
    # TFTP — read request for a nonexistent file → an ERROR datagram (still a reply)
    69: b"\x00\x01" + b"heaven\x00" + b"netascii\x00",
    # NTP — mode 3 (client) v3 request
    123: b"\x1b" + b"\x00" * 47,
    # NetBIOS name service — node status request
    137: (b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"),
    # SNMP — v1 get-request for sysDescr.0 with community "public"
    161: (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01"
          b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    # IKE / ISAKMP — main-mode SA proposal (a minimal, widely-answered header)
    500: (b"\x00" * 8 + b"\x00" * 8 + b"\x01\x10\x02\x00" + b"\x00" * 4
          + b"\x00\x00\x00\x1c"),
    # SIP — OPTIONS request
    5060: (b"OPTIONS sip:nm SIP/2.0\r\n"
           b"Via: SIP/2.0/UDP nm;branch=z9hG4bKheaven\r\n"
           b"From: <sip:nm@nm>;tag=root\r\nTo: <sip:nm@nm>\r\n"
           b"Call-ID: heaven@nm\r\nCSeq: 1 OPTIONS\r\n"
           b"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"),
    # mDNS — standard query for _services._dns-sd._udp.local PTR
    5353: (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"),
    # SSDP / UPnP — M-SEARCH discovery
    1900: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
    # RPC portmapper (SunRPC) — NULL call to the portmap program (v2, proc 0)
    111: (b"\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02"
          b"\x00\x01\x86\xA0\x00\x00\x00\x02\x00\x00\x00\x00"
          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
}

# A generic empty-ish probe for ports without a service-specific payload. Rarely
# elicits a reply (that's the nature of UDP), but harmless and occasionally useful.
_GENERIC_PROBE = b"\x00"

# Human-readable service names for the well-known UDP ports we probe / report.
UDP_SERVICE_NAMES: dict[int, str] = {
    53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 111: "rpcbind",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmptrap", 389: "ldap", 500: "isakmp", 514: "syslog", 520: "rip",
    623: "ipmi", 631: "ipp", 1194: "openvpn", 1434: "ms-sql-m", 1645: "radius",
    1646: "radius", 1701: "l2tp", 1812: "radius", 1813: "radius", 1900: "upnp",
    2049: "nfs", 4500: "ipsec-nat-t", 5060: "sip", 5353: "mdns", 11211: "memcached",
}

# The default "top UDP services" set — the ports worth probing when the caller
# asks for a UDP scan without naming ports. Real, commonly-exposed UDP services
# (DNS, DHCP, TFTP, NTP, SNMP, NetBIOS, RPC, IKE, syslog, RADIUS, L2TP, SIP,
# mDNS, UPnP, IPMI, memcached, NFS, MS-SQL browser, RIP, OpenVPN …). Kept modest
# so a UDP sweep stays feasible without root — each silent port costs a timeout.
COMMON_UDP_PORTS: tuple[int, ...] = (
    53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161, 162, 177, 389, 427,
    443, 500, 514, 520, 523, 546, 547, 623, 631, 1027, 1194, 1434, 1645, 1646,
    1701, 1718, 1719, 1812, 1813, 1900, 2049, 2222, 3283, 3478, 4500, 4789,
    5060, 5353, 5355, 5683, 6481, 11211, 17185, 20000, 32768, 49152,
)


def resolve_udp_ports(spec: Optional[str], tcp_ports: Optional[list[int]] = None,
                      *, max_ports: int = 1024) -> list[int]:
    """Resolve a UDP port spec into a concrete, sorted port list.

    ``spec`` may be ``None``/``""``/``"top"``/``"common"`` (the curated common-UDP
    set), ``"all"``/``"*"`` (1-65535 — slow; only sensible with root + nmap), or an
    explicit nmap-style spec (``"53,161,500"`` / ``"1-1024"``). A pure-Python
    unprivileged sweep is bounded to ``max_ports`` so it stays feasible; an
    explicit request larger than that is honoured only up to the cap (the caller
    logs the truncation).
    """
    from heaven.recon.network_scanner import parse_port_range

    s = (spec or "").strip().lower()
    if s in ("", "top", "common", "default"):
        ports = list(COMMON_UDP_PORTS)
    elif s in ("all", "*", "1-65535"):
        ports = list(range(1, 65536))
    else:
        try:
            ports = parse_port_range(s)
        except ValueError:
            logger.warning("invalid UDP port spec %r — falling back to common set", spec)
            ports = list(COMMON_UDP_PORTS)
    return sorted(set(ports))[:max_ports]


class _UDPProbeProtocol(asyncio.DatagramProtocol):
    """One connected UDP socket: send a probe, resolve on reply / refusal / timeout."""

    def __init__(self, probe: bytes, fut: "asyncio.Future[tuple[str, bytes]]"):
        self._probe = probe
        self._fut = fut

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        try:
            transport.sendto(self._probe)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — treat a send failure as no-response
            if not self._fut.done():
                self._fut.set_result(("filtered", b""))

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self._fut.done():
            self._fut.set_result(("open", data))

    def error_received(self, exc: Exception) -> None:
        # A connected UDP socket surfaces ICMP port-unreachable here as
        # ConnectionRefusedError → the port is genuinely closed.
        if not self._fut.done():
            state = "closed" if isinstance(exc, ConnectionRefusedError) else "filtered"
            self._fut.set_result((state, b""))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if not self._fut.done():
            self._fut.set_result(("filtered", b""))


async def _probe_one(host: str, port: int, timeout: float,
                     retries: int) -> tuple[int, str, bytes]:
    """Probe a single UDP port. Returns (port, state, response_bytes)."""
    probe = UDP_SERVICE_PROBES.get(port, _GENERIC_PROBE)
    loop = asyncio.get_running_loop()
    last_state = "open|filtered"
    for _ in range(max(1, retries)):
        fut: asyncio.Future[tuple[str, bytes]] = loop.create_future()
        transport = None
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProbeProtocol(probe, fut),
                remote_addr=(host, port),
            )
        except (OSError, ConnectionRefusedError) as e:
            # create failed (e.g. immediate refusal) — closed if refused.
            if isinstance(e, ConnectionRefusedError):
                return port, "closed", b""
            return port, "open|filtered", b""
        try:
            state, data = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            state, data = "open|filtered", b""
        finally:
            if transport is not None:
                transport.close()
        if state == "open":
            return port, "open", data
        if state == "closed":
            return port, "closed", b""
        last_state = "open|filtered"
    return port, last_state, b""


def _decode_banner(data: bytes) -> str:
    if not data:
        return ""
    text = data[:200].decode("latin-1", errors="replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text).strip(".")


async def scan_udp_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    concurrency: int = 128,
    retries: int = 2,
) -> dict[str, Any]:
    """Pure-Python UDP service scan of ``host`` across ``ports``.

    Returns ``{"open": [PortResult-dict, ...], "open_filtered": int, "closed": int}``.
    Only ports that ACTUALLY answered a probe are reported open — no invention from
    silence. Works without root on Linux / macOS / Windows.
    """
    if not ports:
        return {"open": [], "open_filtered": 0, "closed": 0}

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _guarded(p: int) -> tuple[int, str, bytes]:
        async with sem:
            try:
                return await _probe_one(host, p, timeout, retries)
            except Exception:  # noqa: BLE001 — one bad port never fails the sweep
                logger.debug("udp probe failed host=%s port=%s", host, p, exc_info=True)
                return p, "open|filtered", b""

    results = await asyncio.gather(*[_guarded(p) for p in ports])

    open_ports: list[dict[str, Any]] = []
    open_filtered = 0
    closed = 0
    for port, state, data in results:
        if state == "open":
            open_ports.append({
                "host": host, "port": port, "protocol": "udp", "state": "open",
                "service": UDP_SERVICE_NAMES.get(port, ""),
                "banner": _decode_banner(data),
            })
        elif state == "closed":
            closed += 1
        else:
            open_filtered += 1

    if open_ports:
        logger.info("UDP scan %s: %d open (responsive) service(s)", host, len(open_ports))
    return {"open": open_ports, "open_filtered": open_filtered, "closed": closed}


def _have_raw_udp() -> bool:
    """True when we can run nmap's raw -sU (root / passwordless sudo / admin)."""
    try:
        from heaven.recon.network_scanner import _have_admin_privileges, _nmap_sudo_prefix
        return _have_admin_privileges() or bool(_nmap_sudo_prefix())
    except Exception:  # noqa: BLE001
        return False
