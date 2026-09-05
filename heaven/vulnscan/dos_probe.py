"""
HEAVEN — Denial-of-Service (DoS/DDoS) susceptibility probe.

This module answers the CEH/CPENT "Denial-of-Service" domain **honestly and
safely**: it identifies whether a target is *abusable* as a reflection/
amplification source, or is *susceptible* to a slow-HTTP resource-exhaustion
attack. It NEVER launches a flood, never sends more than one probe per vector,
and never tries to actually take a service down.

Two classes of check, both single-shot and read-only:

1. **Reflection / amplification reflectors** — for each well-known UDP reflector
   protocol we send exactly ONE small, benign request and measure the size of
   the reflected reply. The *bandwidth amplification factor* (BAF = response
   bytes / request bytes) is the real, measured evidence that the host could be
   weaponised in a spoofed-source DDoS against a third party. Vectors:
   NTP monlist (CVE-2013-5211), DNS open-resolver, SSDP/UPnP, memcached
   (CVE-2018-1000115), CLDAP, chargen, QOTD, RIPv1 and NetBIOS name service.

2. **Slow-HTTP susceptibility** — a single connection that sends a partial
   request header and measures whether the server tolerates a very slow / never-
   completed header (the pre-condition for a Slowloris / slow-read attack). One
   socket, closed immediately; this is a susceptibility signal, not an attack.

Everything here is a *susceptibility assessment* — the finding is "this host can
be abused / is exposed", with the measured amplification factor or header-timeout
as proof. Nothing is written to the target and no flood is generated.

Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.dos_probe")

# Per-probe wait for a reflected UDP datagram. Short — a real reflector on the
# path answers in well under a second; anything slower we treat as "no reflector".
_UDP_TIMEOUT = 2.5
# Slow-HTTP: how long we let the server hold a partial-header connection open
# before we call it susceptible. A hardened server (mod_reqtimeout, nginx
# client_header_timeout, a reverse proxy) drops a stalled header well before this.
_SLOW_HTTP_HOLD = 8.0

# A reflector with BAF at or above this is a genuinely usable DDoS weapon.
_BAF_HIGH = 10.0
_BAF_MEDIUM = 2.0


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, *, confidence: float, evidence: dict) -> dict:
    """Finding dict in HEAVEN's standard shape (mirrors network_exposure)."""
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "evidence": evidence,
    }


# ── UDP reflector request builders (each returns one benign request datagram) ──

def _dns_qname(name: str) -> bytes:
    """Encode a DNS QNAME (labels length-prefixed, root-terminated)."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        lb = label.encode("idna") if label else b""
        out.append(len(lb))
        out.extend(lb)
    out.append(0)
    return bytes(out)


def _ntp_monlist_request() -> bytes:
    """NTP mode-7 (private) MON_GETLIST_1 — the classic monlist amplifier."""
    # LI/VN/Mode = 0x17 (VN=2, mode=7), auth/seq=0, impl=3 (XNTPD), req=42 (0x2a)
    return b"\x17\x00\x03\x2a" + b"\x00" * 4


def _ntp_readvar_request() -> bytes:
    """NTP mode-6 (control) READVAR — a smaller amplifier than monlist, present on
    servers that have monlist disabled but still answer control queries."""
    # LI/VN/Mode = 0x16 (VN=2, mode=6), op=2 (readvar), seq/status/assoc = 0
    return b"\x16\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _dns_any_request() -> bytes:
    """A single recursion-desired DNS query. If an open resolver answers it, the
    reply for a large zone is many times the request size."""
    txid = os.urandom(2)
    flags = b"\x01\x00"                         # RD=1 (recursion desired)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)   # qd=1
    # Query the root name servers (a benign, well-known large answer set) — ANY
    # so an open resolver returns the full root NS record set.
    question = _dns_qname(".") + struct.pack(">HH", 255, 1)  # QTYPE=ANY, QCLASS=IN
    return txid + flags + counts + question


def _ssdp_msearch_request() -> bytes:
    """SSDP/UPnP unicast M-SEARCH ssdp:all — a UPnP device answers with its full
    service list, amplifying the small request."""
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )


def _memcached_stats_request() -> bytes:
    """memcached UDP `stats` — CVE-2018-1000115. The 8-byte UDP frame header plus
    `stats\\r\\n` reflects a large stats block."""
    # frame header: request id, sequence number, total datagrams, reserved
    return b"\x00\x01\x00\x00\x00\x01\x00\x00" + b"stats\r\n"


def _chargen_request() -> bytes:
    """Character-generator (RFC 864): any datagram triggers a stream of output."""
    return b"\n"


def _qotd_request() -> bytes:
    """Quote-of-the-day (RFC 865): any datagram returns a quote."""
    return b"\n"


def _ripv1_request() -> bytes:
    """RIPv1 request for the full routing table (command=1, version=1) with a
    single AFI=0, metric=16 route entry meaning "send everything"."""
    header = struct.pack(">BBH", 1, 1, 0)                  # command=1, version=1
    rte = struct.pack(">HH", 0, 0) + b"\x00" * 12 + struct.pack(">I", 16)
    return header + rte


def _netbios_nbstat_request() -> bytes:
    """NetBIOS Name Service node-status (NBSTAT) query for '*' — reflects the
    host's registered name table."""
    txid = os.urandom(2)
    header = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # Encoded NetBIOS name for "*" (wildcard node status)
    encoded = bytearray([0x20])
    star = b"*" + b"\x00" * 15
    for byte in star:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    encoded.append(0x00)
    question = bytes(encoded) + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def _cldap_rootdse_request() -> bytes:
    """Connectionless LDAP (CLDAP) searchRequest for the rootDSE — a well-known
    amplifier against Active Directory / LDAP servers."""
    def _tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag]) + bytes([len(val)]) + val

    # searchRequest [APPLICATION 3]: base="", scope=base(0), deref=never(0),
    # sizeLimit=0, timeLimit=0, typesOnly=false, filter=present("objectClass"),
    # attributes = { namingContexts, ... } (empty SEQUENCE = all).
    base = _tlv(0x04, b"")
    scope = _tlv(0x0A, b"\x00")
    deref = _tlv(0x0A, b"\x00")
    size_limit = _tlv(0x02, b"\x00")
    time_limit = _tlv(0x02, b"\x00")
    types_only = _tlv(0x01, b"\x00")
    filt = _tlv(0x87, b"objectClass")           # present filter, context tag [7]
    attrs = _tlv(0x30, b"")                       # request all attributes
    search = _tlv(
        0x63,
        base + scope + deref + size_limit + time_limit + types_only + filt + attrs,
    )
    message_id = _tlv(0x02, b"\x01")
    return _tlv(0x30, message_id + search)


def _valid_udp_reply(data: bytes) -> bool:
    """A reflected reply is only interesting if the peer actually answered with
    payload — an ICMP-port-unreachable surfaces as an exception, not data."""
    return bool(data)


@dataclass(frozen=True)
class _Reflector:
    name: str
    port: int
    build: Callable[[], bytes]
    cve: str
    capec: str
    # Real-world worst-case BAF for context in the write-up (not the measured value).
    known_baf: str
    always_high: bool = False


# Ordered by how commonly they are abused in the wild.
_REFLECTORS: tuple[_Reflector, ...] = (
    _Reflector("NTP monlist", 123, _ntp_monlist_request, "CVE-2013-5211",
               "CAPEC-490", "≈556×", always_high=True),
    _Reflector("NTP readvar (mode 6)", 123, _ntp_readvar_request, "",
               "CAPEC-490", "≈3.9×"),
    _Reflector("DNS open resolver", 53, _dns_any_request, "",
               "CAPEC-490", "≈28–54×"),
    _Reflector("memcached", 11211, _memcached_stats_request, "CVE-2018-1000115",
               "CAPEC-490", "up to 51000×", always_high=True),
    _Reflector("SSDP / UPnP", 1900, _ssdp_msearch_request, "",
               "CAPEC-490", "≈30×"),
    _Reflector("CLDAP", 389, _cldap_rootdse_request, "",
               "CAPEC-490", "≈56–70×"),
    _Reflector("chargen", 19, _chargen_request, "",
               "CAPEC-490", "≈358×"),
    _Reflector("QOTD", 17, _qotd_request, "",
               "CAPEC-490", "≈140×"),
    _Reflector("RIPv1", 520, _ripv1_request, "",
               "CAPEC-490", "≈131×"),
    _Reflector("NetBIOS name service", 137, _netbios_nbstat_request, "",
               "CAPEC-490", "≈3.8×"),
)


async def _probe_reflector(host: str, refl: _Reflector,
                           timeout: float = _UDP_TIMEOUT
                           ) -> Optional[tuple[int, int, float]]:
    """Send one benign request to a UDP reflector and, if it answers, return
    (request_bytes, response_bytes, amplification_factor). None = no reflector."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not fut.done():
                fut.set_exception(exc)

    transport = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            _Proto, remote_addr=(host, refl.port))
        pkt = refl.build()
        transport.sendto(pkt)
        data = await asyncio.wait_for(fut, timeout)
        if not _valid_udp_reply(data):
            return None
        req_len, resp_len = len(pkt), len(data)
        factor = (resp_len / req_len) if req_len else 0.0
        return req_len, resp_len, factor
    except (asyncio.TimeoutError, OSError, ConnectionError):
        # Timeout / ICMP unreachable / closed → not a reflector.
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"reflector probe {refl.name} @ {host}:{refl.port} failed: {exc}")
        return None
    finally:
        if transport is not None:
            transport.close()


def _is_usable_reflector(refl: _Reflector, factor: float) -> bool:
    """Decide whether a reflected reply is a genuine amplifier worth reporting.

    A reply that is the same size or smaller than the request (BAF ≤ 1) is an
    error/echo, not amplification, so it is never reported. The named-CVE vectors
    (NTP monlist, memcached) are reported as soon as they answer with any real
    amplification (BAF > 1); every other vector must reach the medium BAF floor to
    count as a usable DDoS weapon.
    """
    if factor <= 1.0:
        return False
    if refl.always_high:
        return True
    return factor >= _BAF_MEDIUM


def _reflector_finding(host: str, refl: _Reflector,
                       req_len: int, resp_len: int, factor: float) -> dict:
    if refl.always_high or factor >= _BAF_HIGH:
        severity = "high"
    elif factor >= _BAF_MEDIUM:
        severity = "medium"
    else:
        severity = "low"
    cve_note = f" ({refl.cve})" if refl.cve else ""
    return _finding(
        target=f"{host}:{refl.port}",
        vuln_type="dos_amplification",
        severity=severity,
        title=f"DDoS Amplification Reflector — {refl.name}{cve_note}",
        description=(
            f"The {refl.name} service on UDP/{refl.port} answered a single small, "
            f"spoofable request with a reply {factor:.1f}× larger "
            f"({req_len}→{resp_len} bytes). An attacker can spoof a victim's source "
            f"address and use this host to reflect and amplify traffic in a "
            f"distributed denial-of-service attack against that victim "
            f"(real-world worst case for this vector is {refl.known_baf})."
        ),
        confidence=0.95,
        evidence={
            "vector": refl.name,
            "protocol": "udp",
            "port": refl.port,
            "request_bytes": req_len,
            "response_bytes": resp_len,
            "amplification_factor": round(factor, 2),
            "cve": refl.cve,
            "capec": refl.capec,
            "cwe": "CWE-406",
            "proof": (
                f"Sent {req_len}-byte {refl.name} request to {host}:{refl.port}/udp; "
                f"received {resp_len}-byte reflected reply (BAF {factor:.1f}×)."
            ),
        },
    )


# ── Slow-HTTP (Slowloris / slow-read) susceptibility ─────────────────────────

async def _slow_http_susceptible(host: str, port: int, use_tls: bool,
                                  hold: float = _SLOW_HTTP_HOLD
                                  ) -> Optional[float]:
    """Open ONE connection, send an incomplete request header, and measure how
    long the server keeps it open without responding. Returns the tolerated hold
    time in seconds if the server is susceptible (held the partial header for the
    full window without dropping it), else None. Single socket, closed at once —
    this is a susceptibility signal, not an attack."""
    reader = writer = None
    try:
        if use_tls:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            fut = asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
        else:
            fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=5.0)

        # Send a request line + one header, but never the terminating blank line.
        writer.write(b"GET / HTTP/1.1\r\n")
        writer.write(f"Host: {host}\r\n".encode())
        await writer.drain()

        start = asyncio.get_event_loop().time()
        # Dribble one bogus partial header slowly; a hardened server drops us.
        while asyncio.get_event_loop().time() - start < hold:
            try:
                writer.write(b"X-a: b\r\n")
                await writer.drain()
            except (ConnectionError, OSError):
                return None  # server closed the stalled connection → not susceptible
            # If the server responds/closes early, it isn't holding the partial header.
            try:
                data = await asyncio.wait_for(reader.read(1), timeout=1.5)
            except asyncio.TimeoutError:
                continue  # still holding the incomplete header open → the bad sign
            if data == b"":
                return None  # connection closed → server enforced a header timeout
            # Any response byte means the server answered without a complete
            # request (it did not sit and wait) → not the slow-header condition.
            return None
        return round(asyncio.get_event_loop().time() - start, 1)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"slow-http probe {host}:{port} failed: {exc}")
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                logger.debug("closing slow-http probe writer failed", exc_info=True)


def _slow_http_finding(host: str, port: int, use_tls: bool, held: float) -> dict:
    scheme = "https" if use_tls else "http"
    return _finding(
        target=f"{scheme}://{host}:{port}",
        vuln_type="slow_http_dos",
        severity="medium",
        title="Slow-HTTP (Slowloris) Denial-of-Service Susceptibility",
        description=(
            f"The web server held an incomplete request header open for {held:.0f}s "
            f"without enforcing a header-read timeout. A Slowloris / slow-read "
            f"attacker can hold many connections open with trickled partial "
            f"headers, exhausting the server's connection pool and denying service "
            f"to legitimate users — all from a single low-bandwidth host."
        ),
        confidence=0.75,
        evidence={
            "vector": "slow-http (Slowloris)",
            "protocol": scheme,
            "port": port,
            "header_hold_seconds": held,
            "cwe": "CWE-400",
            "capec": "CAPEC-469",
            "proof": (
                f"Sent an incomplete HTTP request header to {scheme}://{host}:{port} "
                f"and the server kept the connection open {held:.0f}s without a "
                f"header-read timeout."
            ),
        },
    )


# ── Host/port extraction from recon results ──────────────────────────────────

def _hosts_from_net_data(net_data: dict) -> list[tuple[str, set[int]]]:
    """Return [(ip, {open_tcp_ports})] from a network-recon result dict."""
    out: list[tuple[str, set[int]]] = []
    for host in (net_data or {}).get("hosts", []) or []:
        ip = host.get("ip") or host.get("host") or host.get("address")
        if not ip:
            continue
        ports: set[int] = set()
        for p in host.get("open_ports", []) or []:
            try:
                ports.add(int(p.get("port") if isinstance(p, dict) else p))
            except (TypeError, ValueError):
                continue
        out.append((str(ip), ports))
    return out


def _web_targets(net_data: dict, urls: list[str]) -> list[tuple[str, int, bool]]:
    """Return [(host, port, use_tls)] web endpoints to slow-HTTP test."""
    seen: set[tuple[str, int, bool]] = set()
    out: list[tuple[str, int, bool]] = []
    from urllib.parse import urlparse

    for url in urls or []:
        try:
            u = urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            logger.debug("could not parse target URL %r", url, exc_info=True)
            continue
        if not u.hostname:
            continue
        tls = u.scheme == "https"
        port = u.port or (443 if tls else 80)
        key = (u.hostname, port, tls)
        if key not in seen:
            seen.add(key)
            out.append(key)

    # Also pick up bare HTTP/HTTPS ports discovered by the network scan.
    for ip, ports in _hosts_from_net_data(net_data):
        for port, tls in ((80, False), (8080, False), (443, True), (8443, True)):
            if port in ports:
                key = (ip, port, tls)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


# ── Public entrypoint ────────────────────────────────────────────────────────

async def scan_dos_targets(
    net_data: Optional[dict] = None,
    urls: Optional[list[str]] = None,
    targets: Optional[list[str]] = None,
    *,
    max_hosts: int = 64,
    max_web: int = 12,
) -> dict:
    """Assess DoS/DDoS susceptibility across the discovered hosts.

    For every in-scope host we send one benign probe per UDP reflector vector and
    measure the amplification factor, and for every discovered web endpoint we run
    a single slow-HTTP header-timeout check. Returns ``{"findings": [...]}``.

    Nothing is flooded and nothing is written to any target — each check is a
    single, read-only susceptibility probe.
    """
    net_data = net_data or {}
    urls = urls or []
    findings: list[dict] = []

    host_ports = _hosts_from_net_data(net_data)
    if not host_ports and targets:
        host_ports = [(str(t), set()) for t in targets]
    host_ports = host_ports[:max_hosts]

    # 1. UDP reflector / amplification sweep — one packet per (host, vector).
    async def _scan_host_reflectors(ip: str, open_ports: set[int]) -> None:
        async def _one(refl: _Reflector) -> None:
            # If a TCP port scan saw the port closed we still probe UDP (UDP state
            # is independent), but if we have an explicit UDP-open hint we trust it.
            res = await _probe_reflector(ip, refl)
            if res is None:
                return
            req_len, resp_len, factor = res
            # Only report a genuine amplifier. A reply the same size or smaller is
            # an error/echo (e.g. a DNS server REFUSING our query), not a usable
            # DDoS reflector — reporting it would be a false positive. The known
            # high-BAF vectors with a named CVE (NTP monlist, memcached) qualify as
            # soon as they answer with real payload; the rest must show BAF ≥ 2×.
            if not _is_usable_reflector(refl, factor):
                return
            findings.append(_reflector_finding(ip, refl, req_len, resp_len, factor))

        await asyncio.gather(*(_one(r) for r in _REFLECTORS))

    await asyncio.gather(*(_scan_host_reflectors(ip, ports) for ip, ports in host_ports))

    # 2. Slow-HTTP susceptibility across discovered web endpoints.
    web = _web_targets(net_data, urls)[:max_web]

    async def _scan_web(host: str, port: int, tls: bool) -> None:
        held = await _slow_http_susceptible(host, port, tls)
        if held is not None and held >= (_SLOW_HTTP_HOLD - 1.0):
            findings.append(_slow_http_finding(host, port, tls, held))

    await asyncio.gather(*(_scan_web(h, p, t) for h, p, t in web))

    logger.info(
        f"DoS susceptibility probe complete: {len(findings)} finding(s) across "
        f"{len(host_ports)} host(s) and {len(web)} web endpoint(s)."
    )
    return {"findings": findings, "reflectors_tested": [r.name for r in _REFLECTORS]}
