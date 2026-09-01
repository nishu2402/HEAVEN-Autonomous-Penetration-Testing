"""
HEAVEN — Sniffing / internal Man-in-the-Middle susceptibility probe.

This answers the CEH/CPENT "Sniffing" domain for an **internal** engagement: it
finds the broadcast/multicast name-resolution services that let an on-segment
attacker (Responder / Inveigh / mitm6) poison name lookups, capture NetNTLM
hashes and relay authentication. Each check is a single, benign, standard
name-resolution query — nothing is poisoned, nothing is relayed.

Checks (all read-only, one query each):

* **NBT-NS (UDP 137)** — a NetBIOS node-status (NBSTAT) query. A reply proves the
  host participates in NetBIOS name resolution and discloses its name table; an
  attacker on the segment can spoof NBT-NS responses to coerce authentication.
* **LLMNR (UDP 5355)** — a Link-Local Multicast Name Resolution query for the
  host's own name (learned from NBT-NS). A reply proves LLMNR is enabled, so an
  attacker can race-answer LLMNR queries and capture credentials.
* **mDNS (UDP 5353)** — a multicast-DNS service-enumeration query. A reply proves
  mDNS/Bonjour/Avahi is reachable, disclosing services and enabling mDNS
  spoofing.
* **mitm6 (IPv6)** — if recon shows the host is dual-stack (has an IPv6 address),
  the segment is typically susceptible to the mitm6 attack (rogue DHCPv6 +
  IPv6 DNS takeover) unless RA-Guard / DHCPv6-Guard is deployed.

The findings are *susceptibility* observations — "this host/segment enables a
name-poisoning MITM primitive" — with the query/response as proof.

Cross-platform: Linux, macOS, Windows. Runs from an in-scope network position
(the normal footing for an internal test).
"""

from __future__ import annotations

import asyncio
import os
import struct
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.mitm_probe")

_UDP_TIMEOUT = 2.5

# NetBIOS suffix → role, for a readable name-table write-up.
_NBT_SUFFIX = {
    0x00: "Workstation",
    0x03: "Messenger",
    0x20: "File Server",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Elections",
}


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, *, confidence: float, evidence: dict) -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "evidence": evidence,
    }


async def _udp_query(host: str, port: int, payload: bytes,
                     timeout: float = _UDP_TIMEOUT) -> Optional[bytes]:
    """Send one UDP datagram and return the first reply, or None."""
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
            _Proto, remote_addr=(host, port))
        transport.sendto(payload)
        return await asyncio.wait_for(fut, timeout)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"udp query {host}:{port} failed: {exc}")
        return None
    finally:
        if transport is not None:
            transport.close()


# ── NBT-NS (NetBIOS name service) ─────────────────────────────────────────────

def _nbstat_request() -> bytes:
    """NetBIOS node-status (NBSTAT) query for the wildcard name '*'."""
    txid = os.urandom(2)
    header = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    encoded = bytearray([0x20])
    star = b"*" + b"\x00" * 15
    for byte in star:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    encoded.append(0x00)
    question = bytes(encoded) + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def _skip_dns_name(data: bytes, off: int) -> int:
    """Return the offset just past a DNS/NetBIOS name at ``off`` (handles both a
    compression pointer and a length-prefixed label sequence)."""
    while off < len(data):
        length = data[off]
        if length == 0:                    # root terminator
            return off + 1
        if length & 0xC0 == 0xC0:          # compression pointer (2 bytes)
            return off + 2
        off += 1 + length
    return off


def _parse_nbstat_names(data: bytes) -> list[tuple[str, int]]:
    """Extract (name, suffix) pairs from an NBSTAT response's name table.

    The answer RR begins immediately after the 12-byte header (the NBSTAT reply
    sets QDCOUNT=0 and does not echo the question). Layout: answer name, then
    type(2) class(2) ttl(4) rdlength(2), then RDATA = num_names(1) followed by
    18-byte entries (15-byte name, 1-byte suffix, 2-byte flags).
    """
    names: list[tuple[str, int]] = []
    try:
        if len(data) < 12:
            return names
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount < 1:
            return names
        off = _skip_dns_name(data, 12)     # past the answer RR name
        off += 2 + 2 + 4                   # type + class + ttl
        if off + 2 > len(data):
            return names
        rdlen = struct.unpack(">H", data[off:off + 2])[0]
        rd = data[off + 2:off + 2 + rdlen]
        if not rd:
            return names
        count = rd[0]
        pos = 1
        for _ in range(count):
            if pos + 18 > len(rd):
                break
            name = rd[pos:pos + 15].decode("ascii", "ignore").strip()
            suffix = rd[pos + 15]
            if name:
                names.append((name, suffix))
            pos += 18
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"nbstat parse failed: {exc}")
    return names


def _host_name_from_nbt(names: list[tuple[str, int]]) -> str:
    """The host's own workstation name (<00> UNIQUE), for the LLMNR probe."""
    for name, suffix in names:
        if suffix == 0x00:
            return name
    return names[0][0] if names else ""


async def _probe_nbtns(host: str) -> Optional[list[tuple[str, int]]]:
    data = await _udp_query(host, 137, _nbstat_request())
    if not data or len(data) < 12:
        return None
    names = _parse_nbstat_names(data)
    return names if names else []


# ── LLMNR (Link-Local Multicast Name Resolution) ─────────────────────────────

def _dns_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        lb = label.encode("ascii", "ignore")
        out.append(len(lb))
        out.extend(lb)
    out.append(0)
    return bytes(out)


def _llmnr_query(name: str) -> bytes:
    """A standard LLMNR query (DNS wire format) for `name`, type A."""
    txid = os.urandom(2)
    flags = b"\x00\x00"                          # standard query, no flags
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = _dns_qname(name) + struct.pack(">HH", 1, 1)  # A, IN
    return txid + flags + counts + question


async def _probe_llmnr(host: str, name: str) -> bool:
    """True if the host answers an LLMNR query for its own name (LLMNR enabled)."""
    if not name:
        return False
    data = await _udp_query(host, 5355, _llmnr_query(name))
    if not data or len(data) < 12:
        return False
    # A response has QR=1 and at least one answer record.
    qr = bool(data[2] & 0x80)
    ancount = struct.unpack(">H", data[6:8])[0]
    return qr and ancount >= 1


# ── mDNS (multicast DNS / Bonjour / Avahi) ───────────────────────────────────

def _mdns_query() -> bytes:
    """A benign mDNS service-enumeration query (_services._dns-sd._udp.local PTR)."""
    txid = b"\x00\x00"
    flags = b"\x00\x00"
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    name = _dns_qname("_services._dns-sd._udp.local")
    question = name + struct.pack(">HH", 12, 1)  # PTR, IN
    return txid + flags + counts + question


async def _probe_mdns(host: str) -> bool:
    data = await _udp_query(host, 5353, _mdns_query())
    if not data or len(data) < 12:
        return False
    ancount = struct.unpack(">H", data[6:8])[0]
    return bool(data[2] & 0x80) and ancount >= 1


# ── Findings ─────────────────────────────────────────────────────────────────

def _nbtns_finding(host: str, names: list[tuple[str, int]]) -> dict:
    table = ", ".join(
        f"{n}<{s:02X}> ({_NBT_SUFFIX.get(s, 'unknown')})" for n, s in names[:8]
    )
    return _finding(
        target=f"{host}:137",
        vuln_type="nbtns_poisoning",
        severity="high",
        title="NBT-NS Name Poisoning Susceptibility (Responder/SMB Relay)",
        description=(
            "The host answered a NetBIOS Name Service (UDP 137) node-status query, "
            "so it participates in NetBIOS broadcast name resolution. An attacker "
            "on the same segment can spoof NBT-NS responses (Responder/Inveigh) to "
            "become the answer for a mistyped or failed lookup, coercing the victim "
            "to authenticate and capturing its NetNTLM hash for offline cracking or "
            "SMB relay."
        ),
        confidence=0.9,
        evidence={
            "protocol": "nbt-ns",
            "port": 137,
            "name_table": table,
            "cwe": "CWE-290",
            "mitre": "T1557.001",
            "capec": "CAPEC-89",
            "proof": (
                f"NBT-NS node-status query to {host}:137/udp returned the host name "
                f"table: {table}."
            ),
            "attack_tools": ["Responder", "Inveigh", "ntlmrelayx"],
        },
    )


def _llmnr_finding(host: str, name: str) -> dict:
    return _finding(
        target=f"{host}:5355",
        vuln_type="llmnr_poisoning",
        severity="high",
        title="LLMNR Name Poisoning Susceptibility (Responder/SMB Relay)",
        description=(
            "The host answered a Link-Local Multicast Name Resolution (UDP 5355) "
            "query for its own name, so LLMNR is enabled. When a name fails to "
            "resolve via DNS, hosts fall back to LLMNR and any machine on the "
            "segment may answer. An attacker can race-answer LLMNR queries "
            "(Responder/Inveigh) to capture NetNTLM credentials or relay them to "
            "another host."
        ),
        confidence=0.9,
        evidence={
            "protocol": "llmnr",
            "port": 5355,
            "resolved_name": name,
            "cwe": "CWE-290",
            "mitre": "T1557.001",
            "capec": "CAPEC-89",
            "proof": (
                f"LLMNR query for '{name}' to {host}:5355/udp was answered, "
                f"confirming LLMNR is enabled."
            ),
            "attack_tools": ["Responder", "Inveigh", "ntlmrelayx"],
        },
    )


def _mdns_finding(host: str) -> dict:
    return _finding(
        target=f"{host}:5353",
        vuln_type="mdns_exposure",
        severity="medium",
        title="mDNS / Bonjour Exposure & Spoofing Susceptibility",
        description=(
            "The host answered a multicast-DNS (UDP 5353) service-enumeration "
            "query. mDNS discloses advertised services and host information, and an "
            "on-segment attacker can spoof mDNS responses to redirect '.local' name "
            "resolution and stage a man-in-the-middle."
        ),
        confidence=0.85,
        evidence={
            "protocol": "mdns",
            "port": 5353,
            "cwe": "CWE-290",
            "mitre": "T1557",
            "capec": "CAPEC-89",
            "proof": (
                f"mDNS service query (_services._dns-sd._udp.local) to {host}:5353/udp "
                f"was answered."
            ),
        },
    )


def _mitm6_finding(host: str, ipv6: str) -> dict:
    return _finding(
        target=host,
        vuln_type="ipv6_mitm6",
        severity="medium",
        title="IPv6 mitm6 Susceptibility (Dual-Stack, No DHCPv6/RA Guard)",
        description=(
            "The host is dual-stack (reachable/advertised over IPv6) while the "
            "environment is administered over IPv4. Windows prefers IPv6 and looks "
            "for a DHCPv6 server, so an attacker running mitm6 can answer as the "
            "rogue DHCPv6 server, assign itself as the host's IPv6 DNS, and "
            "man-in-the-middle traffic (commonly chained with ntlmrelayx to relay "
            "to LDAP/SMB) unless RA-Guard and DHCPv6-Guard are enforced."
        ),
        confidence=0.6,
        evidence={
            "protocol": "ipv6",
            "ipv6_address": ipv6,
            "cwe": "CWE-300",
            "mitre": "T1557",
            "capec": "CAPEC-94",
            "proof": f"Recon shows {host} is reachable/advertised over IPv6 ({ipv6}).",
            "attack_tools": ["mitm6", "ntlmrelayx"],
        },
    )


def _hosts_from_net_data(net_data: dict) -> list[tuple[str, str]]:
    """Return [(ip, ipv6_or_empty)] from a network-recon result."""
    out: list[tuple[str, str]] = []
    for host in (net_data or {}).get("hosts", []) or []:
        ip = host.get("ip") or host.get("host") or host.get("address")
        if not ip:
            continue
        ipv6 = ""
        for key in ("ipv6", "ip6", "address6"):
            if host.get(key):
                ipv6 = str(host[key])
                break
        # Some scanners record all addresses in a list.
        for addr in host.get("addresses", []) or []:
            if isinstance(addr, str) and ":" in addr:
                ipv6 = addr
                break
        out.append((str(ip), ipv6))
    return out


async def scan_mitm_targets(
    net_data: Optional[dict] = None,
    targets: Optional[list[str]] = None,
    *,
    max_hosts: int = 128,
) -> dict:
    """Assess internal sniffing / MITM name-poisoning susceptibility.

    For each in-scope host: one NBT-NS node-status query, one LLMNR query (for the
    name NBT-NS disclosed), one mDNS query, plus a mitm6 flag when recon shows the
    host is dual-stack. Returns ``{"findings": [...]}``. All probes are single
    benign name-resolution queries — nothing is poisoned or relayed.
    """
    net_data = net_data or {}
    findings: list[dict] = []

    host_v6 = _hosts_from_net_data(net_data)
    if not host_v6 and targets:
        host_v6 = [(str(t), "") for t in targets]
    host_v6 = host_v6[:max_hosts]

    async def _scan_host(ip: str, ipv6: str) -> None:
        # NBT-NS first — it both flags susceptibility and hands us the hostname.
        names = await _probe_nbtns(ip)
        host_name = ""
        if names is not None and names:
            findings.append(_nbtns_finding(ip, names))
            host_name = _host_name_from_nbt(names)

        # LLMNR — needs a name to confirm the responder is enabled.
        if host_name and await _probe_llmnr(ip, host_name):
            findings.append(_llmnr_finding(ip, host_name))

        # mDNS — independent multicast responder.
        if await _probe_mdns(ip):
            findings.append(_mdns_finding(ip))

        # mitm6 — a posture flag from recon (dual-stack), not an active probe.
        if ipv6:
            findings.append(_mitm6_finding(ip, ipv6))

    await asyncio.gather(*(_scan_host(ip, v6) for ip, v6 in host_v6))

    logger.info(
        f"MITM/sniffing susceptibility probe complete: {len(findings)} finding(s) "
        f"across {len(host_v6)} host(s)."
    )
    return {"findings": findings}
