"""
HEAVEN — IoT / SCADA / OT Security Scanner

Two distinct scan surfaces share this module:

* ``scan_iot_targets`` — consumer / building-automation devices: Modbus, MQTT,
  SNMP, RTSP cameras, CoAP, UPnP/SSDP and vendor web panels.
* ``scan_ot_targets``  — operational-technology / ICS: Modbus, Siemens S7comm,
  EtherNet/IP, DNP3, IEC 60870-5-104, OPC-UA and BACnet.

Every finding is either

* **proven** — a real, protocol-correct handshake elicited a valid response
  (high confidence, evidence attached), or
* **detected-but-unconfirmed** — a well-known port is open but the protocol
  handshake did not confirm (``info`` severity, low confidence, "verify"),

so nothing is ever fabricated from an open port alone. All probes are
**READ-ONLY** — identification / read requests only; the scanner never writes
to a PLC, changes a register, or issues a control command.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.iot")


@dataclass
class IoTFinding:
    target: str
    protocol: str
    severity: str
    title: str
    description: str
    port: int = 0
    device_info: dict = field(default_factory=dict)
    confidence: float = 0.0
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target, "protocol": self.protocol,
            "severity": self.severity, "title": self.title,
            "description": self.description, "port": self.port,
            "device_info": self.device_info, "confidence": self.confidence,
            "remediation": self.remediation, "cwe": self.cwe,
        }


# IoT default credentials (vendor, service, username, password). Used to
# ACTIVELY verify a login against a fingerprinted web panel — never reported
# as a vulnerability without a confirmed authentication.
IOT_DEFAULT_CREDS = [
    ("Hikvision", "web", "admin", "12345"),
    ("Dahua", "web", "admin", "admin"),
    ("Axis", "web", "root", "pass"),
    ("Ubiquiti", "ssh", "ubnt", "ubnt"),
    ("MikroTik", "web", "admin", ""),
    ("TP-Link", "web", "admin", "admin"),
    ("D-Link", "web", "admin", ""),
    ("Netgear", "web", "admin", "password"),
    ("Linksys", "web", "admin", "admin"),
    ("Ruckus", "web", "super", "sp-admin"),
    ("Honeywell", "web", "admin", "1234"),
    ("Schneider Electric", "web", "USER", "USER"),
    ("Siemens", "web", "admin", "admin"),
    ("Rockwell", "web", "admin", "1234"),
    ("Moxa", "web", "admin", ""),
    ("Advantech", "web", "admin", "admin"),
    ("Digi", "web", "root", "dbps"),
    ("Sierra Wireless", "web", "user", "12345"),
    ("Crestron", "web", "admin", "admin"),
    ("Extron", "web", "admin", "extron"),
    ("Bosch", "web", "service", "service"),
    ("Pelco", "web", "admin", "admin"),
    ("FLIR", "web", "admin", "fliradmin"),
    ("Vivotek", "web", "root", ""),
    ("Foscam", "web", "admin", ""),
]

# Vendor fingerprints: a specific token that must appear as a whole word (or in
# a Server / WWW-Authenticate header) to claim the vendor. Avoids the classic
# substring false positive ("GE" matching "imaGE"/"paGE").
_VENDOR_TOKENS = {
    "Hikvision": ["hikvision", "webs", "dvrdvs"],
    "Dahua": ["dahua", "webserver 2.0"],
    "Axis": ["axis"],
    "MikroTik": ["mikrotik", "routeros"],
    "TP-Link": ["tp-link", "tp link"],
    "D-Link": ["d-link", "dlink"],
    "Netgear": ["netgear"],
    "Linksys": ["linksys"],
    "Ubiquiti": ["ubiquiti", "airos", "edgeos"],
    "Honeywell": ["honeywell"],
    "Schneider Electric": ["schneider"],
    "Siemens": ["siemens", "simatic"],
    "Rockwell": ["rockwell", "allen-bradley"],
    "Moxa": ["moxa"],
    "Advantech": ["advantech"],
    "Crestron": ["crestron"],
    "Vivotek": ["vivotek"],
    "Foscam": ["foscam"],
    "Pelco": ["pelco"],
    "FLIR": ["fliradmin"],
}

# Consumer / building-automation IoT ports.
IOT_TCP_PORTS = {
    502: "Modbus TCP", 1883: "MQTT", 8883: "MQTT (TLS)",
    554: "RTSP (camera)", 80: "HTTP (panel)", 443: "HTTPS (panel)",
    8080: "HTTP alt (panel)", 8443: "HTTPS alt (panel)",
}
IOT_UDP_PORTS = {161: "SNMP", 5683: "CoAP", 47808: "BACnet/IP", 1900: "UPnP/SSDP"}

# Operational-technology / ICS ports.
OT_TCP_PORTS = {
    502: "Modbus TCP", 102: "Siemens S7comm", 44818: "EtherNet/IP",
    20000: "DNP3", 2404: "IEC 60870-5-104", 4840: "OPC-UA",
}
OT_UDP_PORTS = {47808: "BACnet/IP", 44818: "EtherNet/IP (UDP)"}


# ── low-level transport helpers ───────────────────────────────────────────
async def _tcp_query(host: str, port: int, payload: bytes,
                     timeout: float, recv: int = 1024) -> Optional[bytes]:
    """Open a TCP connection, send ``payload``, return the first response chunk
    (or ``None`` on any failure). Read-only."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        return await asyncio.wait_for(reader.read(recv), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — best-effort close
            logger.debug("suppressed non-fatal exception", exc_info=True)


def _udp_query_blocking(host: str, port: int, payload: bytes,
                        timeout: float, recv: int) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(recv)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


async def _udp_query(host: str, port: int, payload: bytes,
                     timeout: float = 4.0, recv: int = 2048) -> Optional[bytes]:
    """Send one UDP datagram and wait for a reply. A UDP service is only
    treated as present when it actually answers a protocol-correct probe."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _udp_query_blocking, host, port, payload, timeout, recv)


async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            logger.debug("suppressed non-fatal exception", exc_info=True)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def _match_vendor(text: str) -> Optional[str]:
    """Return the IoT vendor whose fingerprint token appears as a whole word in
    ``text`` (body + Server + WWW-Authenticate), or ``None``. Whole-word / phrase
    matching avoids the classic substring false positive ("GE" in "imaGE")."""
    import re
    hay = text.lower()
    for name, tokens in _VENDOR_TOKENS.items():
        for tok in tokens:
            if re.search(r"(?<![a-z0-9])" + re.escape(tok) + r"(?![a-z0-9])", hay):
                return name
    return None


def _host_of(target: str) -> str:
    """Strip scheme / path / port from a target so protocol probes get a bare host."""
    t = target.strip()
    if "://" in t:
        from urllib.parse import urlparse
        t = urlparse(t).hostname or t
    if t.count(":") == 1 and not t.replace(":", "").replace(".", "").isalpha():
        # host:port (but not an IPv6 literal)
        t = t.split(":", 1)[0]
    return t


# ── DNP3 CRC (poly 0x3D65, reflected → 0xA6BC, one's-complemented) ─────────
def _dnp3_crc(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    crc = (~crc) & 0xFFFF
    return struct.pack("<H", crc)


# ── protocol probes: each returns evidence dict on confirmation, else None ──
async def probe_modbus(host: str, port: int = 502, timeout: float = 4.0) -> Optional[dict]:
    """Modbus Read Device Identification (FC 43 / MEI 14) — read-only. Even a
    Modbus *exception* reply confirms an unauthenticated Modbus endpoint."""
    req = struct.pack(">HHHBBBBB", 1, 0, 5, 0xFF, 0x2B, 0x0E, 0x01, 0x00)
    resp = await _tcp_query(host, port, req, timeout)
    if (resp and len(resp) >= 8 and resp[0:2] == b"\x00\x01"
            and resp[2:4] == b"\x00\x00" and resp[7] in (0x2B, 0xAB)):
        return {"function": resp[7], "unit_id": resp[6]}
    return None


async def probe_mqtt(host: str, port: int = 1883, timeout: float = 4.0) -> Optional[dict]:
    """MQTT CONNECT → CONNACK. Return code 0 = anonymous accepted."""
    client_id = b"HEAVEN_SCAN"
    connect = bytearray([
        0x10, 12 + len(client_id),
        0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C,
        0x00, len(client_id),
    ])
    connect.extend(client_id)
    resp = await _tcp_query(host, port, bytes(connect), timeout, recv=8)
    if resp and len(resp) >= 4 and resp[0] == 0x20:
        return {"connack_code": resp[3], "anonymous": resp[3] == 0}
    return None


async def probe_snmp(host: str, port: int = 161, timeout: float = 4.0) -> Optional[dict]:
    """SNMP v1 GET sysDescr against default community strings."""
    for community in ("public", "private", "community", "default"):
        comm = community.encode()
        # SNMPv1 GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr)
        pdu = (b"\x02\x01\x00" + b"\x04" + bytes([len(comm)]) + comm
               + b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
               + b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
        msg = b"\x30" + bytes([len(pdu) + 3]) + b"\x02\x01\x00" + pdu
        resp = await _udp_query(host, port, msg, timeout)
        if resp and resp[:1] == b"\x30":
            return {"community": community}
    return None


async def probe_rtsp(host: str, port: int = 554, timeout: float = 4.0) -> Optional[dict]:
    """RTSP DESCRIBE — 200 = unauthenticated stream, 401 = auth-protected."""
    req = f"DESCRIBE rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    resp = await _tcp_query(host, port, req.encode(), timeout)
    if not resp:
        return None
    text = resp.decode(errors="ignore")
    if text.startswith("RTSP/1.0"):
        code = text.split()[1] if len(text.split()) > 1 else ""
        return {"status": code, "unauthenticated": "200" in text.split("\r\n")[0]}
    return None


async def probe_bacnet(host: str, port: int = 47808, timeout: float = 4.0) -> Optional[dict]:
    """BACnet/IP Who-Is (unconfirmed) → I-Am. A 0x81 (BVLC) reply confirms BACnet."""
    who_is = bytes([0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08])
    resp = await _udp_query(host, port, who_is, timeout)
    if resp and resp[:1] == b"\x81":
        info: dict = {"bvlc_function": resp[1] if len(resp) > 1 else None}
        return info
    return None


async def probe_coap(host: str, port: int = 5683, timeout: float = 4.0) -> Optional[dict]:
    """CoAP GET /.well-known/core — a version-1 CoAP reply confirms the service."""
    well_known = b".well-known"
    header = bytes([0x40, 0x01, 0x12, 0x34])  # ver1, CON, GET, msg-id
    opts = bytes([(11 << 4) | len(well_known)]) + well_known + bytes([0x04]) + b"core"
    resp = await _udp_query(host, port, header + opts, timeout)
    if resp and (resp[0] >> 6) == 1:  # CoAP version 1
        return {"response_code": resp[1]}
    return None


async def probe_ssdp(host: str, port: int = 1900, timeout: float = 4.0) -> Optional[dict]:
    """SSDP unicast M-SEARCH → HTTP/1.1 200 with device headers."""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\nST: ssdp:all\r\n\r\n"
    ).encode()
    resp = await _udp_query(host, port, msearch, timeout)
    if resp and resp[:8].upper().startswith(b"HTTP/1.1"):
        text = resp.decode(errors="ignore")
        server = ""
        location = ""
        for line in text.split("\r\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif low.startswith("location:"):
                location = line.split(":", 1)[1].strip()
        return {"server": server, "location": location}
    return None


async def probe_s7comm(host: str, port: int = 102, timeout: float = 4.0) -> Optional[dict]:
    """Siemens S7comm: ISO-COTP connect → S7 setup-communication (read-only).
    A valid S7 (protocol-id 0x32) response confirms an S7 PLC."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        # COTP Connection Request (rack 0 / slot 2)
        cotp_cr = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
        writer.write(cotp_cr)
        await writer.drain()
        cc = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not (cc and len(cc) >= 6 and cc[5] == 0xD0):  # COTP Connection Confirm
            return None
        # S7 Setup Communication
        s7_setup = bytes.fromhex("0300001902f080320100000000000800000103c0010a")
        writer.write(s7_setup)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        if resp and b"\x32" in resp[7:9]:  # S7 protocol id at TPKT+COTP offset
            return {"cotp_confirmed": True, "s7_setup": True}
        return {"cotp_confirmed": True, "s7_setup": False}
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            logger.debug("suppressed non-fatal exception", exc_info=True)


async def probe_enip(host: str, port: int = 44818, timeout: float = 4.0) -> Optional[dict]:
    """EtherNet/IP ListIdentity (0x63) over UDP → device identity. Read-only."""
    header = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    resp = await _udp_query(host, port, header, timeout)
    if not (resp and len(resp) >= 24 and resp[0:2] == b"\x63\x00"):
        return None
    info: dict = {}
    try:
        body = resp[24:]
        # item count(2), item type(2 == 0x0C), item len(2), then identity
        idx = 6 + 2 + 16 + 2 + 2 + 2 + 2 + 2 + 4  # skip to product-name length
        if len(body) > idx:
            name_len = body[idx]
            info["product_name"] = body[idx + 1:idx + 1 + name_len].decode(
                errors="replace")
            info["vendor_id"] = struct.unpack("<H", body[6:8])[0]
    except Exception:  # noqa: BLE001 — parse is best-effort; presence already proven
        logger.debug("suppressed non-fatal exception", exc_info=True)
    return info


async def probe_dnp3(host: str, port: int = 20000, timeout: float = 4.0) -> Optional[dict]:
    """DNP3 data-link Request-Link-Status (read-only). A 0x0564 reply confirms DNP3."""
    header = bytes([0x05, 0x64, 0x05, 0xC9, 0x00, 0x00, 0x01, 0x00])
    frame = header + _dnp3_crc(header)
    resp = await _tcp_query(host, port, frame, timeout)
    if resp and resp[0:2] == b"\x05\x64":
        return {"link_status": True}
    return None


async def probe_iec104(host: str, port: int = 2404, timeout: float = 4.0) -> Optional[dict]:
    """IEC 60870-5-104 STARTDT act → STARTDT con (U-frame). Read-only."""
    startdt_act = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
    resp = await _tcp_query(host, port, startdt_act, timeout)
    if resp and resp[:1] == b"\x68":
        return {"apci": resp[2] if len(resp) > 2 else None}
    return None


async def probe_opcua(host: str, port: int = 4840, timeout: float = 4.0) -> Optional[dict]:
    """OPC-UA HEL (Hello) → ACK (Acknowledge). Read-only handshake."""
    endpoint = f"opc.tcp://{host}:{port}".encode()
    body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0) + \
        struct.pack("<I", len(endpoint)) + endpoint
    msg = b"HELF" + struct.pack("<I", 8 + len(body)) + body
    resp = await _tcp_query(host, port, msg, timeout)
    if resp and resp[:3] == b"ACK":
        return {"acknowledged": True}
    return None


# ── IoT (consumer / building) scanner ─────────────────────────────────────
class IoTScanner:
    """Consumer / building-automation IoT scanner."""

    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout
        self._findings: list[IoTFinding] = []

    async def scan_host(self, host: str) -> list[IoTFinding]:
        host = _host_of(host)
        self._findings = []
        logger.info(f"IoT scanning {host}...")

        # TCP services (probe only what's actually open)
        open_tcp = await self._open_tcp(host, list(IOT_TCP_PORTS))
        for port in open_tcp:
            if port == 502:
                await self._modbus(host, port)
            elif port in (1883, 8883):
                await self._mqtt(host, port)
            elif port == 554:
                await self._rtsp(host, port)
            elif port in (80, 443, 8080, 8443):
                await self._iot_web(host, port)

        # UDP services (the protocol probe IS the discovery — no fabrication)
        await self._snmp(host)
        await self._coap(host)
        await self._bacnet(host)
        await self._ssdp(host)

        logger.info(f"IoT scan complete for {host}: {len(self._findings)} findings")
        return self._findings

    async def _open_tcp(self, host: str, ports: list[int]) -> list[int]:
        sem = asyncio.Semaphore(100)

        async def check(p: int) -> Optional[int]:
            async with sem:
                return p if await _tcp_open(host, p, self._timeout) else None

        return [p for p in await asyncio.gather(*[check(p) for p in ports]) if p]

    async def _modbus(self, host: str, port: int) -> None:
        ev = await probe_modbus(host, port, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="Modbus TCP", severity="critical", port=port,
                title=f"Modbus TCP unauthenticated access on {host}:{port}",
                description="Modbus responded to a Read-Device-Identification "
                            "request without authentication — registers/coils are "
                            "reachable and could be read or written by an attacker.",
                device_info=ev, confidence=0.9, cwe="CWE-306",
                remediation="Segment the ICS network; front Modbus with an "
                            "authenticating gateway; restrict to an allowlist.",
            ))

    async def _mqtt(self, host: str, port: int) -> None:
        ev = await probe_mqtt(host, port, self._timeout)
        if not ev:
            return
        if ev["anonymous"]:
            self._findings.append(IoTFinding(
                target=host, protocol="MQTT", severity="critical", port=port,
                title=f"MQTT broker allows anonymous access on {host}:{port}",
                description="The MQTT broker accepted a CONNECT with no credentials "
                            "(CONNACK return code 0).",
                device_info=ev, confidence=0.95, cwe="CWE-306",
                remediation="Require authentication; enable TLS; apply topic ACLs.",
            ))
        else:
            self._findings.append(IoTFinding(
                target=host, protocol="MQTT", severity="info", port=port,
                title=f"MQTT broker detected on {host}:{port}",
                description=f"MQTT broker present (CONNACK code {ev['connack_code']}, "
                            "authentication required). Verify credential strength.",
                device_info=ev, confidence=0.6, cwe="CWE-1188",
                remediation="Ensure strong credentials and TLS are enforced.",
            ))

    async def _rtsp(self, host: str, port: int) -> None:
        ev = await probe_rtsp(host, port, self._timeout)
        if not ev:
            return
        if ev.get("unauthenticated"):
            self._findings.append(IoTFinding(
                target=host, protocol="RTSP", severity="high", port=port,
                title=f"Unauthenticated RTSP stream on {host}:{port}",
                description="RTSP DESCRIBE returned 200 OK without authentication — "
                            "the camera stream is viewable by anyone.",
                device_info=ev, confidence=0.85, cwe="CWE-306",
                remediation="Require RTSP authentication; encrypt the stream.",
            ))
        else:
            self._findings.append(IoTFinding(
                target=host, protocol="RTSP", severity="info", port=port,
                title=f"RTSP camera service detected on {host}:{port}",
                description=f"RTSP endpoint present (status {ev.get('status')}, "
                            "authentication required).",
                device_info=ev, confidence=0.6, cwe="",
                remediation="Confirm credentials are strong and unique.",
            ))

    async def _snmp(self, host: str) -> None:
        ev = await probe_snmp(host, 161, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="SNMP", severity="high", port=161,
                title=f"SNMP default community '{ev['community']}' on {host}",
                description=f"The device answered an SNMP GET using the default "
                            f"community string '{ev['community']}'.",
                device_info=ev, confidence=0.9, cwe="CWE-798",
                remediation="Change community strings; move to SNMPv3 with auth+priv.",
            ))

    async def _coap(self, host: str) -> None:
        ev = await probe_coap(host, 5683, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="CoAP", severity="medium", port=5683,
                title=f"CoAP service exposed on {host}:5683",
                description="A CoAP endpoint answered GET /.well-known/core over "
                            "unencrypted UDP — resources are discoverable without DTLS.",
                device_info=ev, confidence=0.85, cwe="CWE-319",
                remediation="Require CoAPs (DTLS); restrict to trusted networks.",
            ))

    async def _bacnet(self, host: str) -> None:
        ev = await probe_bacnet(host, 47808, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="BACnet", severity="medium", port=47808,
                title=f"BACnet/IP device responds to Who-Is on {host}:47808",
                description="A BACnet building-automation controller answered an "
                            "unauthenticated Who-Is broadcast (I-Am reply).",
                device_info=ev, confidence=0.85, cwe="CWE-306",
                remediation="Segment the BACnet network; use BACnet/SC where possible.",
            ))

    async def _ssdp(self, host: str) -> None:
        ev = await probe_ssdp(host, 1900, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="UPnP/SSDP", severity="medium", port=1900,
                title=f"UPnP/SSDP service exposed on {host}:1900",
                description="The device answered an SSDP M-SEARCH, disclosing device "
                            f"details (server: {ev.get('server') or 'n/a'}). UPnP can "
                            "expose internal services and port-forwarding controls.",
                device_info=ev, confidence=0.8, cwe="CWE-200",
                remediation="Disable UPnP on the WAN; restrict SSDP to the LAN.",
            ))

    async def _iot_web(self, host: str, port: int) -> None:
        """Fingerprint the web panel by whole-word vendor token, then ACTIVELY
        verify the default credential. A vuln is reported only on a *successful*
        login; otherwise a low-confidence info finding records the fingerprint."""
        try:
            import aiohttp
        except ImportError:
            return

        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{host}:{port}"
        vendor = None
        server = ""
        auth_required = False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        base, ssl=False, allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=self._timeout)) as resp:
                    body = await resp.text(errors="ignore")
                    server = resp.headers.get("Server", "")
                    realm = resp.headers.get("WWW-Authenticate", "")
                    # A default-credential login can only be *proven* against an
                    # HTTP-Basic challenge (401 + WWW-Authenticate). An open panel
                    # that answers 200 without any challenge must NOT be reported as
                    # "accepts default credentials" — that would be a false positive.
                    auth_required = resp.status == 401 and bool(realm)
                    vendor = _match_vendor(f"{body}\n{server}\n{realm}")
        except Exception:  # noqa: BLE001 — panel may be down / TLS error
            return
        if not vendor:
            return

        creds = next(((u, p) for v, svc, u, p in IOT_DEFAULT_CREDS
                      if v == vendor and svc == "web"), None)
        # Only attempt (and claim) a default-credential login when the panel
        # actually issued a Basic-auth challenge; a form-login panel can't be
        # proven generically, so it stays a fingerprint-only info finding.
        verified = False
        if creds and auth_required:
            verified = await self._try_default_login(base, creds[0], creds[1])

        if verified:
            self._findings.append(IoTFinding(
                target=host, protocol="HTTP", severity="critical", port=port,
                title=f"{vendor} panel accepts default credentials on {host}:{port}",
                description=f"Logged in to the {vendor} web panel with the default "
                            f"credentials {creds[0]}/{creds[1] or '(empty)'} — "
                            "confirmed by a successful authenticated response.",
                device_info={"vendor": vendor, "server": server,
                             "verified_login": True},
                confidence=0.95, cwe="CWE-798",
                remediation=f"Immediately change the default {vendor} credentials.",
            ))
        else:
            hint = (f" Default credentials to verify: {creds[0]}/{creds[1] or '(empty)'}."
                    if creds else "")
            self._findings.append(IoTFinding(
                target=host, protocol="HTTP", severity="info", port=port,
                title=f"{vendor} device web panel detected on {host}:{port}",
                description=f"Fingerprinted a {vendor} device management panel "
                            f"(server: {server or 'n/a'}).{hint} Default login was "
                            "not confirmed — manual verification recommended.",
                device_info={"vendor": vendor, "server": server,
                             "verified_login": False},
                confidence=0.5, cwe="CWE-1188",
                remediation=f"Ensure the {vendor} panel does not use default or weak "
                            "credentials and is not internet-exposed.",
            ))

    async def _try_default_login(self, base: str, user: str, pwd: str) -> bool:
        """Attempt one HTTP Basic auth request with the default credential.

        This is only called after the panel answered the unauthenticated request
        with a 401 Basic challenge, so a response that is no longer a 401 (a 2xx,
        or a redirect into the panel) means the credential cleared the challenge.
        A repeated 401/403 means the credential was rejected."""
        try:
            import aiohttp
        except ImportError:
            return False
        import base64
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        base, ssl=False, allow_redirects=False,
                        headers={"Authorization": f"Basic {token}"},
                        timeout=aiohttp.ClientTimeout(total=self._timeout)) as resp:
                    # Challenge cleared: no longer unauthorized/forbidden and the
                    # server did not re-issue a WWW-Authenticate challenge.
                    return (resp.status in (200, 301, 302, 303)
                            and "www-authenticate" not in resp.headers)
        except Exception:  # noqa: BLE001
            return False

    def summary(self) -> dict:
        return _summary(self._findings)


# ── OT / ICS scanner ──────────────────────────────────────────────────────
class OTScanner:
    """Operational-technology / ICS scanner (industrial protocols, read-only)."""

    def __init__(self, timeout: float = 6.0):
        self._timeout = timeout
        self._findings: list[IoTFinding] = []

    async def scan_host(self, host: str) -> list[IoTFinding]:
        host = _host_of(host)
        self._findings = []
        logger.info(f"OT/ICS scanning {host}...")

        open_tcp = await self._open_tcp(host, list(OT_TCP_PORTS))
        probers = {
            502: ("Modbus TCP", probe_modbus, "critical"),
            102: ("Siemens S7comm", probe_s7comm, "high"),
            20000: ("DNP3", probe_dnp3, "high"),
            2404: ("IEC 60870-5-104", probe_iec104, "high"),
            4840: ("OPC-UA", probe_opcua, "medium"),
        }
        for port in open_tcp:
            if port in probers:
                name, fn, sev = probers[port]
                await self._ics(host, port, name, fn, sev)

        # EtherNet/IP + BACnet over UDP (probe = discovery)
        await self._enip(host)
        await self._bacnet(host)

        logger.info(f"OT scan complete for {host}: {len(self._findings)} findings")
        return self._findings

    async def _open_tcp(self, host: str, ports: list[int]) -> list[int]:
        sem = asyncio.Semaphore(50)

        async def check(p: int) -> Optional[int]:
            async with sem:
                return p if await _tcp_open(host, p, self._timeout) else None

        return [p for p in await asyncio.gather(*[check(p) for p in ports]) if p]

    async def _ics(self, host: str, port: int, name: str, probe, severity: str) -> None:
        ev = await probe(host, port, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol=name, severity=severity, port=port,
                title=f"{name} ICS service reachable on {host}:{port}",
                description=f"A protocol-correct {name} handshake succeeded against "
                            f"{host}:{port}. Industrial control protocols are typically "
                            "unauthenticated and must not be reachable from untrusted "
                            "networks.",
                device_info=ev, confidence=0.9, cwe="CWE-306",
                remediation="Isolate OT from IT/Internet (segmentation, data diode / "
                            "unidirectional gateway); restrict to engineering hosts.",
            ))
        else:
            # Open ICS port but the handshake did not confirm — honest info finding.
            self._findings.append(IoTFinding(
                target=host, protocol=name, severity="info", port=port,
                title=f"Port {port} open on {host} ({name} default port)",
                description=f"TCP {port} is open (the default {name} port) but the "
                            f"{name} handshake did not confirm the protocol. Manual "
                            "verification recommended.",
                device_info={"protocol_confirmed": False}, confidence=0.4, cwe="",
                remediation=f"Confirm whether {name} is running and whether it should "
                            "be reachable from this network.",
            ))

    async def _enip(self, host: str) -> None:
        ev = await probe_enip(host, 44818, self._timeout)
        if ev:
            name = ev.get("product_name", "")
            self._findings.append(IoTFinding(
                target=host, protocol="EtherNet/IP", severity="high", port=44818,
                title=f"EtherNet/IP device identity disclosed on {host}:44818",
                description="An EtherNet/IP ListIdentity request returned device "
                            f"identity{f' ({name})' if name else ''} without "
                            "authentication.",
                device_info=ev, confidence=0.9, cwe="CWE-306",
                remediation="Segment the ICS network; restrict EtherNet/IP to trusted "
                            "engineering stations.",
            ))

    async def _bacnet(self, host: str) -> None:
        ev = await probe_bacnet(host, 47808, self._timeout)
        if ev:
            self._findings.append(IoTFinding(
                target=host, protocol="BACnet", severity="medium", port=47808,
                title=f"BACnet/IP controller responds to Who-Is on {host}:47808",
                description="A BACnet controller answered an unauthenticated Who-Is.",
                device_info=ev, confidence=0.85, cwe="CWE-306",
                remediation="Segment the BACnet network; adopt BACnet/SC.",
            ))

    def summary(self) -> dict:
        return _summary(self._findings)


def _summary(findings: list[IoTFinding]) -> dict:
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {
        "total_findings": len(findings),
        "severity": sev,
        "protocols": sorted({f.protocol for f in findings}),
        "findings": [f.to_dict() for f in findings],
    }


# ── orchestrator entry points ─────────────────────────────────────────────
async def scan_iot_targets(targets: Optional[list[str]] = None, **kwargs) -> dict:
    """Entry point for the IOT scan mode (consumer / building automation)."""
    hosts = targets or kwargs.get("iot_targets", [])
    if not hosts:
        return {"skipped": True, "reason": "No IoT targets specified"}
    scanner = IoTScanner()
    all_findings: list[dict] = []
    for host in hosts:
        for f in await scanner.scan_host(host):
            all_findings.append(f.to_dict())
    return {"total": len(all_findings), "findings": all_findings}


async def scan_ot_targets(targets: Optional[list[str]] = None, **kwargs) -> dict:
    """Entry point for the OT scan mode (ICS / SCADA industrial protocols)."""
    hosts = targets or kwargs.get("ot_targets", [])
    if not hosts:
        return {"skipped": True, "reason": "No OT targets specified"}
    scanner = OTScanner()
    all_findings: list[dict] = []
    for host in hosts:
        for f in await scanner.scan_host(host):
            all_findings.append(f.to_dict())
    return {"total": len(all_findings), "findings": all_findings}
