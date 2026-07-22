"""
HEAVEN — Network Service Exposure Analyzer

Turns the host / port / service inventory produced by network reconnaissance
into real security findings for network devices and hosts — routers, switches,
firewalls, servers, printers. Without this layer a scan of a Cisco router (or
any appliance) produced only an inventory and *no findings*, because the web /
auth / injection detectors only look at HTTP endpoints and the CVE mapper only
fires on a matched software version.

What it flags (all grounded in the discovered attack surface, never fabricated):

* **Cleartext / legacy management protocols** exposed — Telnet, FTP, the
  r-services (rlogin/rsh/rexec), TFTP, Finger. These transmit credentials and
  data in the clear; their mere exposure is the weakness.
* **SNMP exposure**, plus an **active, strictly READ-ONLY default-community
  probe** (an SNMP v2c GET of the public ``sysDescr.0`` MIB value with the
  vendor-default communities ``public`` / ``private``). A finding is only raised
  as *proven* when the device actually answers — the returned system descriptor
  is attached as evidence. Nothing is ever written to the device.
* **High-risk appliance management planes** — Cisco Smart Install (TCP 4786),
  IPMI/BMC (UDP 623) — which are routinely abused for remote config theft / RCE.

Severity discipline: an exposure detected from the port/service alone is rated
by the protocol's inherent risk and marked as detected; the SNMP default
community is only rated high once *proven* by a live reply.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.exposure")


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


# ── Cleartext / legacy protocols: (label, severity, why) ─────────────────────
# Keyed by well-known port. `service_names` lets us also match when nmap labelled
# the service rather than using the canonical port.
_CLEARTEXT_PORTS: dict[int, tuple[str, str, str, tuple[str, ...]]] = {
    23:  ("Telnet", "high",
          "Telnet transmits credentials and all session data in cleartext, so "
          "anyone on the path can capture administrative logins. It is the "
          "classic insecure management protocol on routers, switches and IoT.",
          ("telnet",)),
    21:  ("FTP", "medium",
          "FTP authenticates and transfers data in cleartext, exposing "
          "credentials and files to network sniffing.",
          ("ftp",)),
    513: ("rlogin", "high",
          "The BSD r-service rlogin trusts host-based authentication and sends "
          "data in cleartext — trivially sniffed or spoofed.",
          ("login", "rlogin")),
    514: ("rsh", "high",
          "The BSD r-service rsh executes remote commands over a cleartext, "
          "host-trust channel that is trivially spoofed.",
          ("shell", "rsh", "cmd")),
    512: ("rexec", "high",
          "rexec sends credentials in cleartext to run remote commands.",
          ("exec", "rexec")),
    69:  ("TFTP", "medium",
          "TFTP has no authentication and runs in cleartext; on network gear it "
          "often exposes or accepts device configuration and firmware.",
          ("tftp",)),
    79:  ("Finger", "low",
          "The Finger service discloses user and system information useful for "
          "targeting.",
          ("finger",)),
}

# ── High-risk appliance management planes ────────────────────────────────────
_MGMT_PORTS: dict[int, tuple[str, str, str, str, tuple[str, ...]]] = {
    4786: ("Cisco Smart Install", "cisco_smart_install", "high",
           "Cisco Smart Install (SMI) is reachable. SMI has no authentication "
           "and is widely abused to pull or overwrite device configuration and "
           "achieve remote code execution on Cisco IOS switches (CVE-2018-0171, "
           "SIET tooling). It should never be reachable in production.",
           ("smart-install", "cisco-smi")),
    623: ("IPMI / BMC", "ipmi_exposed", "medium",
          "An IPMI/BMC management interface is exposed. IPMI is affected by "
          "cipher-zero auth bypass and password-hash retrieval (RAKP), giving "
          "out-of-band control of the host.",
          ("ipmi", "asf-rmcp")),
}

SYS_DESCR_OID = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])  # 1.3.6.1.2.1.1.1.0
_SNMP_COMMUNITIES = ("public", "private")


# ── Minimal SNMP v2c GET (read-only) ─────────────────────────────────────────
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def _ber_int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _snmp_get_packet(community: str, request_id: int, oid: bytes) -> bytes:
    """Build a well-formed SNMP v2c GetRequest for a single scalar OID."""
    version = _ber_int(1)                       # v2c
    comm = _tlv(0x04, community.encode())
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))   # { OID, NULL }
    varbind_list = _tlv(0x30, varbind)
    pdu_body = (_ber_int(request_id) + _ber_int(0) + _ber_int(0) + varbind_list)
    pdu = _tlv(0xA0, pdu_body)                   # GetRequest-PDU
    return _tlv(0x30, version + comm + pdu)


def _extract_sysdescr(resp: bytes, oid: bytes) -> Optional[str]:
    """Best-effort: locate the sysDescr OID in the reply and read the OCTET
    STRING that follows it. Returns the decoded descriptor, or "" if the reply is
    a valid response but the value couldn't be parsed, or None if not a GetResponse."""
    if len(resp) < 2 or resp[0] != 0x30:
        return None
    if bytes([0xA2]) not in resp:               # GetResponse-PDU tag must be present
        return None
    idx = resp.find(oid)
    if idx != -1:
        j = idx + len(oid)
        if j < len(resp) and resp[j] == 0x04:   # OCTET STRING value
            ln = resp[j + 1]
            val = resp[j + 2: j + 2 + ln]
            try:
                return val.decode("utf-8", "replace").strip() or ""
            except Exception:
                return ""
    return ""                                    # answered, value unparsed


async def _snmp_probe(host: str, community: str, timeout: float = 2.5) -> Optional[str]:
    """Send one READ-ONLY SNMP v2c GET(sysDescr.0). Returns the system descriptor
    string on success (may be empty if the device answered but the value didn't
    parse), or None if there was no valid SNMP response."""
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
            _Proto, remote_addr=(host, 161)
        )
        request_id = int.from_bytes(os.urandom(3), "big")
        transport.sendto(_snmp_get_packet(community, request_id, SYS_DESCR_OID))
        data = await asyncio.wait_for(fut, timeout)
        return _extract_sysdescr(data, SYS_DESCR_OID)
    except Exception:
        # Timeout / unreachable / malformed reply → treat as "no SNMP answer".
        return None
    finally:
        if transport is not None:
            transport.close()


# ── SNMP GETBULK amplification (read-only) ───────────────────────────────────
def _snmp_getbulk_packet(community: str, request_id: int, oid: bytes,
                         max_repetitions: int = 50) -> bytes:
    """A single SNMP v2c GetBulkRequest over a broad subtree. Used only to
    *measure* the reflected-response size — nothing is written to the device."""
    version = _ber_int(1)                        # v2c
    comm = _tlv(0x04, community.encode())
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))
    varbind_list = _tlv(0x30, varbind)
    # GetBulk PDU: request-id, non-repeaters=0, max-repetitions=N
    pdu_body = (_ber_int(request_id) + _ber_int(0)
                + _ber_int(max_repetitions) + varbind_list)
    pdu = _tlv(0xA5, pdu_body)                    # GetBulkRequest-PDU
    return _tlv(0x30, version + comm + pdu)


# 1.3.6.1.2.1 (mib-2) — walking from here returns a large table on most agents.
MIB2_OID = bytes([0x2B, 6, 1, 2, 1])


async def _snmp_getbulk_amplification(host: str, community: str,
                                      timeout: float = 2.5
                                      ) -> Optional[tuple[int, int, float]]:
    """Send one READ-ONLY GetBulk and return (request_bytes, response_bytes,
    amplification_factor), or None if the device did not answer."""
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
            _Proto, remote_addr=(host, 161))
        request_id = int.from_bytes(os.urandom(3), "big")
        pkt = _snmp_getbulk_packet(community, request_id, MIB2_OID)
        transport.sendto(pkt)
        data = await asyncio.wait_for(fut, timeout)
        if not data or data[0] != 0x30 or bytes([0xA2]) not in data:
            return None
        req_len, resp_len = len(pkt), len(data)
        factor = (resp_len / req_len) if req_len else 0.0
        return req_len, resp_len, factor
    except Exception:
        return None
    finally:
        if transport is not None:
            transport.close()


# ── FTP anonymous-login probe (read-only) ────────────────────────────────────
async def _ftp_anonymous_login(host: str, port: int = 21,
                               timeout: float = 4.0) -> Optional[bool]:
    """Attempt an anonymous FTP login (USER anonymous / PASS). Returns True if
    the server grants access (230), False if it refuses, None if unreachable.
    Strictly read-only: it authenticates and immediately QUITs — no listing,
    no upload, no download."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)

        async def _line() -> str:
            data = await asyncio.wait_for(reader.readline(), timeout)
            return data.decode("latin-1", "replace").strip()

        async def _cmd(text: str) -> str:
            writer.write((text + "\r\n").encode("latin-1"))
            await writer.drain()
            return await _line()

        greeting = await _line()
        if not greeting.startswith("220"):
            return None
        r1 = await _cmd("USER anonymous")
        # 331 = need password; 230 = logged in without one.
        if r1.startswith("230"):
            granted = True
        elif r1.startswith("331"):
            r2 = await _cmd("PASS anonymous@heaven.probe")
            granted = r2.startswith("230")
        else:
            granted = False
        with contextlib.suppress(Exception):
            await _cmd("QUIT")
        return granted
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


# ── RDP Network Level Authentication (NLA) probe (read-only) ─────────────────
def _rdp_neg_request(requested_protocols: int) -> bytes:
    """X.224 Connection Request carrying an RDP Negotiation Request."""
    # RDP Negotiation Request: type=0x01, flags=0x00, length=0x0008, protocol(LE)
    neg = bytes([0x01, 0x00, 0x08, 0x00]) + requested_protocols.to_bytes(4, "little")
    # X.224 Connection Request TPDU: LI, CR(0xE0), dst-ref(2), src-ref(2), class(1)
    # LI counts everything after itself (6-byte fixed header + the neg payload).
    x224 = bytes([6 + len(neg), 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + neg
    # TPKT header: version=3, reserved=0, total length (2 bytes, big-endian)
    total = 4 + len(x224)
    return bytes([0x03, 0x00]) + total.to_bytes(2, "big") + x224


async def _rdp_nla_not_required(host: str, port: int = 3389,
                                timeout: float = 5.0) -> Optional[bool]:
    """Probe whether the RDP server accepts *standard* RDP security (i.e. does
    NOT enforce NLA). Returns True when NLA is not required, False when the
    server demands NLA/TLS, None if it can't be determined. Read-only: it sends
    a single negotiation request and never completes a session."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        # Request PROTOCOL_RDP (0) — plain standard RDP security only.
        writer.write(_rdp_neg_request(0x00000000))
        await writer.drain()
        data = await asyncio.wait_for(reader.readexactly(4), timeout)  # TPKT header
        if len(data) < 4 or data[0] != 0x03:
            return None
        total = int.from_bytes(data[2:4], "big")
        rest = await asyncio.wait_for(reader.readexactly(max(0, total - 4)), timeout)
        # Walk to the optional RDP Negotiation structure (after the X.224 CC).
        # rest = [x224 len][0xD0 CC ...]; the neg struct (if present) is the last
        # 8 bytes: type(1) flags(1) length(2) data(4).
        if len(rest) >= 8:
            neg = rest[-8:]
            neg_type = neg[0]
            if neg_type == 0x02:            # Negotiation Response
                selected = int.from_bytes(neg[4:8], "little")
                # selectedProtocol == PROTOCOL_RDP(0) → standard security accepted.
                return selected == 0x00000000
            if neg_type == 0x03:            # Negotiation Failure
                failure = int.from_bytes(neg[4:8], "little")
                # 0x05 = HYBRID_REQUIRED_BY_SERVER → NLA enforced (secure).
                if failure in (0x00000005, 0x00000002):
                    return False
                return None
        # A bare Connection Confirm with no negotiation failure means the server
        # accepted standard RDP security → NLA not required.
        if len(rest) >= 2 and rest[1] == 0xD0:
            return True
        return None
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


# ── IPMI 2.0 RAKP password-hash disclosure probe (CVE-2013-4786, read-only) ──
def _rmcp_plus(payload_type: int, payload: bytes) -> bytes:
    """Wrap a payload in an RMCP+ (IPMI 2.0) session envelope with a null
    (pre-session) session id/sequence — the form used before authentication."""
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])           # RMCP header, class=IPMI
    auth_type = 0x06                                  # RMCP+ format
    session_id = b"\x00\x00\x00\x00"
    session_seq = b"\x00\x00\x00\x00"
    length = len(payload).to_bytes(2, "little")
    return rmcp + bytes([auth_type, payload_type]) + session_id + session_seq + length + payload


def _ipmi_open_session_request(console_sid: int) -> bytes:
    # tag, max-priv(0=highest), reserved(2), console session id(4, LE),
    # then auth/integrity/confidentiality algorithm payloads.
    body = bytes([0x00, 0x00, 0x00, 0x00]) + console_sid.to_bytes(4, "little")
    auth = bytes([0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])   # HMAC-SHA1
    integ = bytes([0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # HMAC-SHA1-96
    conf = bytes([0x02, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])   # AES-CBC-128
    return _rmcp_plus(0x10, body + auth + integ + conf)


def _ipmi_rakp1(console_sid: int, bmc_sid: bytes, username: str) -> bytes:
    tag = bytes([0x00])
    reserved = bytes([0x00, 0x00, 0x00])
    console_rand = os.urandom(16)
    # 0x14 = request Administrator (0x04) + name-only lookup (0x10).
    priv = bytes([0x14, 0x00, 0x00])
    uname = username.encode("latin-1")[:16]
    body = tag + reserved + bmc_sid + console_rand + priv + bytes([len(uname)]) + uname
    return _rmcp_plus(0x12, body)


_IPMI_USERNAMES = ("", "admin", "ADMIN", "root", "administrator")


async def _ipmi_rakp_hashdump(host: str, port: int = 623,
                              timeout: float = 3.0) -> Optional[dict]:
    """Perform the IPMI 2.0 RMCP+ Open-Session + RAKP-1 exchange. If the BMC
    returns a RAKP-2 message carrying a password-hash HMAC (CVE-2013-4786) it is
    captured as proof. Returns an evidence dict, or None if the host is not a
    RAKP-speaking IPMI 2.0 BMC. Strictly read-only — no session is established
    and the hash is never cracked here."""
    loop = asyncio.get_running_loop()

    async def _rt(pkt: bytes) -> Optional[bytes]:
        fut: asyncio.Future = loop.create_future()

        class _P(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not fut.done():
                    fut.set_exception(exc)

        tr = None
        try:
            tr, _ = await loop.create_datagram_endpoint(_P, remote_addr=(host, port))
            tr.sendto(pkt)
            return await asyncio.wait_for(fut, timeout)
        except Exception:
            return None
        finally:
            if tr is not None:
                tr.close()

    console_sid = int.from_bytes(os.urandom(4), "little")
    resp = await _rt(_ipmi_open_session_request(console_sid))
    # Open Session Response payload type is 0x11; the managed-system session id
    # sits at a fixed offset inside the RMCP+ envelope.
    if not resp or len(resp) < 24 or resp[0] != 0x06 or resp[5] != 0x11:
        return None
    # Envelope: rmcp(4) authtype(1) paytype(1) sid(4) seq(4) len(2) then payload.
    payload = resp[16:]
    # Open Session Response body: tag(1) status(1) maxpriv(1) reserved(1)
    # console_sid(4) managed_sid(4) ...
    if len(payload) < 12 or payload[1] != 0x00:      # status 0 = no errors
        return None
    bmc_sid = payload[8:12]

    for uname in _IPMI_USERNAMES:
        r2 = await _rt(_ipmi_rakp1(console_sid, bmc_sid, uname))
        if not r2 or len(r2) < 24 or r2[5] != 0x13:  # RAKP Message 2
            continue
        body = r2[16:]
        # RAKP2 body: tag(1) status(1) reserved(2) console_sid(4)
        # bmc_random(16) bmc_guid(16) key_exchange_auth_code(HMAC...)
        if len(body) < 8 or body[1] != 0x00:
            continue
        hmac_hash = body[40:] if len(body) > 40 else b""
        if hmac_hash and any(b != 0 for b in hmac_hash):
            return {
                "username": uname or "(null)",
                "hash_algorithm": "HMAC-SHA1",
                "hash_length": len(hmac_hash),
                "hash_prefix": hmac_hash[:8].hex(),
                "cve": "CVE-2013-4786",
                "rmcp_plus": True,
            }
    # RMCP+ handshake worked but no username yielded a hash → IPMI 2.0 confirmed.
    return {"rmcp_plus": True, "hash": False}


def _port_service_pairs(host: dict) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for p in host.get("open_ports", []):
        try:
            port = int(p.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0
        svc = (p.get("service") or "").lower()
        if port:
            out.append((port, svc))
    return out


async def analyze_network_exposure(net_data: dict, *, active_snmp: bool = True,
                                    active_probes: Optional[bool] = None,
                                    snmp_timeout: float = 2.5) -> dict:
    """Analyse a network-recon result and return insecure-exposure findings.

    ``net_data`` is the dict produced by ``scan_network`` (``{"hosts": [...]}``).
    Every finding is derived from an actually-open port/service; the active
    probes (SNMP default community + GETBULK amplification, IPMI RAKP hash
    disclosure, anonymous-FTP login, RDP-NLA negotiation) are all strictly
    READ-ONLY and each fires only on a proven, attacker-favourable response.

    ``active_probes`` gates the non-SNMP protocol probes; when ``None`` it
    follows ``active_snmp`` so a single "active vs. passive" decision drives all
    of them.
    """
    if active_probes is None:
        active_probes = active_snmp
    hosts = net_data.get("hosts", []) if isinstance(net_data, dict) else []
    findings: list[dict] = []
    snmp_hosts: list[str] = []

    for host in hosts:
        ip = host.get("ip") or host.get("host") or ""
        if not ip:
            continue
        pairs = _port_service_pairs(host)
        ports = {p for p, _ in pairs}

        # 1) Cleartext / legacy protocols (port OR nmap service name)
        for port, svc in pairs:
            spec = _CLEARTEXT_PORTS.get(port)
            if not spec and svc:
                # Match a non-canonical port by exact nmap service token (e.g.
                # "telnet" on an alternate port). Exact match — never substring —
                # so an unrelated service name can't trip a cleartext finding.
                for cand in _CLEARTEXT_PORTS.values():
                    if svc in cand[3]:
                        spec = cand
                        break
            if spec:
                label, sev, why, _names = spec
                findings.append(_finding(
                    f"{ip}:{port}", "cleartext_service", sev,
                    f"Cleartext Service Exposed: {label} (port {port})",
                    why + " Disable it and use an encrypted equivalent "
                    "(SSH/SFTP/HTTPS) restricted to a management network.",
                    confidence=0.85,
                    evidence={"port": port, "service": svc or label.lower(),
                              "protocol": label},
                ))

        # 2) High-risk appliance management planes
        for port, (label, vt, sev, why, names) in _MGMT_PORTS.items():
            svc = next((s for p, s in pairs if p == port), "")
            name_hit = any(s in names for _p, s in pairs if s)
            if not (port in ports or name_hit):
                continue
            # IPMI/BMC: actively (read-only) attempt the RAKP hash disclosure. A
            # returned password-hash HMAC proves CVE-2013-4786 and upgrades the
            # finding from "exposed" (medium) to a high-severity, proven hashdump.
            if port == 623 and active_probes:
                dump = await _ipmi_rakp_hashdump(ip)
                if dump and dump.get("cve"):
                    findings.append(_finding(
                        f"{ip}:623", "ipmi_hash_disclosure", "high",
                        "Unauthenticated IPMI RAKP Password-Hash Disclosure",
                        "The BMC completed the IPMI 2.0 RMCP+/RAKP exchange and "
                        f"returned a salted {dump['hash_algorithm']} hash of the "
                        f"'{dump['username']}' account's password (CVE-2013-4786). "
                        "This is a design flaw in the IPMI spec: any unauthenticated "
                        "party can retrieve the hash and crack it offline, then take "
                        "out-of-band control of the host. Isolate BMCs to a dedicated "
                        "management network and set long, random passwords.",
                        confidence=0.95,
                        evidence={"port": 623, "protocol": "IPMI 2.0 / RMCP+",
                                  **dump},
                    ))
                    continue
            findings.append(_finding(
                f"{ip}:{port}", vt, sev,
                f"{label} Management Plane Exposed (port {port})",
                why + " Restrict it to an isolated management VLAN or disable "
                "it entirely.",
                confidence=0.75,
                evidence={"port": port, "service": svc, "protocol": label},
            ))

        # 2b) FTP — active, read-only anonymous-login test. An accepted anonymous
        # login is a concrete access-control failure, not just cleartext exposure.
        ftp_ports = [p for p, s in pairs if p == 21 or s == "ftp"]
        if ftp_ports and active_probes:
            fport = ftp_ports[0]
            granted = await _ftp_anonymous_login(ip, fport)
            if granted:
                findings.append(_finding(
                    f"{ip}:{fport}", "ftp_anonymous", "medium",
                    "Anonymous FTP Login Allowed",
                    "The FTP service accepted an anonymous login (USER anonymous). "
                    "Anonymous access exposes whatever the FTP root serves to any "
                    "unauthenticated user and, where writable, offers a foothold to "
                    "stage files. Disable anonymous access unless it is a deliberate "
                    "public-download service, and never expose it with write access.",
                    confidence=0.95,
                    evidence={"port": fport, "anonymous_login": True,
                              "proven": True},
                ))

        # 2c) RDP — read-only NLA negotiation probe. A server that accepts standard
        # RDP security is not enforcing Network Level Authentication, exposing it to
        # pre-auth MiTM and reducing brute-force cost.
        rdp_ports = [p for p, s in pairs if p == 3389 or "ms-wbt" in s or s == "rdp"]
        if rdp_ports and active_probes:
            rport = rdp_ports[0]
            no_nla = await _rdp_nla_not_required(ip, rport)
            if no_nla is True:
                findings.append(_finding(
                    f"{ip}:{rport}", "rdp_nla_disabled", "medium",
                    "RDP Network Level Authentication (NLA) Not Required",
                    "The Remote Desktop service accepted standard RDP security "
                    "without requiring Network Level Authentication. Without NLA, "
                    "authentication happens after a full session is set up, exposing "
                    "the host to pre-authentication man-in-the-middle attacks and "
                    "lowering the cost of credential brute-forcing. Require NLA "
                    "(CredSSP) via Group Policy / System Properties.",
                    confidence=0.85,
                    evidence={"port": rport, "nla_required": False, "proven": True},
                ))

        # 3) SNMP — exposure + active read-only default-community probe
        snmp_ports = [p for p, s in pairs if p in (161,) or "snmp" in s]
        if snmp_ports:
            snmp_hosts.append(ip)
            proven = None
            if active_snmp:
                for community in _SNMP_COMMUNITIES:
                    descr = await _snmp_probe(ip, community, timeout=snmp_timeout)
                    if descr is not None:
                        proven = (community, descr)
                        break
            if proven:
                community, descr = proven
                findings.append(_finding(
                    f"{ip}:161", "snmp_default_community", "high",
                    f"SNMP Default Community String Accepted ('{community}')",
                    "The device answered an SNMP query authenticated with the "
                    f"vendor-default community '{community}'. SNMP read access "
                    "discloses the full device configuration, interfaces, ARP/"
                    "routing tables and running software; with write access it "
                    "allows reconfiguration. This was proven with a read-only "
                    "GET of sysDescr.0.",
                    confidence=0.98,
                    evidence={"port": 161, "community": community,
                              "sys_descr": (descr or "(no descriptor returned)")[:400],
                              "proven": True},
                ))
                # With a working community, measure the GETBULK amplification the
                # device offers — a large reflected response makes it a usable
                # SNMP reflection/amplification DDoS source. Read-only measurement.
                amp = await _snmp_getbulk_amplification(ip, community,
                                                        timeout=snmp_timeout)
                if amp and amp[2] >= 5.0:
                    req_b, resp_b, factor = amp
                    findings.append(_finding(
                        f"{ip}:161", "snmp_amplification", "medium",
                        f"SNMP GETBULK Amplification (~{factor:.1f}x)",
                        "The SNMP agent answered a small GETBULK request with a far "
                        f"larger response (~{factor:.1f}x, {req_b}->{resp_b} bytes). "
                        "Because SNMP is UDP and source addresses can be spoofed, an "
                        "attacker can abuse this host as a reflector to amplify a "
                        "denial-of-service attack against a third party. Restrict "
                        "SNMP to a management network and rate-limit/disable it.",
                        confidence=0.9,
                        evidence={"port": 161, "request_bytes": req_b,
                                  "response_bytes": resp_b,
                                  "amplification_factor": round(factor, 2),
                                  "proven": True},
                    ))
            else:
                findings.append(_finding(
                    f"{ip}:161", "snmp_exposed", "medium",
                    "SNMP Service Exposed",
                    "An SNMP service is reachable. Even without a default "
                    "community, exposed SNMP is a reconnaissance and brute-force "
                    "target and often leaks device information. Restrict it to a "
                    "management network and require SNMPv3 with authPriv.",
                    confidence=0.7,
                    evidence={"port": 161, "probed_default_community": active_snmp,
                              "proven": False},
                ))

    logger.info(
        f"Network exposure analysis: {len(findings)} finding(s) across "
        f"{len(hosts)} host(s); {len(snmp_hosts)} SNMP host(s) probed"
    )
    return {"findings": findings, "hosts_analyzed": len(hosts),
            "snmp_hosts": snmp_hosts}
