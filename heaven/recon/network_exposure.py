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
* **World-exported NFS shares** — a read-only ``showmount -e`` style RPC dump.
  A filesystem exported to ``*`` is a direct access-control failure.
* **Default / weak service credentials, proven by an authenticated handshake** —
  Tomcat Manager (WAR-deploy RCE), PostgreSQL (DB takeover), and VNC (no-auth or
  default-password desktop takeover). Each tries only a tiny list of well-known
  vendor defaults, stops at the first hit, reports only a credential that
  actually authenticated, and tears the session down immediately.

Severity discipline: an exposure detected from the port/service alone is rated
by the protocol's inherent risk and marked as detected; the active checks (SNMP
default community, IPMI RAKP, anonymous FTP, RDP-NLA, NFS export dump, and the
Tomcat / PostgreSQL / VNC default-credential probes) are only raised once
*proven* by a live, attacker-favourable response.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import struct
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

# ── Directly-exposed database services ───────────────────────────────────────
# A database reachable from an untrusted network is a serious exposure (data
# theft, and several engines ship with NO authentication by default). Keyed by
# canonical port; service_names matches when the DB runs on a non-standard port.
_DATABASE_PORTS: dict[int, tuple[str, tuple[str, ...]]] = {
    3306:  ("MySQL / MariaDB", ("mysql", "mariadb")),
    5432:  ("PostgreSQL", ("postgresql", "postgres")),
    1433:  ("Microsoft SQL Server", ("ms-sql", "mssql", "ms-sql-s")),
    1521:  ("Oracle Database", ("oracle", "oracle-tns")),
    27017: ("MongoDB", ("mongodb", "mongod")),
    6379:  ("Redis", ("redis",)),
    9200:  ("Elasticsearch", ("elasticsearch",)),
    5984:  ("CouchDB", ("couchdb",)),
    11211: ("Memcached", ("memcached", "memcache")),
    9042:  ("Apache Cassandra", ("cassandra",)),
}
# Engines that historically bind with no authentication by default → exposure is
# especially dangerous (direct unauthenticated read/write to all data).
_NOAUTH_DEFAULT_DB = frozenset({6379, 27017, 9200, 5984, 11211, 9042})


# ── Backdoor shells & remote-code-execution-by-design services ───────────────
# Unlike the database block, these fire on public AND internal hosts: a bind
# shell is an unauthenticated backdoor, and dRuby / Java RMI invoke
# attacker-supplied code by design wherever they are reachable. Every match is
# driven by the service label or the banner the scanner already captured, never
# a bare port number, so an unrelated service on the same port cannot trip them.
_BACKDOOR_SHELL_TOKENS = ("bindshell", "backdoor", "root shell")
# Strong, low-false-positive signals that a listener is handing out a shell with
# no authentication: an advertised shell/backdoor, a leaked root uid, or a live
# root shell prompt. Deliberately NOT a bare "#" or "/bin/sh" — those appear in
# too many benign banners (paths, help text).
_SHELL_BANNER_RE = re.compile(
    r"(root\s*shell|bind\s*shell|back\s*door|uid=0\(root\)|"
    r"\broot@[\w.-]+:[^\s]*[#$])",
    re.I)


def _dangerous_service_findings(ip: str, host: dict) -> list[dict]:
    """Flag unauthenticated backdoor shells and RCE-by-design services from the
    per-port banner/service the scanner captured. Backdoors are dangerous on any
    network, so — unlike ``database_exposed`` — these are not gated on a public
    host."""
    out: list[dict] = []
    for p in host.get("open_ports", []):
        try:
            port = int(p.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not port:
            continue
        svc = (p.get("service") or "").lower()
        product = p.get("product") or ""
        banner = p.get("banner") or ""
        hay = f"{svc} {product} {banner}".lower()

        # 1) Unauthenticated bind / backdoor shell (e.g. Metasploitable's 1524
        #    "root shell"). The banner or nmap label literally advertises a shell.
        if (any(t in hay for t in _BACKDOOR_SHELL_TOKENS)
                or _SHELL_BANNER_RE.search(f"{product} {banner}")):
            f = _finding(
                f"{ip}:{port}", "backdoor_shell", "critical",
                f"Unauthenticated Backdoor Shell (port {port})",
                "This port answers with an interactive command shell and no "
                "authentication, giving any client on the network direct command "
                "execution (typically as root). It is a bind shell / backdoor — "
                "treat the host as fully compromised: remove the listener and "
                "rebuild from a known-good image.",
                confidence=0.9,
                evidence={"port": port, "service": svc, "banner": banner[:200]})
            f["typical_cvss"] = 10.0
            out.append(f)
            continue

        # 2) Distributed Ruby (dRuby / DRb) — deserialises and invokes methods on
        #    remote objects with no auth, so an exposed endpoint is RCE by design.
        if svc in ("drb", "druby") or "druby" in hay or " drb " in f" {hay} ":
            f = _finding(
                f"{ip}:{port}", "dangerous_service_exposed", "critical",
                f"Distributed Ruby (dRuby) Exposed (port {port})",
                "A dRuby (DRb) endpoint is reachable. dRuby invokes methods on "
                "remote objects with no authentication, so an exposed endpoint is "
                "remote code execution by design (msf drb_remote_codeexec). Bind "
                "it to localhost or require an authenticated transport.",
                confidence=0.85,
                evidence={"port": port, "service": svc, "banner": banner[:200]})
            f["typical_cvss"] = 9.8
            out.append(f)
            continue

        # 3) Java RMI registry — a well-known RCE surface: default configurations
        #    permit remote class loading, and object endpoints are frequently
        #    vulnerable to deserialization attacks (ysoserial, BaRMIe).
        if (svc in ("java-rmi", "rmiregistry", "rmi")
                or "rmiregistry" in hay or "java rmi" in hay):
            f = _finding(
                f"{ip}:{port}", "dangerous_service_exposed", "high",
                f"Java RMI Registry Exposed (port {port})",
                "A Java RMI registry is reachable. An exposed registry is a "
                "well-known remote-code-execution surface: default configurations "
                "allow remote class loading and object endpoints are frequently "
                "vulnerable to deserialization (ysoserial, BaRMIe). Restrict it to "
                "a management network and disable remote class loading.",
                confidence=0.65,
                evidence={"port": port, "service": svc, "banner": banner[:200]})
            f["typical_cvss"] = 8.1
            out.append(f)
    return out


def _is_public_host(host: str) -> bool:
    """True when *host* is a public / routable address (or a hostname, assumed
    internet-facing). Private, loopback, link-local and reserved IPs return False
    so internal-range (/24) scans don't raise "exposed to untrusted network"
    database findings — internal DB reachability is expected, not a finding."""
    import ipaddress
    h = (host or "").split("%", 1)[0].strip()
    try:
        return ipaddress.ip_address(h).is_global
    except ValueError:
        return bool(h)  # a hostname target — treat as internet-facing


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


# ── Active default-/weak-credential checks (authorized, bounded) ─────────────
# These complete an authentication handshake to *prove* a service accepts a
# vendor-default or trivially-guessable credential — the same class of check as
# the SNMP default-community and IPMI RAKP probes above, and the reason the
# scanner exists (an authorized assessment). They are deliberately NOT
# brute-force: each list is a handful of well-known defaults an unauthenticated
# attacker would try first, every probe stops at the first hit, and only a
# credential that actually authenticated is ever reported. On success the
# session is torn down immediately — no command is run, no object deployed, no
# framebuffer read. All are gated on ``active_probes`` so a stealthy profile
# skips them.
_TOMCAT_MANAGER_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("admin", "admin"),
    ("admin", ""), ("role1", "role1"), ("both", "tomcat"),
    ("manager", "manager"), ("tomcat", "manager"),
)
_POSTGRES_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("postgres", "postgres"), ("postgres", ""), ("postgres", "password"),
    ("postgres", "admin"),
)
_VNC_DEFAULT_PASSWORDS: tuple[str, ...] = ("password", "", "root", "admin", "vnc")

# NFS group tokens that mean "any host on the network" — an export shared this
# widely is world-accessible.
_NFS_WORLD_TOKENS = frozenset({"*", "", "(everyone)", "0.0.0.0/0", "::/0"})
# Sensitive export roots that make a world-accessible NFS share critical rather
# than merely high (full-filesystem / home / credential-bearing paths). "/" is
# handled separately as an exact match so it doesn't prefix-match every path.
_NFS_SENSITIVE_ROOTS = ("/root", "/home", "/etc", "/var", "/srv", "/export", "/usr")


def _nfs_path_is_sensitive(path: str) -> bool:
    """True for the whole filesystem ("/") or a credential-bearing system root,
    matched on path boundaries so "/homework" does not match "/home"."""
    if path == "/":
        return True
    return any(path == r or path.startswith(r + "/") for r in _NFS_SENSITIVE_ROOTS)


# ── NFS export enumeration (read-only RPC MOUNT dump; `showmount -e`) ─────────
# AUTH_NULL cred {flavor 0, length 0} = 8 bytes, plus AUTH_NULL verf = 16 total.
_AUTH_NULL = b"\x00" * 16


def _xdr_pack(data: bytes) -> bytes:
    """Encode one XDR variable-length opaque (4-byte length + 4-byte-padded body)."""
    return struct.pack(">I", len(data)) + data + b"\x00" * ((4 - len(data) % 4) % 4)


def _auth_unix(uid: int = 0, gid: int = 0, machine: bytes = b"heaven") -> bytes:
    """AUTH_UNIX (AUTH_SYS) credential + AUTH_NULL verifier. NFS MOUNT and ACCESS
    reject AUTH_NULL; uid/gid 0 means a server with root_squash maps us to its
    anonymous user, so the probe reflects the rights an unauthenticated client is
    actually granted rather than assuming any privilege."""
    body = (struct.pack(">I", 0)                    # stamp
            + _xdr_pack(machine)                    # machinename
            + struct.pack(">III", uid, gid, 0))     # uid, gid, 0 auxiliary gids
    cred = struct.pack(">II", 1, len(body)) + body  # AUTH_UNIX (flavor 1) + opaque
    return cred + struct.pack(">II", 0, 0)          # + AUTH_NULL verifier


def _rpc_record(prog: int, vers: int, proc: int, args: bytes = b"",
                cred: bytes = _AUTH_NULL) -> bytes:
    """Build one ONC-RPC (RFC 1057) CALL, record-marked for TCP. ``cred`` is the
    full credential+verifier blob — AUTH_NULL by default, AUTH_UNIX for the
    MOUNT/NFS calls that demand a real identity."""
    xid = int.from_bytes(os.urandom(4), "big")
    body = struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc) + cred + args
    return struct.pack(">I", 0x80000000 | len(body)) + body


def _rpc_reply_results(payload: bytes) -> Optional[bytes]:
    """Return the results bytes of an *accepted* RPC reply, or None on any
    reject / non-success status (so a wrong-program reply never looks like data)."""
    if len(payload) < 12:
        return None
    _xid, mtype, rstat = struct.unpack(">III", payload[:12])
    if mtype != 1 or rstat != 0:                            # REPLY / MSG_ACCEPTED
        return None
    off = 12
    _vf, vl = struct.unpack(">II", payload[off:off + 8])
    off += 8 + vl                                           # skip verifier
    if off + 4 > len(payload):
        return None
    astat = struct.unpack(">I", payload[off:off + 4])[0]
    off += 4
    return payload[off:] if astat == 0 else None            # SUCCESS


def _xdr_string(data: bytes, off: int) -> tuple[str, int]:
    """Read one XDR variable-length opaque string (4-byte length + padded body)."""
    ln = struct.unpack(">I", data[off:off + 4])[0]
    off += 4
    val = data[off:off + ln]
    off += ln + ((4 - ln % 4) % 4)                          # 4-byte alignment pad
    return val.decode("latin-1", "replace"), off


async def _rpc_call(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    prog: int, vers: int, proc: int, args: bytes,
                    timeout: float, cred: bytes = _AUTH_NULL) -> Optional[bytes]:
    """Send one RPC CALL over an open TCP stream and return the accepted results,
    reassembling record fragments. None on any transport/parse failure."""
    writer.write(_rpc_record(prog, vers, proc, args, cred))
    await writer.drain()
    payload = b""
    while True:
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout)
        frag = struct.unpack(">I", hdr)[0]
        payload += await asyncio.wait_for(reader.readexactly(frag & 0x7FFFFFFF),
                                          timeout)
        if frag & 0x80000000:                               # last-fragment flag
            break
    return _rpc_reply_results(payload)


async def _nfs_exports(host: str, port: int = 111,
                       timeout: float = 5.0) -> Optional[list[tuple[str, list[str]]]]:
    """Read-only NFS export enumeration, the wire equivalent of ``showmount -e``.

    Asks the portmapper (rpcbind, TCP 111) for the mountd port, then issues a
    single MOUNTPROC_EXPORT (procedure 5) call and parses the export list. This
    is exactly the dump any unauthenticated client can request — nothing is
    mounted and nothing is written. Returns a list of ``(dirpath, [allowed])``
    tuples (``allowed`` is the host/netgroup list the path is shared with), or
    None if the host is not a reachable NFS/mountd server."""
    _MOUNTD = 100005
    reader = writer = None
    mport = 0
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        # portmap GETPORT (prog 100000, vers 2, proc 3) for mountd over TCP(6).
        res = await _rpc_call(reader, writer, 100000, 2, 3,
                              struct.pack(">IIII", _MOUNTD, 1, 6, 0), timeout)
        if res and len(res) >= 4:
            mport = struct.unpack(">I", res[:4])[0]
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
    if not mport:
        return None

    # MOUNTPROC_EXPORT (proc 5) on a fresh connection per version — a version the
    # daemon does not speak answers with PROG_MISMATCH and may drop the socket,
    # so we never reuse a connection across attempts.
    res = None
    for vers in (1, 3, 2):                                  # v1 is the most widely supported
        mreader = mwriter = None
        try:
            mreader, mwriter = await asyncio.wait_for(
                asyncio.open_connection(host, mport), timeout)
            res = await _rpc_call(mreader, mwriter, _MOUNTD, vers, 5, b"", timeout)
        except Exception:
            res = None
        finally:
            if mwriter is not None:
                with contextlib.suppress(Exception):
                    mwriter.close()
        if res is not None:
            break
    if res is None:
        return None
    try:
        exports: list[tuple[str, list[str]]] = []
        off = 0
        while off + 4 <= len(res):
            if struct.unpack(">I", res[off:off + 4])[0] == 0:   # exportnode: no more
                break
            off += 4
            dirpath, off = _xdr_string(res, off)
            groups: list[str] = []
            while off + 4 <= len(res):
                if struct.unpack(">I", res[off:off + 4])[0] == 0:  # group: no more
                    off += 4
                    break
                off += 4
                gname, off = _xdr_string(res, off)
                groups.append(gname)
            exports.append((dirpath, groups))
        return exports
    except Exception:
        return None


# ── NFS anonymous write-access probe (read-only NFSv3 ACCESS) ────────────────
# MOUNTPROC_EXPORT reveals that a share is world-exported but not whether it is
# read-only or read-write — that lives in the server's /etc/exports. NFSv3's
# ACCESS procedure closes the gap without touching data: it returns the rights
# the server *would* grant. We mount the export for a file handle (MOUNT MNT),
# issue one ACCESS call, then unmount (UMNT) to clear our rmtab entry. Nothing is
# created, written or deleted. NFS `secure` exports (the default) only honour
# requests from a privileged (<1024) source port, so we source from one; when we
# cannot (unprivileged and the OS forbids it) the probe reports "undetermined"
# and the finding keeps its honest read-write caveat.
_NFS_ACCESS_MODIFY = 0x04
_NFS_ACCESS_EXTEND = 0x08


async def _rpc_getport(host: str, prog: int, vers: int, proto: int,
                       timeout: float) -> int:
    """portmap GETPORT — resolve the TCP(6)/UDP(17) port of an RPC program, or 0."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 111), timeout)
        res = await _rpc_call(reader, writer, 100000, 2, 3,
                              struct.pack(">IIII", prog, vers, proto, 0), timeout)
        if res and len(res) >= 4:
            return struct.unpack(">I", res[:4])[0]
    except Exception:
        return 0
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
    return 0


async def _open_reserved(host: str, port: int, timeout: float):
    """Open a TCP stream from a privileged (<1024) source port, which NFS
    `secure` exports require. Raises PermissionError when the OS forbids it (we
    are unprivileged), so the caller can degrade to an honest "undetermined"."""
    last: Optional[BaseException] = None
    for src in range(1023, 600, -1):
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, local_addr=("0.0.0.0", src)),
                timeout)
        except PermissionError:
            raise
        except OSError as exc:                              # source port in use
            last = exc
            continue
    raise last or OSError("no free reserved source port")


async def _nfs_mnt(host: str, mount_port: int, dirpath: str,
                   timeout: float) -> Optional[bytes]:
    """MOUNT MNT (v3) — return the NFS file handle for an export, or None."""
    reader = writer = None
    try:
        reader, writer = await _open_reserved(host, mount_port, timeout)
        res = await _rpc_call(reader, writer, 100005, 3, 1,
                              _xdr_pack(dirpath.encode("latin-1")), timeout,
                              cred=_auth_unix())
        if not res or len(res) < 8 or struct.unpack(">I", res[:4])[0] != 0:
            return None                                     # mountstat3 != MNT3_OK
        fhlen = struct.unpack(">I", res[4:8])[0]
        if fhlen == 0 or 8 + fhlen > len(res):
            return None
        return res[8:8 + fhlen]
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


async def _nfs_umnt(host: str, mount_port: int, dirpath: str,
                    timeout: float) -> None:
    """MOUNT UMNT (v3) — best-effort removal of our rmtab entry after MNT."""
    reader = writer = None
    try:
        reader, writer = await _open_reserved(host, mount_port, timeout)
        await _rpc_call(reader, writer, 100005, 3, 3,
                        _xdr_pack(dirpath.encode("latin-1")), timeout,
                        cred=_auth_unix())
    except Exception:
        return
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


async def _nfs_access_mode(host: str, nfs_port: int, fh: bytes,
                           timeout: float) -> Optional[str]:
    """One NFSv3 ACCESS call for a file handle. Returns "read-write" when the
    server grants MODIFY/EXTEND, "read-only" otherwise, or None. Performs no I/O."""
    reader = writer = None
    try:
        reader, writer = await _open_reserved(host, nfs_port, timeout)
        args = _xdr_pack(fh) + struct.pack(">I", 0x3F)      # request all six bits
        res = await _rpc_call(reader, writer, 100003, 3, 4, args, timeout,
                              cred=_auth_unix())
        if not res or len(res) < 8 or struct.unpack(">I", res[:4])[0] != 0:
            return None                                     # nfsstat3 != NFS3_OK
        off = 4
        if struct.unpack(">I", res[off:off + 4])[0] == 1:   # post_op_attr present
            off += 4 + 84                                   # attrs_follow + fattr3
        else:
            off += 4
        if off + 4 > len(res):
            return None
        granted = struct.unpack(">I", res[off:off + 4])[0]
        return ("read-write"
                if granted & (_NFS_ACCESS_MODIFY | _NFS_ACCESS_EXTEND)
                else "read-only")
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


async def _nfs_world_write_check(host: str, dirpath: str,
                                 timeout: float = 5.0) -> Optional[str]:
    """Determine, read-only, whether an anonymous client is granted write access
    to a world-exported NFS share. Resolves the mount/NFS ports, mounts the
    export for a file handle, issues one NFSv3 ACCESS query (which reports the
    rights the server would grant without performing any I/O), and unmounts.
    Returns "read-write", "read-only", or None when it cannot be determined."""
    mport = await _rpc_getport(host, 100005, 3, 6, timeout)
    if not mport:
        return None
    nport = await _rpc_getport(host, 100003, 3, 6, timeout) or 2049
    fh = await _nfs_mnt(host, mport, dirpath, timeout)
    if fh is None:
        return None
    try:
        return await _nfs_access_mode(host, nport, fh, timeout)
    finally:
        await _nfs_umnt(host, mport, dirpath, timeout)


# ── Tomcat Manager default-credential check (read-only) ──────────────────────
async def _tomcat_manager_default_creds(host: str, port: int,
                                        timeout: float = 6.0) -> Optional[dict]:
    """Try a small set of well-known Tomcat defaults against ``/manager/html``.

    Confirms first that the endpoint exists and demands HTTP Basic auth (a 401
    with a Basic challenge); a wrong password then also yields 401, so a 200 in
    response to a default pair is proof the credential authenticated. Only GETs
    ``/manager/html`` — nothing is deployed, undeployed, started or stopped.
    Returns the working credential + evidence, or None."""
    try:
        import aiohttp
    except ImportError:
        return None
    scheme = "https" if port in (8443, 443) else "http"
    url = f"{scheme}://{host}:{port}/manager/html"
    to = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(
                timeout=to, connector=aiohttp.TCPConnector(ssl=False)) as session:
            try:
                async with session.get(url) as r0:
                    challenge = (r0.headers.get("WWW-Authenticate", "") or "").lower()
                    if r0.status != 401 or "basic" not in challenge:
                        return None            # not a Basic-protected Manager here
            except aiohttp.ClientError:
                return None
            for user, pwd in _TOMCAT_MANAGER_DEFAULT_CREDS:
                try:
                    async with session.get(
                            url, auth=aiohttp.BasicAuth(user, pwd)) as r:
                        if r.status != 200:
                            continue
                        body = (await r.text())[:8000]
                except (aiohttp.ClientError, UnicodeError):
                    continue
                low = body.lower()
                ui = any(m in low for m in (
                    "tomcat web application manager", "application manager",
                    "/manager/html", "list of applications", "war file to deploy",
                    "server information"))
                return {"username": user, "password_used": pwd, "url": url,
                        "status": 200, "manager_ui_confirmed": ui}
    except Exception:
        return None
    return None


# ── PostgreSQL default-credential check (read-only) ──────────────────────────
async def _postgres_default_creds(host: str, port: int = 5432,
                                  timeout: float = 6.0) -> Optional[dict]:
    """Try a small set of PostgreSQL defaults. A completed startup/auth handshake
    proves the credential; the connection is closed immediately with no query
    run. ``ssl=False`` is required for legacy servers that reject a modern TLS
    ``ClientHello``. Returns the working credential + server version, or None."""
    try:
        import asyncpg
    except ImportError:
        return None
    for user, pwd in _POSTGRES_DEFAULT_CREDS:
        creds_valid_db_unknown = False
        for db in ("template1", "postgres", user):
            try:
                conn = await asyncio.wait_for(
                    asyncpg.connect(host=host, port=port, user=user, password=pwd,
                                    database=db, ssl=False, timeout=timeout),
                    timeout=timeout + 2)
            except asyncpg.InvalidPasswordError:
                break                          # wrong password for this user
            except asyncpg.InvalidCatalogNameError:
                creds_valid_db_unknown = True  # password ACCEPTED, db just absent
                continue
            except Exception:
                break                          # transport/auth-method issue → give up pair
            else:
                try:
                    ver = conn.get_server_version()
                    server = f"{ver.major}.{ver.minor}.{ver.micro}"
                finally:
                    with contextlib.suppress(Exception):
                        await conn.close()
                return {"username": user, "password_used": pwd,
                        "database": db, "server_version": server}
        if creds_valid_db_unknown:
            return {"username": user, "password_used": pwd,
                    "database": "(accepted; no default database opened)",
                    "server_version": ""}
    return None


# ── VNC weak-/no-authentication check (read-only RFB handshake) ──────────────
def _vnc_des_response(password: str, challenge: bytes) -> bytes:
    """RFB "VNC Authentication" response: DES-ECB-encrypt the 16-byte challenge
    with the password as key, applying VNC's per-byte bit-reversal quirk. Uses a
    24-byte triple-DES key with K1=K2=K3 (identical to single DES) to avoid the
    deprecated single-key-DES path."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # older cryptography still exposes it under primitives
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    def _rev(b: int) -> int:
        b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
        b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
        b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
        return b

    pw = password.encode("latin-1", "replace")[:8].ljust(8, b"\x00")
    key = bytes(_rev(c) for c in pw)
    # DES-ECB is mandated by the RFB protocol's VNC authentication (RFC 6143
    # §7.2.2); it is the scheme the server itself uses, not a HEAVEN cipher
    # choice, and this is a read-only auth probe, not data-at-rest encryption.
    enc = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()  # nosec B304 B305
    return enc.update(challenge) + enc.finalize()


async def _vnc_probe_once(host: str, port: int, password: Optional[str],
                          timeout: float = 6.0) -> Optional[object]:
    """One RFB handshake. With ``password=None`` it only detects the offered
    security: returns ``"none"`` (no auth), ``"vncauth"`` (password required),
    ``"other"``, or None (not RFB). With a password it completes VNC-auth and
    returns True/False for accepted/rejected (None if unreachable/not VNC-auth).
    Read-only: on success it stops right after the SecurityResult — no
    framebuffer request, no input events."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        banner = await asyncio.wait_for(reader.readexactly(12), timeout)
        if not banner.startswith(b"RFB "):
            return None
        try:
            major, minor = int(banner[4:7]), int(banner[8:11])
        except ValueError:
            major, minor = 3, 3
        ver = (major, minor) if (major, minor) <= (3, 8) else (3, 8)
        writer.write(f"RFB {ver[0]:03d}.{ver[1]:03d}\n".encode("ascii"))
        await writer.drain()

        if ver >= (3, 7):
            n = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            if n == 0:                                   # server refused (reason follows)
                return None
            types = await asyncio.wait_for(reader.readexactly(n), timeout)
            if 1 in types:
                sectype = 1
            elif 2 in types:
                sectype = 2
                writer.write(b"\x02")                    # select VNC authentication
                await writer.drain()
            else:
                return "other"
        else:                                            # RFB 3.3: server dictates the type
            sectype = struct.unpack(
                ">I", await asyncio.wait_for(reader.readexactly(4), timeout))[0]

        if sectype == 1:
            return "none"
        if sectype != 2:
            return "other"
        # VNC authentication required.
        if password is None:
            return "vncauth"
        challenge = await asyncio.wait_for(reader.readexactly(16), timeout)
        writer.write(_vnc_des_response(password, challenge))
        await writer.drain()
        result = struct.unpack(
            ">I", await asyncio.wait_for(reader.readexactly(4), timeout))[0]
        return result == 0                               # 0 = OK
    except Exception:
        return None
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


async def _vnc_weak_auth(host: str, port: int = 5900,
                         timeout: float = 6.0) -> Optional[dict]:
    """Detect a VNC server that requires no authentication, or accepts one of a
    small set of default passwords. Each password attempt reconnects (RFB auth
    is single-shot per connection). Returns an outcome dict, or None if the host
    is not a VNC/RFB server or requires a password we do not have."""
    first = await _vnc_probe_once(host, port, None, timeout)
    if first is None:
        return None
    if first == "none":
        return {"auth": "none"}
    if first != "vncauth":
        return {"auth": "other"}
    for pwd in _VNC_DEFAULT_PASSWORDS:
        ok = await _vnc_probe_once(host, port, pwd, timeout)
        if ok is True:
            return {"auth": "weak", "password_used": pwd}
    return None                                          # reachable but not weak → no finding


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
    disclosure, anonymous-FTP login, RDP-NLA negotiation, NFS export dump plus a
    read-only NFSv3 ACCESS check that reports whether an anonymous client is
    granted write access, and the Tomcat / PostgreSQL / VNC default-credential
    checks) are all strictly READ-ONLY and each fires only on a proven,
    attacker-favourable response.

    ``active_probes`` gates the non-SNMP protocol probes; when ``None`` it
    follows ``active_snmp`` so a single "active vs. passive" decision drives all
    of them.
    """
    if active_probes is None:
        active_probes = active_snmp
    hosts = net_data.get("hosts", []) if isinstance(net_data, dict) else []
    findings: list[dict] = []
    snmp_hosts: list[str] = []

    # Perimeter-defence observations (firewall / IDS-IPS / tarpit) surfaced by the
    # network scanner's adaptive pass. Informational — a firewall is good posture;
    # the value is telling the operator WHY results may be thin and how HEAVEN
    # already tried to get through it (evasion re-probe). Empty when nothing was
    # detected, so a clean scan adds no noise.
    try:
        from heaven.recon.firewall_detector import build_perimeter_findings
        findings.extend(build_perimeter_findings(net_data))
    except Exception:
        logger.debug("perimeter-finding synthesis failed", exc_info=True)

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

        # 1a) Backdoor shells & RCE-by-design services (any network — a backdoor
        #     is not "expected" internal reachability the way a database is).
        findings.extend(_dangerous_service_findings(ip, host))

        # 1b) Directly-exposed database services (public/routable hosts only).
        if _is_public_host(ip):
            for real_port, svc in pairs:
                db_spec = _DATABASE_PORTS.get(real_port)
                if not db_spec and svc:
                    for db_cand in _DATABASE_PORTS.values():
                        if svc in db_cand[1]:
                            db_spec = db_cand
                            break
                if not db_spec:
                    continue
                label = db_spec[0]
                noauth = real_port in _NOAUTH_DEFAULT_DB
                # A database reachable from an untrusted network is at least a
                # High exposure. When the engine *defaults to no authentication*
                # (Redis, Memcached, MongoDB, Elasticsearch, CouchDB, Cassandra),
                # public exposure means unauthenticated read/write of ALL data —
                # an unambiguous Critical. An auth-gated engine (MySQL/Postgres/
                # MSSQL/Oracle) stays High: a serious pre-auth attack surface
                # (credential brute-force, pre-auth CVEs) but not instant data
                # loss. The per-finding ``typical_cvss`` pins the number so
                # ``reconcile_severity`` keeps the label — a bare "critical" with
                # no score is otherwise realigned down to the class's 8.6 High band.
                if noauth:
                    sev, base_cvss = "critical", 9.8
                    extra = (" This engine binds with no authentication by default, "
                             "so exposure can mean direct, unauthenticated read/write "
                             "access to all data.")
                else:
                    sev, base_cvss = "high", 8.6
                    extra = (" Even with authentication required, a public database "
                             "port invites credential brute-forcing and pre-auth CVE "
                             "exploitation.")
                _db_f = _finding(
                    f"{ip}:{real_port}", "database_exposed", sev,
                    f"Database Exposed to Untrusted Network: {label} (port {real_port})",
                    f"A {label} service is reachable on a public/routable address. "
                    "Databases must never be directly exposed to untrusted networks — "
                    "bind to localhost or a private management network, require "
                    "authentication and TLS, and firewall the port to known "
                    f"application hosts only.{extra}",
                    confidence=0.8,
                    evidence={"port": real_port, "service": svc or label.lower(),
                              "product": label, "no_auth_by_default": noauth,
                              "public_exposure": True},
                )
                _db_f["typical_cvss"] = base_cvss
                findings.append(_db_f)

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

        # 2d) NFS — read-only export enumeration (showmount -e). A share offered
        # to "everyone" (*) is a direct access-control failure; the root/home/etc
        # filesystem exported world-wide is a classic full-host compromise path.
        nfs_present = any(
            p in (111, 2049) or s in ("rpcbind", "portmapper", "nfs", "mountd",
                                      "nfs_acl", "sunrpc")
            for p, s in pairs)
        if nfs_present and active_probes:
            exports = await _nfs_exports(ip)
            if exports:
                world = [(d, g) for d, g in exports
                         if any(tok in _NFS_WORLD_TOKENS or tok.endswith("/0")
                                for tok in g)]
                if world:
                    sensitive = any(_nfs_path_is_sensitive(d) for d, _ in world)
                    world_paths = sorted({d for d, _ in world})
                    paths = ", ".join(world_paths)
                    # Read-only NFSv3 ACCESS probe: does an anonymous client
                    # actually get write access, or only read? (No data is touched.)
                    writable: list[str] = []
                    readonly: list[str] = []
                    for d in world_paths[:5]:
                        mode = await _nfs_world_write_check(ip, d)
                        if mode == "read-write":
                            writable.append(d)
                        elif mode == "read-only":
                            readonly.append(d)
                    if writable:
                        sev, cvss, access_mode = "critical", 9.1, "read-write"
                        access_note = (
                            " A read-only NFSv3 ACCESS check confirms an anonymous "
                            f"client is granted write access to {', '.join(writable)}: "
                            "an attacker can modify the share directly, for example "
                            "planting an SSH authorized_keys or a cron job for code "
                            "execution.")
                    elif readonly:
                        sev = "high" if sensitive else "medium"
                        cvss = 7.5 if sensitive else 5.3
                        access_mode = "read-only"
                        access_note = (
                            " A read-only NFSv3 ACCESS check shows anonymous clients "
                            f"get read-only access to {', '.join(readonly)} (write "
                            "denied, most likely root_squash); the contents are still "
                            "world-readable.")
                    else:
                        sev = "critical" if sensitive else "high"
                        cvss = 9.1 if sensitive else 7.5
                        access_mode = "undetermined"
                        access_note = (
                            " Read-only versus read-write is set by the server's "
                            "/etc/exports options and is not visible on the wire; "
                            "where the export is read-write an attacker can also "
                            "modify its contents.")
                    nfs_f = _finding(
                        f"{ip}:2049", "nfs_export_exposed", sev,
                        "NFS Share Exported to the World",
                        f"The NFS server exports {paths} to any host (share list: "
                        "'*'). Any unauthenticated client on the network can mount "
                        "the share and read its contents." + access_note +
                        " Exporting the root, home or system filesystem this way is "
                        "a direct path to credential theft and full host compromise "
                        "(read SSH keys or /etc/shadow, drop an authorized_keys). "
                        "Restrict exports to specific hosts, use root_squash, and "
                        "require Kerberos (sec=krb5p) where possible.",
                        confidence=0.95,
                        evidence={"port": 2049, "world_exports": paths,
                                  "access_mode": access_mode,
                                  "writable_exports": ", ".join(writable) or None,
                                  "all_exports": {d: g for d, g in exports},
                                  "proven": True})
                    nfs_f["typical_cvss"] = cvss
                    findings.append(nfs_f)

        # 2e) Apache Tomcat Manager — read-only default-credential check. Access to
        # the Manager app means arbitrary WAR deployment, i.e. remote code execution.
        tomcat_ports = sorted({
            p for p, s in pairs
            if p in (8080, 8180, 8443, 8888)
            or any(t in s for t in ("tomcat", "coyote", "jserv"))})
        if tomcat_ports and active_probes:
            for tport in tomcat_ports:
                hit = await _tomcat_manager_default_creds(ip, tport)
                if hit:
                    tc_f = _finding(
                        f"{ip}:{tport}", "tomcat_manager_default_creds", "critical",
                        "Apache Tomcat Manager Default Credentials",
                        "The Tomcat Manager application accepted the vendor-default "
                        f"credential '{hit['username']}:{hit['password_used']}'. The "
                        "Manager app can deploy arbitrary web applications, so this "
                        "grants remote code execution on the server (upload a WAR / "
                        "JSP webshell). Change or remove the default users in "
                        "tomcat-users.xml, restrict /manager and /host-manager to "
                        "trusted hosts, and never expose the Manager to untrusted "
                        "networks.",
                        confidence=0.97,
                        evidence={"port": tport, "username": hit["username"],
                                  "password": hit["password_used"],
                                  "path": "/manager/html",
                                  "manager_ui_confirmed": hit.get("manager_ui_confirmed"),
                                  "proven": True})
                    tc_f["typical_cvss"] = 9.8
                    findings.append(tc_f)
                    break

        # 2f) PostgreSQL — read-only default-credential check. A superuser login
        # (postgres) means full data access and, on many builds, code execution.
        pg_ports = sorted({p for p, s in pairs
                           if p == 5432 or s in ("postgresql", "postgres")})
        if pg_ports and active_probes:
            for pgport in pg_ports:
                hit = await _postgres_default_creds(ip, pgport)
                if hit:
                    v = f" (server {hit['server_version']})" if hit.get("server_version") else ""
                    pg_f = _finding(
                        f"{ip}:{pgport}", "weak_db_credentials", "critical",
                        "PostgreSQL Default Credentials",
                        "The PostgreSQL server accepted the default credential "
                        f"'{hit['username']}:{hit['password_used']}'{v}. This grants "
                        "full access to the database and, for the superuser account, "
                        "frequently a path to command execution on the host (COPY ... "
                        "FROM PROGRAM, untrusted PL/language, or writing files). "
                        "Set a strong password for every role, remove default "
                        "accounts, and firewall the port to the application tier.",
                        confidence=0.97,
                        evidence={"port": pgport, "username": hit["username"],
                                  "password": hit["password_used"],
                                  "database": hit.get("database"),
                                  "server_version": hit.get("server_version"),
                                  "proven": True})
                    pg_f["typical_cvss"] = 9.8
                    findings.append(pg_f)
                    break

        # 2g) VNC — read-only remote-framebuffer auth check (no auth / default
        # password). VNC exposes the full interactive desktop, so either is a
        # complete takeover of the console session.
        vnc_ports = sorted({p for p, s in pairs
                            if 5900 <= p <= 5905 or s in ("vnc", "rfb")
                            or "vnc" in s})
        if vnc_ports and active_probes:
            for vport in vnc_ports:
                outcome = await _vnc_weak_auth(ip, vport)
                if not outcome:
                    continue
                if outcome.get("auth") == "none":
                    vt, title, desc = (
                        "vnc_no_auth",
                        "VNC Server Requires No Authentication",
                        "The VNC/RFB server offers the 'None' security type and "
                        "accepts connections with no authentication whatsoever. Any "
                        "client on the network gets full interactive control of the "
                        "console desktop.")
                    ev = {"port": vport, "auth": "none", "proven": True}
                elif outcome.get("auth") == "weak":
                    vt, title, desc = (
                        "vnc_weak_credentials",
                        "VNC Server Accepts a Default Password",
                        "The VNC/RFB server accepted the default password "
                        f"'{outcome['password_used']}'. This grants full interactive "
                        "control of the console desktop to anyone who can reach the "
                        "port.")
                    ev = {"port": vport, "auth": "weak",
                          "password": outcome["password_used"], "proven": True}
                else:
                    continue
                vnc_f = _finding(
                    f"{ip}:{vport}", vt, "critical", title,
                    desc + " Require a strong password (or, better, tunnel VNC over "
                    "SSH/VPN), restrict it to a management network, and never expose "
                    "it to untrusted networks.",
                    confidence=0.95, evidence=ev)
                vnc_f["typical_cvss"] = 9.8
                findings.append(vnc_f)
                break

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
