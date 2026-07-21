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
                                    snmp_timeout: float = 2.5) -> dict:
    """Analyse a network-recon result and return insecure-exposure findings.

    ``net_data`` is the dict produced by ``scan_network`` (``{"hosts": [...]}``).
    Every finding is derived from an actually-open port/service; the SNMP default
    community, when checked, is proven by a live read-only reply.
    """
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
            if port in ports or name_hit:
                findings.append(_finding(
                    f"{ip}:{port}", vt, sev,
                    f"{label} Management Plane Exposed (port {port})",
                    why + " Restrict it to an isolated management VLAN or disable "
                    "it entirely.",
                    confidence=0.75,
                    evidence={"port": port, "service": svc, "protocol": label},
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
