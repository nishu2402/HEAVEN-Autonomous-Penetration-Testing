"""HEAVEN — NetBIOS name-service (NBSTAT) enrichment.

A hardened Windows host with Windows Firewall on and File & Printer Sharing off
silently *filters* every classic TCP port (135 / 139 / 445 / 3389) — so an
unprivileged connect scan sees nothing and the host reads as "down / OS not
determined". Yet the NetBIOS **name service** on UDP/137 almost always still
answers a node-status (NBSTAT) query on a LAN, and its reply is a goldmine of
*real, observed* facts that need no root and no open TCP port:

* the machine's **computer name** (the NetBIOS ``<00>`` UNIQUE entry),
* the **workgroup / domain** (the ``<00>`` GROUP entry),
* whether the **Server service** (file sharing, suffix ``<20>``) is running,
* whether it is a **domain controller** / browser master (``<1c>`` / ``<1d>``),
* the adapter **MAC address**, embedded in the statistics block.

That single UDP round-trip turns "192.168.0.102 — OS not determined, 0 open
ports" into "192.168.0.102 — Windows host HEAVEN-PC (WORKGROUP), file sharing
enabled, MAC ..." without sending anything but one benign name query. NBSTAT is
a Windows/SMB-stack protocol, so a positive reply is itself a strong, honest
Windows signal.

Everything here is best-effort and read-only: one small UDP datagram out, one
parsed in. It never raises to the caller and returns ``None`` when the host does
not answer (the common case off-LAN, where UDP/137 is not routed).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.netbios")

# NetBIOS suffixes we surface by name (the byte after each 15-char name).
# https://learn.microsoft.com/troubleshoot/windows-server/networking/netbios-suffixes
_SUFFIX_ROLE = {
    0x00: "workstation",
    0x20: "file-server (Server service)",
    0x03: "messenger",
    0x1B: "domain master browser (PDC)",
    0x1C: "domain controller / group",
    0x1D: "master browser",
    0x1E: "browser service elections",
    0x06: "RAS server",
    0x21: "RAS client",
    0x42: "SMS client",
}


@dataclass
class NetbiosInfo:
    """Parsed NBSTAT node-status result. Every field is a directly observed fact
    from the host's own reply; empty when the reply did not carry it."""
    host: str
    computer_name: str = ""
    workgroup: str = ""            # domain OR workgroup — the <00> GROUP entry
    mac_address: str = ""
    is_domain_controller: bool = False
    file_sharing: bool = False     # Server service (suffix <20>) present
    names: list[tuple[str, int, bool]] = field(default_factory=list)  # (name, suffix, is_group)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "computer_name": self.computer_name,
            "workgroup": self.workgroup,
            "mac_address": self.mac_address,
            "is_domain_controller": self.is_domain_controller,
            "file_sharing": self.file_sharing,
            "names": [
                {"name": n, "suffix": f"0x{s:02x}", "group": g,
                 "role": _SUFFIX_ROLE.get(s, "")}
                for n, s, g in self.names
            ],
        }


def _encode_nbstat_name() -> bytes:
    """The wildcard ``*`` name, first-level-encoded, for a node-status request.

    NBSTAT queries the special name ``*`` padded with NULs to 16 bytes, then
    first-level (nibble) encoded into 32 bytes prefixed with the length 0x20 and
    terminated by a 0x00 label — exactly what Windows' ``nbtstat -A`` sends."""
    name = b"*" + b"\x00" * 15  # '*' then 15 NULs = 16 bytes
    encoded = bytearray()
    for byte in name:
        encoded.append((byte >> 4) + ord("A"))
        encoded.append((byte & 0x0F) + ord("A"))
    return bytes([0x20]) + bytes(encoded) + b"\x00"


def _build_query(txn_id: int = 0xA248) -> bytes:
    header = struct.pack(
        ">HHHHHH",
        txn_id,   # transaction id
        0x0000,   # flags: standard query, no recursion
        1,        # QDCOUNT
        0, 0, 0,  # AN / NS / AR
    )
    question = _encode_nbstat_name() + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def _clean(raw: bytes) -> str:
    return raw.decode("latin-1", "replace").rstrip(" \x00").strip()


def _parse_response(data: bytes, host: str) -> Optional[NetbiosInfo]:
    """Parse an NBSTAT node-status response into a :class:`NetbiosInfo`.

    Layout after the 12-byte DNS-style header: the answer RR's NAME (34 bytes for
    our encoded ``*``), TYPE(2) CLASS(2) TTL(4) RDLENGTH(2), then RDATA =
    NUM_NAMES(1) followed by NUM_NAMES × (15-byte name + 1-byte suffix + 2-byte
    flags), then a 46-byte statistics block whose first 6 bytes are the MAC.
    """
    # 12 header + 34 encoded-name + 2 type + 2 class + 4 ttl + 2 rdlength = 56,
    # so NUM_NAMES sits at offset 56 in a standard reply.
    if len(data) < 57:
        return None
    num_names = data[56]
    if num_names == 0 or num_names > 64:
        return None
    off = 57
    info = NetbiosInfo(host=host)
    for _ in range(num_names):
        if off + 18 > len(data):
            break
        name = _clean(data[off:off + 15])
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        is_group = bool(flags & 0x8000)
        off += 18
        if not name:
            continue
        info.names.append((name, suffix, is_group))
        if suffix == 0x00 and not is_group and not info.computer_name:
            info.computer_name = name
        elif suffix == 0x00 and is_group and not info.workgroup:
            info.workgroup = name
        if suffix == 0x20:
            info.file_sharing = True
        if suffix in (0x1B, 0x1C):
            info.is_domain_controller = True
    # Statistics block: the 6 bytes immediately after the name table are the
    # adapter's unit ID = its MAC address. Only trust a non-zero address.
    if off + 6 <= len(data):
        mac = data[off:off + 6]
        if any(mac):
            info.mac_address = ":".join(f"{b:02X}" for b in mac)
    if not info.names:
        return None
    return info


def _nbstat_blocking(host: str, timeout: float) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_build_query(), (host, 137))
        data, _addr = sock.recvfrom(65535)
        return data
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()


def _is_lan_target(host: str) -> bool:
    """NBSTAT is a link-local protocol: UDP/137 is not routed across the public
    internet, so probing a public address is a guaranteed timeout. Restrict the
    probe to private / loopback / link-local space (and un-parseable hostnames,
    which on an internal engagement are usually LAN names) so a public-target
    scan pays nothing for it."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname — let the short timeout decide
    return ip.is_private or ip.is_loopback or ip.is_link_local


async def nbstat(host: str, timeout: float = 3.0,
                 *, lan_only: bool = True) -> Optional[NetbiosInfo]:
    """Best-effort NBSTAT node-status enrichment for *host*.

    Returns a :class:`NetbiosInfo` when the host answers on UDP/137, else
    ``None``. Never raises. Skips public addresses by default (``lan_only``)
    because NetBIOS name service is not routed off-LAN.
    """
    if lan_only and not _is_lan_target(host):
        return None
    try:
        loop = asyncio.get_running_loop()
        data = await loop.run_in_executor(
            None, _nbstat_blocking, host, max(1.0, min(5.0, timeout)))
    except Exception:  # noqa: BLE001 — enrichment must never break a scan
        logger.debug("NBSTAT probe failed for %s", host, exc_info=True)
        return None
    if not data:
        return None
    try:
        return _parse_response(data, host)
    except Exception:  # noqa: BLE001 — a malformed reply must not raise
        logger.debug("NBSTAT parse failed for %s", host, exc_info=True)
        return None


def build_netbios_findings(net_data: dict) -> list[dict]:
    """Turn the NetBIOS node-status facts the scanner collected into honest
    findings. Read-only: consumes what ``scan_network`` already observed.

    Two kinds, both evidence-based:

    * **NetBIOS name-service disclosure** (low, CWE-200) — the host answered an
      unauthenticated UDP/137 node-status query with its computer name, work-
      group/domain and MAC. A real internal-recon exposure (the classic
      ``nbtstat -A`` enumeration); fires only when a name was actually leaked.
    * **Windows host, exact version undetermined** (informational observation) —
      NBSTAT (or another Windows signal) confirmed the OS is Windows, but the
      scan could not pin the *release* because it ran unprivileged and SMB was
      filtered. Surfaced so the operator understands why there is no OS-version /
      EOL finding and exactly how to get one (a privileged ``-O`` re-scan, or from
      an in-scope segment where SMB is reachable). Never a fabricated version.
    """
    if not isinstance(net_data, dict):
        return []
    findings: list[dict] = []
    for host in net_data.get("hosts", []) or []:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip") or host.get("host") or ""
        nb = host.get("netbios") or {}
        if not ip or not isinstance(nb, dict) or not nb.get("names"):
            continue
        name = nb.get("computer_name", "")
        workgroup = nb.get("workgroup", "")
        leaked = ", ".join(
            filter(None, [
                f"computer name '{name}'" if name else "",
                f"workgroup/domain '{workgroup}'" if workgroup else "",
                f"MAC {nb['mac_address']}" if nb.get("mac_address") else "",
            ])) or "its NetBIOS name table"
        findings.append({
            "target": f"{ip}:137",
            "vuln_type": "netbios_information_disclosure",
            "severity": "low",
            "title": "NetBIOS Name Service Information Disclosure",
            "description": (
                "The host answered an unauthenticated NetBIOS node-status query "
                f"(UDP/137) with {leaked}. Any peer on the local network can "
                "enumerate this over UDP/137 (the classic `nbtstat -A <ip>` step) "
                "even when the host's TCP ports are firewalled — it hands an "
                "attacker the machine name, domain/workgroup membership and "
                "hardware address for free, seeding lateral-movement and social-"
                "engineering. Disable NetBIOS over TCP/IP on interfaces that do "
                "not need it, or block UDP/137-139 at the network boundary."
            ),
            "confidence": 0.9,
            "cve_id": "",
            "observation": True,
            "evidence": {
                "computer_name": name, "workgroup": workgroup,
                "mac_address": nb.get("mac_address", ""),
                "file_sharing": nb.get("file_sharing", False),
                "names": nb.get("names", []),
                "cwe": "CWE-200",
            },
            "source": "netbios",
        })
        # A domain controller announcing itself over NetBIOS is worth calling out
        # as an AD attack-surface pointer (still informational).
        if nb.get("is_domain_controller"):
            findings.append({
                "target": ip,
                "vuln_type": "active_directory_exposure",
                "severity": "info",
                "title": "Active Directory Domain Controller Identified (NetBIOS)",
                "description": (
                    f"The host advertises a domain-controller / domain-master "
                    f"NetBIOS role for domain '{workgroup or 'unknown'}'. It is an "
                    "Active Directory DC — the highest-value internal target. Run "
                    "HEAVEN's AD assessment against it (Kerberos AS-REP/roasting, "
                    "SMB signing/null-session, ADCS, coercion) from an in-scope "
                    "segment with the SMB/LDAP/Kerberos ports reachable."
                ),
                "confidence": 0.85,
                "cve_id": "",
                "observation": True,
                "evidence": {"domain": workgroup, "role": "domain controller",
                             "source": "netbios-nbstat"},
                "source": "netbios",
            })
        # Windows confirmed but the exact release is unknown (unprivileged + SMB
        # filtered) → tell the operator how to get the version/EOL, don't guess.
        os_guess = str(host.get("os_guess") or "").strip().lower()
        os_source = str(host.get("os_source") or "").strip().lower()
        version_known = any(tok in os_guess for tok in (
            "xp", "vista", " 7", " 8", " 10", " 11", "2003", "2008", "2012",
            "2016", "2019", "2022", "server"))
        if os_guess == "windows" and not version_known and os_source in ("netbios", "heuristic", ""):
            findings.append({
                "target": ip,
                "vuln_type": "os_version_undetermined",
                "severity": "info",
                "title": "Windows Host — Exact Version Undetermined (privileged re-scan advised)",
                "description": (
                    "The host is confirmed Windows (NetBIOS/SMB stack) but its "
                    "exact release could not be determined, so no OS end-of-life "
                    "check could run. This is a capability limit of the current "
                    "scan, not a clean bill of health: the scan ran without raw-"
                    "socket privileges (no nmap -O TCP/IP fingerprint) and the "
                    "host's SMB (445) is firewall-filtered, so the two reliable "
                    "version sources were both unavailable. To pin the release "
                    "(and flag it if it is an unsupported Windows such as 7 / 8 / "
                    "Server 2008-2012): re-run with privileges (sudo / an "
                    "Administrator token, or grant nmap the raw-socket capability) "
                    "for `-O`, or scan from a segment where SMB is reachable so "
                    "`smb-os-discovery` can read the exact build."
                ),
                "confidence": 0.6,
                "cve_id": "",
                "observation": True,
                "evidence": {"os_guess": host.get("os_guess", ""),
                             "os_source": host.get("os_source", ""),
                             "computer_name": name, "cwe": "CWE-1104"},
                "source": "netbios",
            })
    return findings
