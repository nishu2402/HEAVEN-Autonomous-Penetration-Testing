"""HEAVEN — OS ARP / neighbour-table reader (dependency-free MAC enrichment).

A host's MAC address is an ARP fact that only exists for machines on the **same
local segment** as the scanner. nmap learns it during a privileged host-discovery
sweep, but a ``-Pn`` service scan skips ARP entirely, so on a LAN scan the MAC was
routinely blank. This module recovers it honestly: after we have already sent scan
traffic to a host, the operating system's own ARP/neighbour cache holds the
resolved ``IP → MAC`` mapping for every on-link host that answered. We simply read
that cache — the entry is a real observation the OS made, never a guess.

Cross-platform, no new dependency: Linux reads ``/proc/net/arp`` (falling back to
``ip neigh``), macOS/BSD parse ``arp -an``, Windows parses ``arp -a``. A routed /
remote host has no ARP entry and is left blank, exactly as before. Vendor is left
to the caller (a full OUI database is out of scope); a small high-signal prefix map
resolves the most common makers so the Assets view isn't bare.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 - fixed-argv reads of the local ARP cache only
import sys
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.arp_cache")

# A MAC that carries no information — broadcast, all-zero, or an incomplete entry
# the OS is still resolving. Never treat these as a discovered address.
_JUNK_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b")
# IPv4 only — a MAC is a layer-2 fact on the local segment; IPv6 neighbour
# discovery is handled by the same tables but IPv4 covers the LAN case we need.
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Small, high-signal OUI-prefix → vendor map (first 3 MAC octets, lowercased). A
# real, manufacturer-assigned identifier; deliberately tiny — an unknown prefix
# leaves the vendor blank rather than guessing.
_OUI_VENDORS: dict[str, str] = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "00:1c:14": "VMware", "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:15:5d": "Microsoft Hyper-V",
    "00:1a:11": "Google", "3c:5a:b4": "Google",
    "fc:fb:fb": "Cisco", "00:1b:0d": "Cisco",
    "00:00:0c": "Cisco", "00:0d:b9": "PC Engines",
}


def _normalise_mac(raw: str) -> str:
    """Zero-pad each octet and lowercase, so ``0:c:29:1:2:3`` and
    ``00:0C:29:01:02:03`` compare equal; '' for a junk/blank MAC."""
    parts = raw.strip().lower().split(":")
    if len(parts) != 6:
        return ""
    try:
        mac = ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""
    return "" if mac in _JUNK_MACS else mac


def vendor_for_mac(mac: str) -> str:
    """Best-effort OUI-prefix vendor for a MAC; '' when the prefix is unknown."""
    m = _normalise_mac(mac)
    return _OUI_VENDORS.get(m[:8], "") if m else ""


def _read_proc_net_arp() -> dict[str, str]:
    """Parse Linux ``/proc/net/arp`` → {ip: mac}. '' MACs are dropped."""
    out: dict[str, str] = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines[1:]:  # skip the header row
        cols = line.split()
        if len(cols) >= 4:
            ip, mac = cols[0], _normalise_mac(cols[3])
            if _IPV4_RE.fullmatch(ip) and mac:
                out[ip] = mac
    return out


def _run(cmd: list[str], timeout: float) -> str:
    """Run a fixed-argv local command, returning stdout ('' on any failure)."""
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell, local only
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _parse_arp_text(text: str) -> dict[str, str]:
    """Parse ``arp -an`` / ``ip neigh`` / ``arp -a`` output → {ip: mac}.

    Handles every layout by pulling the first IPv4 and the first real MAC out of
    each line — robust across macOS (``? (10.0.0.1) at aa:bb:… on en0``), Linux
    ``ip neigh`` (``10.0.0.1 dev eth0 lladdr aa:bb:… REACHABLE``) and Windows.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        ip_m = _IPV4_RE.search(line)
        if not ip_m:
            continue
        mac_m = _MAC_RE.search(line)
        if not mac_m:
            continue
        mac = _normalise_mac(mac_m.group(1).replace("-", ":"))
        if mac:
            out.setdefault(ip_m.group(1), mac)
    return out


def read_arp_cache(*, timeout: float = 4.0) -> dict[str, str]:
    """Return the OS ARP/neighbour table as ``{ipv4: mac}`` for on-link hosts.

    Best-effort and fast; an empty dict when the table can't be read. Every entry
    is a real observation the OS recorded, so callers may treat it as a genuine
    layer-2 fact for a host on the same segment.
    """
    try:
        if sys.platform.startswith("linux"):
            table = _read_proc_net_arp()
            if table:
                return table
            return _parse_arp_text(_run(["ip", "neigh", "show"], timeout))
        if sys.platform == "win32":
            return _parse_arp_text(_run(["arp", "-a"], timeout))
        # macOS / *BSD
        return _parse_arp_text(_run(["arp", "-an"], timeout))
    except Exception as e:  # noqa: BLE001 - enrichment must never break a scan
        logger.debug("ARP cache read failed: %s", e)
        return {}


def mac_for_ip(ip: str, cache: Optional[dict[str, str]] = None) -> str:
    """MAC for one IP from the ARP cache (reads it if not supplied); '' if none."""
    table = cache if cache is not None else read_arp_cache()
    return table.get((ip or "").strip(), "")
