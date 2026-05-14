"""
HEAVEN — Wireless Reconnaissance Module
Parses PCAP files to extract wireless network information including
BSSIDs, SSIDs, encryption types, client devices, and rogue AP detection.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.wireless")


@dataclass
class WirelessNetwork:
    bssid: str
    ssid: str = ""
    channel: int = 0
    encryption: str = "Open"
    signal_strength: int = -100
    beacon_count: int = 0
    clients: list[str] = field(default_factory=list)
    is_rogue: bool = False
    rogue_reason: str = ""
    vendor: str = ""


@dataclass
class WirelessClient:
    mac: str
    associated_bssid: str = ""
    probe_ssids: list[str] = field(default_factory=list)
    data_frames: int = 0
    vendor: str = ""


OUI_VENDORS = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "f8:e4:3b": "Apple",
    "3c:22:fb": "Apple", "dc:a6:32": "Raspberry Pi", "44:d9:e7": "TP-Link",
    "00:24:b2": "Netgear", "00:1a:2b": "Cisco", "00:0f:66": "Cisco",
}


def _lookup_vendor(mac: str) -> str:
    return OUI_VENDORS.get(mac[:8].lower(), "Unknown")


def parse_pcap(pcap_path: str) -> dict:
    """Parse PCAP to extract wireless networks, clients, and rogue APs."""
    try:
        from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, RadioTap  # type: ignore[attr-defined]
    except ImportError:
        logger.error("scapy not installed — cannot parse PCAPs")
        return {"networks": [], "clients": [], "rogue_aps": [], "total_frames": 0}

    if not Path(pcap_path).exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        return {"networks": [], "clients": [], "rogue_aps": [], "total_frames": 0}

    logger.info(f"Parsing PCAP: {pcap_path}")
    packets = rdpcap(str(pcap_path))
    networks: dict[str, WirelessNetwork] = {}
    clients: dict[str, WirelessClient] = {}
    ssid_bssids: dict[str, set[str]] = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            continue
        signal = -100
        if pkt.haslayer(RadioTap):
            try:
                signal = int(pkt.getlayer(RadioTap).dBm_AntSignal or -100)  # type: ignore[union-attr]
            except (AttributeError, TypeError):
                pass

        # Beacon frames
        if pkt.haslayer(Dot11Beacon):
            bssid = dot11.addr2
            if not bssid:
                continue
            if bssid not in networks:
                networks[bssid] = WirelessNetwork(bssid=bssid, vendor=_lookup_vendor(bssid))
            net = networks[bssid]
            net.beacon_count += 1
            net.signal_strength = max(net.signal_strength, signal)

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        net.ssid = elt.info.decode("utf-8", errors="replace")
                        ssid_bssids[net.ssid].add(bssid)
                    except Exception:
                        pass
                elif elt.ID == 3:
                    try:
                        net.channel = int.from_bytes(elt.info, "little")
                    except Exception:
                        pass
                elif elt.ID == 48:
                    net.encryption = "WPA2"
                elif elt.ID == 221 and net.encryption == "Open":
                    net.encryption = "WPA"
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None

            cap = pkt.getlayer(Dot11Beacon).cap  # type: ignore[union-attr]
            if hasattr(cap, "privacy") and cap.privacy and net.encryption == "Open":
                net.encryption = "WEP"

        # Probe requests
        elif dot11.type == 0 and dot11.subtype == 4:
            client_mac = dot11.addr2
            if client_mac and client_mac != "ff:ff:ff:ff:ff:ff":
                if client_mac not in clients:
                    clients[client_mac] = WirelessClient(mac=client_mac, vendor=_lookup_vendor(client_mac))
                if pkt.haslayer(Dot11Elt):
                    elt = pkt.getlayer(Dot11Elt)
                    if elt.ID == 0 and elt.info:  # type: ignore[union-attr]
                        try:
                            ssid = elt.info.decode("utf-8", errors="replace")  # type: ignore[union-attr]
                            if ssid and ssid not in clients[client_mac].probe_ssids:
                                clients[client_mac].probe_ssids.append(ssid)
                        except Exception:
                            pass

        # Data frames
        elif dot11.type == 2:
            bssid = dot11.addr1 or dot11.addr2
            if bssid in networks:
                networks[bssid].clients = list(set(networks[bssid].clients + [dot11.addr2 or ""]))

    # Rogue AP detection: SSID duplication with mixed encryption
    rogue_aps = []
    for ssid, bssid_set in ssid_bssids.items():
        if len(bssid_set) > 2 and ssid:
            enc_types = {networks[b].encryption for b in bssid_set if b in networks}
            if len(enc_types) > 1:
                for b in bssid_set:
                    if b in networks:
                        networks[b].is_rogue = True
                        networks[b].rogue_reason = f"Mixed encryption for '{ssid}': {enc_types}"
                        rogue_aps.append(networks[b])

    net_list = list(networks.values())
    client_list = list(clients.values())
    logger.info(f"Wireless: {len(net_list)} networks, {len(client_list)} clients, {len(rogue_aps)} rogue APs")

    return {
        "networks": [{"bssid": n.bssid, "ssid": n.ssid, "channel": n.channel,
                       "encryption": n.encryption, "signal_dbm": n.signal_strength,
                       "clients": len(n.clients), "is_rogue": n.is_rogue, "vendor": n.vendor}
                      for n in net_list],
        "clients": [{"mac": c.mac, "bssid": c.associated_bssid, "probes": c.probe_ssids, "vendor": c.vendor}
                     for c in client_list],
        "rogue_aps": [{"bssid": r.bssid, "ssid": r.ssid, "reason": r.rogue_reason} for r in rogue_aps],
        "total_frames": len(packets),
    }


async def scan_wireless(pcap_files: Optional[list[str]] = None, **kwargs) -> dict[str, Any]:
    """Async entry point for wireless reconnaissance (called by orchestrator)."""
    if not pcap_files:
        logger.info("No PCAP files provided — skipping wireless scan")
        return {"networks": [], "clients": [], "rogue_aps": []}

    loop = asyncio.get_event_loop()
    all_data: dict[str, Any] = {"networks": [], "clients": [], "rogue_aps": [], "total_frames": 0}

    for pcap in pcap_files:
        result = await loop.run_in_executor(None, parse_pcap, pcap)
        all_data["networks"].extend(result.get("networks", []))
        all_data["clients"].extend(result.get("clients", []))
        all_data["rogue_aps"].extend(result.get("rogue_aps", []))
        all_data["total_frames"] += result.get("total_frames", 0)

    return all_data
