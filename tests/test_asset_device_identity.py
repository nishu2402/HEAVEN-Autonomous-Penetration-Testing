"""Device identity in the Host & Service Inventory — MAC, device name, type.

Locks in that the scanner captures a host's MAC address, device / computer name
and device type straight from nmap output, that each is blank when nmap didn't
observe it (never fabricated), and that the shared inventory model carries and
honestly labels them through to the CLI / API / reports. A MAC is an ARP fact, so
it is only present for a same-subnet privileged scan — the tests assert it stays
blank otherwise rather than being invented, and that a device type derived from a
MAC vendor is labelled a hint, never a fingerprint.
"""
from __future__ import annotations

import asyncio

from heaven.devsecops.inventory import (
    device_name_label,
    device_type_label,
    inventory_totals,
    mac_label,
    normalize_assets,
    render_markdown,
)
from heaven.recon.network_scanner import (
    _device_type_from_mac_vendor,
    _host_to_dict,
    _netbios_name_from_script,
)

# ── nmap XML fixtures (crafted, parsed defensively) ──────────────────────────

# Same-subnet host: ARP MAC + vendor, a NetBIOS name (nbstat) AND a PTR name, and
# an nmap -O osclass device type. NetBIOS wins for the name; -O wins for the type.
_XML_FULL = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up" reason="arp-response"/>
  <address addr="192.168.1.50" addrtype="ipv4"/>
  <address addr="00:11:22:aa:bb:cc" addrtype="mac" vendor="Cisco Systems, Inc"/>
  <hostnames><hostname name="switch01.corp.local" type="PTR"/></hostnames>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
  </ports>
  <os><osmatch name="Linux 3.2" accuracy="95">
   <osclass type="router" vendor="Cisco" osfamily="IOS" accuracy="95"/>
  </osmatch></os>
  <hostscript>
   <script id="nbstat" output="NetBIOS name: SWITCH01, NetBIOS user: &lt;unknown&gt;"/>
  </hostscript>
 </host>
</nmaprun>"""

# A reverse-DNS PTR name only (no NetBIOS), no -O osclass, but a known MAC vendor:
# the name comes from PTR and the device type falls back to the MAC-vendor
# category. A leading type="user" hostname (our own input echoed back) is ignored.
_XML_PTR_AND_MAC_VENDOR = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up" reason="arp-response"/>
  <address addr="192.168.1.60" addrtype="ipv4"/>
  <address addr="de:ad:be:ef:00:01" addrtype="mac" vendor="Ubiquiti Inc"/>
  <hostnames>
   <hostname name="192.168.1.60" type="user"/>
   <hostname name="ap.corp.local" type="PTR"/>
  </hostnames>
  <ports>
   <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http"/></port>
  </ports>
 </host>
</nmaprun>"""

# Nothing observed beyond the IP and an open port — every device field stays blank.
_XML_BARE = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.9" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="443"><state state="open"/>
    <service name="https"/></port>
  </ports>
 </host>
</nmaprun>"""

# Only a type="user" hostname (the target we passed in) — not a discovered name,
# so device_name must stay blank.
_XML_USER_HOSTNAME_ONLY = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.30" addrtype="ipv4"/>
  <hostnames><hostname name="example.com" type="user"/></hostnames>
  <ports>
   <port protocol="tcp" portid="443"><state state="open"/>
    <service name="https"/></port>
  </ports>
 </host>
</nmaprun>"""


def _scan(monkeypatch, xml: bytes, host: str):
    """Run scan_host with nmap stubbed to emit `xml`."""
    from heaven.recon import network_scanner as ns

    class _FakeProc:
        async def communicate(self):
            return (xml, b"")

    async def _fake_exec(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    return asyncio.run(ns.scan_host(host, [22, 80, 443]))


# ── scanner capture ──────────────────────────────────────────────────────────

def test_scan_captures_mac_netbios_name_and_fingerprinted_type(monkeypatch):
    res = _scan(monkeypatch, _XML_FULL, "192.168.1.50")
    assert res.mac_address == "00:11:22:AA:BB:CC"      # normalised upper-case
    assert res.mac_vendor == "Cisco Systems, Inc"
    assert res.device_name == "SWITCH01"               # NetBIOS beats PTR
    assert res.device_name_source == "netbios"
    assert res.device_type == "router"                 # nmap -O osclass
    assert res.device_type_source == "nmap"

    d = _host_to_dict(res)
    assert d["mac_address"] == "00:11:22:AA:BB:CC"
    assert d["mac_vendor"] == "Cisco Systems, Inc"
    assert d["device_name"] == "SWITCH01"
    assert d["device_type"] == "router"
    assert d["device_type_source"] == "nmap"


def test_scan_uses_ptr_name_and_mac_vendor_device_type(monkeypatch):
    res = _scan(monkeypatch, _XML_PTR_AND_MAC_VENDOR, "192.168.1.60")
    # 'user' hostname ignored → the PTR name is used, tagged as reverse DNS.
    assert res.device_name == "ap.corp.local"
    assert res.device_name_source == "ptr"
    # No -O osclass → device type falls back to the MAC-vendor category, labelled
    # as such (never presented as a fingerprint).
    assert res.device_type == "network equipment"
    assert res.device_type_source == "mac-vendor"
    assert res.mac_address == "DE:AD:BE:EF:00:01"


def test_scan_leaves_device_fields_blank_when_not_observed(monkeypatch):
    res = _scan(monkeypatch, _XML_BARE, "10.0.0.9")
    assert res.mac_address == "" and res.mac_vendor == ""
    assert res.device_name == "" and res.device_name_source == ""
    assert res.device_type == "" and res.device_type_source == ""
    d = _host_to_dict(res)
    assert d["mac_address"] == "" and d["device_name"] == "" and d["device_type"] == ""


def test_user_supplied_hostname_is_not_a_device_name(monkeypatch):
    res = _scan(monkeypatch, _XML_USER_HOSTNAME_ONLY, "example.com")
    # type="user" is just the target we passed in, not a discovered fact.
    assert res.device_name == ""


# ── helper units ─────────────────────────────────────────────────────────────

def test_device_type_from_mac_vendor_is_conservative():
    assert _device_type_from_mac_vendor("Cisco Systems, Inc") == "network equipment"
    assert _device_type_from_mac_vendor("Ubiquiti Inc") == "network equipment"
    assert _device_type_from_mac_vendor("Raspberry Pi Trading Ltd") == "single-board computer"
    assert _device_type_from_mac_vendor("Hikvision Digital Technology") == "IP camera"
    assert _device_type_from_mac_vendor("Brother Industries") == "printer"
    # An unrecognised vendor yields nothing — never a guessed role.
    assert _device_type_from_mac_vendor("Totally Unknown Widgets Co") == ""
    assert _device_type_from_mac_vendor("") == ""


def test_netbios_name_parsers():
    assert _netbios_name_from_script(
        "nbstat", "NetBIOS name: WIN-PC01, NetBIOS user: x") == "WIN-PC01"
    assert _netbios_name_from_script(
        "smb-os-discovery", "Computer name: host.example.com\nDomain: corp") == "host.example.com"
    assert _netbios_name_from_script(
        "smb-os-discovery", "NetBIOS computer name: WIN-ABC\x00") == "WIN-ABC"
    # A different script, or unparseable text, yields nothing.
    assert _netbios_name_from_script("http-title", "NetBIOS name: NOPE") == ""
    assert _netbios_name_from_script("nbstat", "no name here") == ""


# ── inventory model: carry, merge, label ─────────────────────────────────────

def test_normalize_carries_and_labels_device_identity():
    raw = [{
        "ip": "192.168.1.50", "open_ports": [{"port": 22, "service": "ssh"}],
        "mac_address": "00:11:22:AA:BB:CC", "mac_vendor": "Cisco Systems, Inc",
        "device_name": "SWITCH01", "device_name_source": "netbios",
        "device_type": "router", "device_type_source": "nmap",
    }]
    h = normalize_assets(raw)[0]
    assert h["mac_address"] == "00:11:22:AA:BB:CC"
    assert h["device_name_label"] == "SWITCH01"                 # netbios → no suffix
    assert h["device_type_label"] == "router (fingerprinted)"
    assert h["mac_label"] == "00:11:22:AA:BB:CC (Cisco Systems, Inc)"
    assert mac_label(h) == "00:11:22:AA:BB:CC (Cisco Systems, Inc)"
    assert inventory_totals(normalize_assets(raw))["devices_identified"] == 1


def test_normalize_merges_by_source_rank():
    raw = [
        {"ip": "10.0.0.5", "device_name": "box.corp.local", "device_name_source": "ptr",
         "device_type": "network equipment", "device_type_source": "mac-vendor"},
        {"ip": "10.0.0.5", "device_name": "BOX01", "device_name_source": "netbios",
         "device_type": "router", "device_type_source": "nmap",
         "mac_address": "AA:BB:CC:DD:EE:FF", "mac_vendor": "Acme"},
    ]
    h = normalize_assets(raw)[0]
    assert h["device_name"] == "BOX01"          # NetBIOS outranks PTR
    assert h["device_name_source"] == "netbios"
    assert h["device_type"] == "router"         # nmap osclass outranks MAC-vendor
    assert h["device_type_source"] == "nmap"
    assert h["mac_address"] == "AA:BB:CC:DD:EE:FF"


def test_normalize_backfills_passive_hostname_only_when_blank():
    h = normalize_assets([{"ip": "203.0.113.9", "passive_hostnames": ["svc.example.com"]}])[0]
    assert h["device_name"] == "svc.example.com"
    assert h["device_name_source"] == "passive"
    assert device_name_label(h) == "svc.example.com (passive OSINT)"

    # An active PTR name still outranks a passive one regardless of merge order.
    merged = normalize_assets([
        {"ip": "203.0.113.9", "passive_hostnames": ["svc.example.com"]},
        {"ip": "203.0.113.9", "device_name": "real.corp.local", "device_name_source": "ptr"},
    ])[0]
    assert merged["device_name"] == "real.corp.local"
    assert merged["device_name_source"] == "ptr"


def test_labels_carry_honest_suffixes():
    h = normalize_assets([{
        "ip": "10.0.0.7", "device_name": "cam.corp.local", "device_name_source": "ptr",
        "device_type": "IP camera", "device_type_source": "mac-vendor",
    }])[0]
    assert device_name_label(h) == "cam.corp.local (reverse DNS)"
    assert device_type_label(h) == "IP camera (per MAC vendor)"


def test_render_markdown_shows_device_metadata():
    raw = [{
        "ip": "192.168.1.50", "open_ports": [{"port": 22, "service": "ssh"}],
        "mac_address": "00:11:22:AA:BB:CC", "mac_vendor": "Cisco Systems, Inc",
        "device_name": "SWITCH01", "device_name_source": "netbios",
        "device_type": "router", "device_type_source": "nmap",
    }]
    md = render_markdown(raw)
    assert "**Device:** SWITCH01" in md
    assert "**Type:** router (fingerprinted)" in md
    assert "**MAC:** 00:11:22:AA:BB:CC (Cisco Systems, Inc)" in md


def test_render_markdown_omits_device_lines_when_absent():
    md = render_markdown([{"ip": "10.0.0.9", "open_ports": [{"port": 443, "service": "https"}]}])
    assert "**MAC:**" not in md
    assert "**Device:**" not in md
    assert "**Type:**" not in md
