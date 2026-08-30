"""HEAVEN — device-identity enrichment + end-of-life OS precision.

Locks in the fixes for two reported gaps:
  * Assets never showed a MAC and had no auto/ manual device type — the discovery
    ARP MAC was discarded, no service-based device-type heuristic existed, and
    there was no operator override.
  * An end-of-life OS (e.g. Windows 10) was not flagged because the detected OS
    string collapsed to a generic "Windows" the EOL table couldn't match.
"""

from __future__ import annotations


# ── EOL-OS precision ─────────────────────────────────────────────────────────
def test_windows_cpe_preserves_version():
    from heaven.recon.network_scanner import _os_name_from_cpe
    assert _os_name_from_cpe("cpe:/o:microsoft:windows_10::-") == "Windows 10"
    assert _os_name_from_cpe("cpe:2.3:o:microsoft:windows_server_2008:r2") == "Windows Server 2008"
    assert _os_name_from_cpe("cpe:/o:microsoft:windows_7") == "Windows 7"
    assert _os_name_from_cpe("cpe:/o:microsoft:windows_xp") == "Windows XP"
    # A version-less Windows CPE still maps to the bare name (honest fallback).
    assert _os_name_from_cpe("cpe:/o:microsoft:windows") == "Windows"
    # Non-OS / application CPEs are never treated as an OS.
    assert _os_name_from_cpe("cpe:/a:openbsd:openssh:8.9") == ""


def test_smb_os_discovery_yields_precise_os():
    from heaven.recon.network_scanner import _os_from_smb_script
    out = ("  OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)\n"
           "  Computer name: DESKTOP-ABC\n")
    assert _os_from_smb_script("smb-os-discovery", out) == "Windows 10 Pro 19041"
    # Falls back to the OS CPE when no OS line is present.
    cpe_only = "  OS CPE: cpe:/o:microsoft:windows_server_2012::-\n"
    assert _os_from_smb_script("smb-os-discovery", cpe_only) == "Windows Server 2012"
    # A different host script yields nothing.
    assert _os_from_smb_script("nbstat", "NetBIOS name: X") == ""


def test_eol_flags_precise_windows10_but_not_generic():
    from heaven.vulnscan.eol_scanner import _os_finding
    f = _os_finding("192.168.2.50", "Windows 10 Pro 19041")
    assert f and f["vuln_type"] == "unsupported_software"
    assert f["evidence"]["cwe"] == "CWE-1104"
    # A version-less "Windows" must NOT be flagged — that would be a guess.
    assert _os_finding("10.0.0.5", "Windows") is None


def test_eol_flags_old_macos():
    from heaven.vulnscan.eol_scanner import _os_finding
    assert _os_finding("10.0.0.6", "Mac OS X 10.14.6") is not None
    # A supported macOS 12 must not match the 10.x rule.
    assert _os_finding("10.0.0.7", "macOS 12.6") is None


# ── Service-derived device type ──────────────────────────────────────────────
def test_device_type_from_services():
    from heaven.recon.network_scanner import _device_type_from_services
    assert _device_type_from_services([3389, 445]) == "Windows host"
    assert _device_type_from_services([9100]) == "printer"
    assert _device_type_from_services([554]) == "IP camera"
    assert _device_type_from_services([502, 80]) == "industrial control system"
    assert _device_type_from_services([1883]) == "IoT device"
    # An ambiguous/plain web host yields nothing rather than a guess.
    assert _device_type_from_services([80, 443]) == ""
    assert _device_type_from_services([]) == ""


# ── ARP cache reader ─────────────────────────────────────────────────────────
def test_arp_text_parse_and_vendor():
    from heaven.recon import arp_cache
    text = ("? (192.168.2.97) at aa:bb:cc:0:11:22 on en0 ifscope [ethernet]\n"
            "? (192.168.2.1) at ff:ff:ff:ff:ff:ff on en0\n"          # broadcast → dropped
            "192.168.2.5 dev eth0 lladdr 00:0c:29:aa:bb:cc REACHABLE\n")
    table = arp_cache._parse_arp_text(text)
    assert table["192.168.2.97"] == "aa:bb:cc:00:11:22"   # zero-padded
    assert table["192.168.2.5"] == "00:0c:29:aa:bb:cc"
    assert "192.168.2.1" not in table                      # junk MAC excluded
    assert arp_cache.vendor_for_mac("00:0c:29:aa:bb:cc") == "VMware"
    assert arp_cache.vendor_for_mac("aa:bb:cc:00:11:22") == ""   # unknown OUI


# ── Device-identity enrichment (MAC + type) end to end ───────────────────────
def test_enrich_device_identity_fills_mac_and_type(monkeypatch):
    from heaven.recon import network_scanner as ns
    from heaven.recon import arp_cache
    h1 = ns.HostResult(host="192.168.2.50", is_alive=True)
    h1.open_ports = [ns.PortResult(host=h1.host, port=3389, protocol="tcp", state="open")]
    h2 = ns.HostResult(host="192.168.2.51", is_alive=True)
    h2.open_ports = [ns.PortResult(host=h2.host, port=9100, protocol="tcp", state="open")]

    # h1 gets its MAC from the discovery sweep (+vendor); h2 from the ARP cache.
    monkeypatch.setattr(arp_cache, "read_arp_cache",
                        lambda **kw: {"192.168.2.51": "b8:27:eb:11:22:33"})
    ns._enrich_device_identity([h1, h2],
                               {"192.168.2.50": ("AA:BB:CC:00:11:22", "Dell Inc.")})
    assert h1.mac_address == "AA:BB:CC:00:11:22" and h1.mac_vendor == "Dell Inc."
    assert h1.device_type == "Windows host" and h1.device_type_source == "service-heuristic"
    assert h2.mac_address == "B8:27:EB:11:22:33"
    # Raspberry Pi OUI → vendor + a MAC-vendor device type (ranked above service).
    assert h2.mac_vendor == "Raspberry Pi"
    assert h2.device_type == "single-board computer"
    assert h2.device_type_source == "mac-vendor"


def test_enrich_never_overwrites_nmap_facts(monkeypatch):
    from heaven.recon import network_scanner as ns
    from heaven.recon import arp_cache
    h = ns.HostResult(host="10.0.0.9", is_alive=True)
    h.mac_address = "DE:AD:BE:EF:00:01"
    h.device_type = "router"
    h.device_type_source = "nmap"
    monkeypatch.setattr(arp_cache, "read_arp_cache",
                        lambda **kw: {"10.0.0.9": "00:00:00:00:00:99"})
    ns._enrich_device_identity([h], {})
    assert h.mac_address == "DE:AD:BE:EF:00:01"   # nmap MAC untouched
    assert h.device_type == "router" and h.device_type_source == "nmap"


# ── Inventory labels: manual override + service-heuristic ────────────────────
def test_inventory_labels_and_manual_override():
    from heaven.devsecops.inventory import (
        device_type_label, device_name_label, normalize_assets, merge_host_labels,
    )
    assert device_type_label({"device_type": "Windows host",
                              "device_type_source": "service-heuristic"}) \
        == "Windows host (inferred from services)"
    assert device_name_label({"device_name": "Reception PC",
                              "device_name_source": "manual"}) \
        == "Reception PC (operator-set)"

    raw = [{"ip": "192.168.2.50", "device_type": "Windows host",
            "device_type_source": "service-heuristic",
            "open_ports": [{"port": 3389}]}]
    merge_host_labels(raw, {"192.168.2.50": {"device_name": "Reception PC",
                                             "device_type": "Workstation"}})
    inv = normalize_assets(raw)
    row = inv[0]
    # Operator label wins over the service-inferred type.
    assert row["device_type"] == "Workstation"
    assert row["device_type_source"] == "manual"
    assert row["device_name"] == "Reception PC"
    assert row["device_name_source"] == "manual"


def test_cli_asset_path_overlays_operator_labels():
    """The CLI inventory/report path (`heaven assets`, `heaven report`) applies a
    manually-set device name/type too — not only the web report. This is the
    single point where the CLI reads raw host assets, so a label set via the
    Assets ✎ Edit control must show up here as well."""
    from heaven.cli._helpers import _engagement_db_path
    from heaven.cli.assets import _collect_engagement_assets
    from heaven.devsecops.inventory import device_name_label, normalize_assets
    from heaven.engagement import EngagementStore

    db = _engagement_db_path("acme")
    db.parent.mkdir(parents=True, exist_ok=True)
    s = EngagementStore(db)
    s.create_engagement(name="acme")
    s.record_scan_start("sc1", name="10.0.0.5", mode="network",
                        config={"targets": {"ips": ["10.0.0.5"]}})
    s.record_scan_complete("sc1", summary={"assets": [{
        "ip": "10.0.0.5", "host": "10.0.0.5", "is_alive": True,
        "device_type": "Windows host", "device_type_source": "service-heuristic",
        "open_ports": [{"port": 445}],
    }]})

    # No label yet → CLI path shows the service-inferred type, blank name.
    before = normalize_assets(_collect_engagement_assets("acme"))[0]
    assert before["device_type_source"] == "service-heuristic"
    assert not before.get("device_name")

    # Operator sets a manual name/type; the CLI path must reflect it now.
    s.set_host_label("10.0.0.5", device_name="Reception PC", device_type="Workstation")
    after = normalize_assets(_collect_engagement_assets("acme"))[0]
    assert device_name_label(after) == "Reception PC (operator-set)"
    assert after["device_type"] == "Workstation"
    assert after["device_type_source"] == "manual"


# ── EOL product precision: Apache HTTP Server vs the other "Apache" products ──
def test_apache_httpd_eol_excludes_tomcat_and_ajp():
    """Regression: the Apache-httpd EOL rule matched a bare "apache", so
    Metasploitable's Tomcat (:8180, Coyote/1.1) and AJP (:8009, Jserv v1.3) were
    flagged "Apache httpd 2.2" EOL off their PROTOCOL version (1.1/1.3 < 2.4) —
    two false positives with a garbled doubled-version title. The rule now
    requires an httpd context; only the real Apache HTTP Server fires, cleanly."""
    from heaven.vulnscan.eol_scanner import _product_findings

    real = _product_findings("h:80", "Apache httpd", "2.2.8", "Apache/2.2.8 (Ubuntu)")
    titles = [f["title"] for f in real]
    assert titles == ["Unsupported / End-of-Life Software: Apache HTTP Server 2.2.8"]

    # Tomcat / AJP / Coyote must NOT be flagged as Apache httpd off a protocol ver.
    for prod, ver, banner in [
        ("Apache Jserv", "1.3", "Apache Jserv (Protocol v1.3)"),
        ("Apache Tomcat/Coyote JSP engine", "1.1", "Apache-Coyote/1.1"),
    ]:
        out = _product_findings("h:x", prod, ver, banner)
        assert not any("Apache" in f["title"] for f in out), (prod, out)


def test_endoflife_slug_excludes_tomcat_and_ajp_from_apache():
    """The dynamic endoflife.date path had the same bug: "apache" alone mapped
    Apache Jserv (AJP) / Tomcat to the Apache HTTP Server feed, flagging their
    PROTOCOL version EOL ("Apache Jserv 1.3"). httpd context is now required."""
    from heaven.vulnscan.eol_scanner import _endoflife_slug
    assert _endoflife_slug("Apache httpd", "Apache/2.2.8") == "apache"
    assert _endoflife_slug("Apache Jserv", "Apache Jserv (Protocol v1.3)") == ""
    assert _endoflife_slug("Apache Tomcat/Coyote", "Apache-Coyote/1.1") == "tomcat"
