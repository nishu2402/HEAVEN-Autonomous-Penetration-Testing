"""
Host & Service Inventory — open ports, service versions and OS.

Locks in that the network scanner captures accurate service/version/OS data and
that it surfaces, unchanged, through the shared inventory model into the CLI,
the API and every report format. The through-line is *no fabrication*: values
are reported exactly as nmap observed them, and an OS inferred from a TTL is
always labelled as a guess — never presented as a confirmed fact.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.devsecops.inventory import (
    host_key,
    inventory_totals,
    normalize_assets,
    os_label,
    render_markdown,
    service_version_str,
)


# ── scanner: version recombination + OS confidence/source ───────────────────

_NMAP_XML_FINGERPRINTED = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.9p1"
             extrainfo="Ubuntu Linux; protocol 2.0">
     <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
    </service>
   </port>
   <port protocol="tcp" portid="443">
    <state state="open"/>
    <service name="https" product="nginx" version="1.18.0"/>
   </port>
   <port protocol="tcp" portid="3306">
    <state state="closed"/>
    <service name="mysql"/>
   </port>
  </ports>
  <os><osmatch name="Linux 5.0 - 5.4" accuracy="97"/></os>
 </host>
</nmaprun>"""

_NMAP_XML_TTL_ONLY = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.9" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.52"/>
   </port>
  </ports>
  <distance value="64"/>
 </host>
</nmaprun>"""


def _run_scan_with_xml(monkeypatch, xml: bytes, host: str):
    from heaven.recon import network_scanner as ns

    class _FakeProc:
        async def communicate(self):
            return (xml, b"")

    async def _fake_exec(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    return asyncio.run(ns.scan_host(host, [22, 80, 443, 3306]))


def test_scan_host_captures_product_version_and_fingerprinted_os(monkeypatch):
    res = _run_scan_with_xml(monkeypatch, _NMAP_XML_FINGERPRINTED, "10.0.0.5")
    assert res.is_alive
    # closed port is dropped; only the two open ports remain
    ports = {p.port: p for p in res.open_ports}
    assert set(ports) == {22, 443}
    assert ports[22].product == "OpenSSH"
    assert ports[22].version == "8.9p1"
    assert ports[22].extrainfo.startswith("Ubuntu")
    assert ports[22].cpe == "cpe:/a:openbsd:openssh:8.9p1"
    # OS came from a real nmap fingerprint, with its confidence preserved
    assert res.os_guess == "Linux 5.0 - 5.4"
    assert res.os_source == "nmap"
    assert res.os_accuracy == 97


def test_scan_host_ttl_os_is_marked_heuristic(monkeypatch):
    res = _run_scan_with_xml(monkeypatch, _NMAP_XML_TTL_ONLY, "10.0.0.9")
    assert res.os_guess == "Linux/Unix"
    # inferred from a TTL, not a stack fingerprint → explicitly heuristic
    assert res.os_source == "heuristic"
    assert res.os_accuracy == 0


def test_host_to_dict_exposes_service_version_and_os_fields(monkeypatch):
    from heaven.recon.network_scanner import _host_to_dict
    res = _run_scan_with_xml(monkeypatch, _NMAP_XML_FINGERPRINTED, "10.0.0.5")
    d = _host_to_dict(res)
    assert d["os_source"] == "nmap"
    assert d["os_accuracy"] == 97
    p22 = next(p for p in d["open_ports"] if p["port"] == 22)
    assert p22["product"] == "OpenSSH"
    assert p22["service_version"] == "OpenSSH 8.9p1 (Ubuntu Linux; protocol 2.0)"


# ── OS fingerprinting without root: privilege gating + heuristic fallback ────
# `nmap -O` / `-sS` / `-sU` need raw sockets and abort the whole scan if run
# unprivileged, so those flags are added only when we're certain we have the
# privileges (root, or passwordless sudo). When we don't, the OS is inferred
# from real service-detection evidence (ostype / OS CPEs, which -sV reports
# without root) and always labelled unconfirmed — never faked.

# service reports its OS type but there's no -O osmatch and no TTL distance
_NMAP_XML_OSTYPE_ONLY = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.7" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.9p1" ostype="Linux"/>
   </port>
  </ports>
 </host>
</nmaprun>"""

# only an OS-level CPE identifies the platform (no osmatch, no ostype, no TTL)
_NMAP_XML_OS_CPE_ONLY = b"""<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.8" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="445">
    <state state="open"/>
    <service name="microsoft-ds" product="Microsoft Windows Server 2019 microsoft-ds">
     <cpe>cpe:/o:microsoft:windows_server_2019</cpe>
    </service>
   </port>
  </ports>
 </host>
</nmaprun>"""


def _run_scan_capture_cmd(monkeypatch, xml: bytes, host: str, ports=None, **kw):
    """Run scan_host with a stubbed nmap and return (result, argv) so tests can
    assert on the exact flags the scanner chose."""
    from heaven.recon import network_scanner as ns

    captured: dict = {}

    class _FakeProc:
        async def communicate(self):
            return (xml, b"")

    async def _fake_exec(*args, **kwargs):
        captured["cmd"] = list(args)
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    res = asyncio.run(ns.scan_host(host, ports or [22, 80, 443], **kw))
    return res, captured["cmd"]


def test_service_ostype_used_as_heuristic_os(monkeypatch):
    res = _run_scan_with_xml(monkeypatch, _NMAP_XML_OSTYPE_ONLY, "10.0.0.7")
    # a real observed signal (the service's ostype), but not a stack fingerprint
    assert res.os_guess == "Linux"
    assert res.os_source == "heuristic"
    assert res.os_accuracy == 0


def test_os_level_cpe_used_as_heuristic_os(monkeypatch):
    res = _run_scan_with_xml(monkeypatch, _NMAP_XML_OS_CPE_ONLY, "10.0.0.8")
    assert res.os_guess == "Windows"
    assert res.os_source == "heuristic"
    # the OS CPE must NOT be mistaken for the port's (application) CPE
    p445 = next(p for p in res.open_ports if p.port == 445)
    assert p445.cpe == ""


def test_os_flag_added_only_when_privileged(monkeypatch):
    from heaven.recon import network_scanner as ns
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: True)
    monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ())
    _, cmd = _run_scan_capture_cmd(monkeypatch, _NMAP_XML_FINGERPRINTED, "10.0.0.5")
    assert cmd[0] == "nmap"
    assert "-O" in cmd


def test_os_flag_omitted_when_unprivileged(monkeypatch):
    from heaven.recon import network_scanner as ns
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
    monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ())
    _, cmd = _run_scan_capture_cmd(monkeypatch, _NMAP_XML_TTL_ONLY, "10.0.0.9")
    # unprivileged: never add -O (it would abort the whole scan)
    assert "-O" not in cmd


def test_sudo_prefix_elevates_and_enables_os_flag(monkeypatch):
    from heaven.recon import network_scanner as ns
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
    monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ("/usr/bin/sudo", "-n"))
    _, cmd = _run_scan_capture_cmd(monkeypatch, _NMAP_XML_FINGERPRINTED, "10.0.0.5")
    assert cmd[:3] == ["/usr/bin/sudo", "-n", "nmap"]
    assert "-O" in cmd  # sudo runs nmap as root → -O is safe


def test_udp_scan_uses_raw_flags_only_when_privileged(monkeypatch):
    from heaven.recon import network_scanner as ns
    # privileged → real SYN + UDP scan
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: True)
    monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ())
    _, cmd = _run_scan_capture_cmd(
        monkeypatch, _NMAP_XML_TTL_ONLY, "10.0.0.9",
        include_udp=True, udp_ports=[161],
    )
    assert "-sS" in cmd and "-sU" in cmd

    # unprivileged → fall back to a TCP connect scan instead of aborting
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
    monkeypatch.setattr(ns, "_nmap_sudo_prefix", lambda: ())
    _, cmd2 = _run_scan_capture_cmd(
        monkeypatch, _NMAP_XML_TTL_ONLY, "10.0.0.9",
        include_udp=True, udp_ports=[161],
    )
    assert "-sU" not in cmd2 and "-sS" not in cmd2 and "-O" not in cmd2


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:/o:microsoft:windows_server_2019", "Windows"),
    ("cpe:/o:linux:linux_kernel:5.4", "Linux"),
    ("cpe:/o:apple:mac_os_x:12.0", "macOS"),
    ("cpe:/o:freebsd:freebsd:13", "FreeBSD"),
    ("cpe:/a:openbsd:openssh:8.9p1", ""),   # application CPE → not an OS
    ("", ""),
])
def test_os_name_from_cpe(cpe, expected):
    from heaven.recon.network_scanner import _os_name_from_cpe
    assert _os_name_from_cpe(cpe) == expected


def test_os_from_service_evidence_prefers_majority():
    from heaven.recon.network_scanner import _os_from_service_evidence
    assert _os_from_service_evidence(["Linux", "Linux", "Windows"], []) == "Linux"
    assert _os_from_service_evidence([], ["cpe:/o:microsoft:windows_10"]) == "Windows"
    assert _os_from_service_evidence([], []) == ""  # no evidence → no guess


def test_nmap_sudo_prefix_policies(monkeypatch):
    from heaven.recon import network_scanner as ns

    def _prefix():
        ns._nmap_sudo_prefix.cache_clear()
        return ns._nmap_sudo_prefix()

    # never → no sudo, ever
    monkeypatch.setenv("HEAVEN_NMAP_SUDO", "never")
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
    monkeypatch.setattr(ns.shutil, "which", lambda name: "/usr/bin/sudo")
    assert _prefix() == ()

    # already privileged → sudo unnecessary even under "always"
    monkeypatch.setenv("HEAVEN_NMAP_SUDO", "always")
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: True)
    assert _prefix() == ()

    # always + sudo present + unprivileged → prepend, no probe needed
    monkeypatch.setattr(ns, "_have_admin_privileges", lambda: False)
    assert _prefix() == ("/usr/bin/sudo", "-n")

    # auto → only when the (non-prompting) probe actually succeeds
    monkeypatch.setenv("HEAVEN_NMAP_SUDO", "auto")

    class _Probe:
        def __init__(self, rc):
            self.returncode = rc

    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **k: _Probe(0))
    assert _prefix() == ("/usr/bin/sudo", "-n")
    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **k: _Probe(1))
    assert _prefix() == ()
    ns._nmap_sudo_prefix.cache_clear()


# ── inventory model: normalization, dedup, honest OS labelling ──────────────

@pytest.mark.parametrize("target,expected", [
    ("https://10.0.0.5:8443/admin", "10.0.0.5"),
    ("http://example.com/path?q=1", "example.com"),
    ("10.0.0.5:22", "10.0.0.5"),
    ("10.0.0.5", "10.0.0.5"),
    ("HOST.LOCAL", "host.local"),
    ("", ""),
])
def test_host_key(target, expected):
    assert host_key(target) == expected


def test_service_version_str_recombines_and_falls_back():
    assert service_version_str({"product": "OpenSSH", "version": "8.9p1"}) == "OpenSSH 8.9p1"
    assert service_version_str(
        {"product": "nginx", "version": "1.18.0", "extrainfo": "Ubuntu"}
    ) == "nginx 1.18.0 (Ubuntu)"
    # pre-computed value wins
    assert service_version_str({"service_version": "already computed"}) == "already computed"
    # nothing but a banner → banner is the fallback
    assert service_version_str({"banner": "raw banner"}) == "raw banner"
    # truly empty → empty (never invented)
    assert service_version_str({}) == ""


def test_os_label_is_honest_about_confidence():
    assert os_label({"os": "Linux 5.4", "os_source": "nmap", "os_accuracy": 98}) \
        == "Linux 5.4 (fingerprinted, 98%)"
    assert os_label({"os": "Linux", "os_source": "nmap"}) == "Linux (fingerprinted)"
    assert os_label({"os": "Windows", "os_source": "heuristic"}) \
        == "Windows (heuristic — unconfirmed)"
    # no OS at all → empty label, never a fabricated guess
    assert os_label({"os": "", "os_source": ""}) == ""


def test_normalize_merges_hosts_and_prefers_authoritative_os():
    assets = [
        {"host": "10.0.0.5", "ip": "10.0.0.5", "is_alive": True,
         "os_guess": "Linux", "os_source": "heuristic",
         "open_ports": [{"port": 22, "service": "ssh"}]},
        # same host from a later scan, now fingerprinted + a new port
        {"host": "https://10.0.0.5:443/", "os_guess": "Linux 5.4",
         "os_source": "nmap", "os_accuracy": 96,
         "open_ports": [{"port": 443, "service": "https", "product": "nginx",
                         "version": "1.18.0"}]},
    ]
    inv = normalize_assets(assets)
    assert len(inv) == 1
    host = inv[0]
    assert host["host"] == "10.0.0.5"
    assert {p["port"] for p in host["ports"]} == {22, 443}
    # nmap fingerprint supersedes the earlier TTL heuristic
    assert host["os_source"] == "nmap"
    assert host["os_label"] == "Linux 5.4 (fingerprinted, 96%)"


def test_normalize_handles_int_ports_and_missing_os():
    inv = normalize_assets([{"ip": "10.0.0.9", "open_ports": [80, 8080]}])
    assert len(inv) == 1
    assert {p["port"] for p in inv[0]["ports"]} == {80, 8080}
    assert inv[0]["os_label"] == ""  # unknown OS is not fabricated


def test_inventory_totals():
    assets = [
        {"ip": "10.0.0.5", "os_guess": "Linux", "os_source": "nmap",
         "open_ports": [{"port": 22, "service": "ssh"},
                        {"port": 443, "service": "https"}]},
        {"ip": "10.0.0.9", "open_ports": [{"port": 22, "service": "ssh"}]},
    ]
    tot = inventory_totals(normalize_assets(assets))
    assert tot["hosts"] == 2
    assert tot["open_ports"] == 3
    assert tot["distinct_services"] == 2   # ssh + https
    assert tot["os_identified"] == 1       # only 10.0.0.5 has an OS


def test_render_markdown_has_section_and_labels():
    md = render_markdown([
        {"ip": "10.0.0.9", "os_guess": "Windows", "os_source": "heuristic",
         "open_ports": [{"port": 3389, "service": "ms-wbt-server"}]},
    ])
    assert "## Host & Service Inventory" in md
    assert "heuristic — unconfirmed" in md
    assert "3389" in md


def test_render_markdown_empty_is_blank():
    assert render_markdown([]) == ""


def test_cli_inventory_prefers_scan_with_open_ports(tmp_path, monkeypatch):
    """Regression: a dead/mistyped-host scan records a host row with zero open
    ports. Defaulting the inventory to it (as the newest asset-bearing scan) made
    the whole inventory look empty even when an earlier scan found real services.
    The default view must skip a 0-port scan for one that actually has ports."""
    from heaven.engagement import EngagementStore
    from heaven.cli import assets as assets_cli

    db = tmp_path / "eng.db"
    store = EngagementStore(db, create=True)
    # Older scan: a live host with real open ports.
    store.record_scan_start("scan-old", name="192.168.1.10", mode="network")
    store.record_scan_complete("scan-old", {"assets": [
        {"ip": "192.168.1.10", "is_alive": True,
         "open_ports": [{"port": 80, "service": "http"},
                        {"port": 443, "service": "https"}]},
    ]})
    # Newer scan: a mistyped/dead host — a bare host row, no ports.
    store.record_scan_start("scan-new", name="192.186.1.100", mode="network")
    store.record_scan_complete("scan-new", {"assets": [
        {"ip": "192.186.1.100", "is_alive": False, "open_ports": []},
    ]})

    monkeypatch.setattr(assets_cli, "_engagement_db_path", lambda eng=None: db)
    raw = assets_cli._collect_engagement_assets(None)
    inv = normalize_assets(raw)
    # The default view must land on the scan that has ports, not the newest empty one.
    assert [h["host"] for h in inv] == ["192.168.1.10"]
    assert inventory_totals(inv)["open_ports"] == 2


# ── reports carry the inventory section ─────────────────────────────────────

_ASSETS = [
    {"host": "10.0.0.5", "ip": "10.0.0.5", "is_alive": True,
     "os_guess": "Linux 5.4", "os_source": "nmap", "os_accuracy": 97,
     "open_ports": [{"port": 22, "service": "ssh", "product": "OpenSSH",
                     "version": "8.9p1", "service_version": "OpenSSH 8.9p1",
                     "cpe": "cpe:/a:openbsd:openssh:8.9p1", "protocol": "tcp"}]},
]
_FINDINGS = [{"title": "Weak TLS", "severity": "medium", "target": "10.0.0.5",
              "vuln_type": "ssl", "risk_score": 5.0, "confidence": 0.9}]


def test_html_report_includes_inventory_section():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    html = ComplianceReportGenerator().generate_html_report(
        _FINDINGS, engagement_name="ACME", assets=_ASSETS)
    assert 'id="inventory"' in html
    assert "#inventory" in html               # TOC entry
    assert "OpenSSH 8.9p1" in html
    assert "fingerprinted, 97%" in html


def test_html_report_without_assets_omits_inventory():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    html = ComplianceReportGenerator().generate_html_report(
        _FINDINGS, engagement_name="ACME")
    assert 'id="inventory"' not in html
    assert "#inventory" not in html


def test_markdown_report_includes_inventory():
    from heaven.devsecops.evidence import export_findings_markdown
    md = export_findings_markdown(_FINDINGS, engagement_name="ACME", assets=_ASSETS)
    assert "## Host & Service Inventory" in md
    assert "OpenSSH 8.9p1" in md


# ── API: /api/assets returns a normalized inventory ─────────────────────────

@pytest.fixture
def api_client(tmp_path, monkeypatch):
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_DATA_DIR", str(tmp_path / "data"))
    import heaven.security.auth as auth_mod
    from heaven.config import reload_config
    reload_config()
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None
        monkeypatch.delenv("HEAVEN_DATA_DIR", raising=False)
        reload_config()


def test_api_assets_returns_normalized_inventory(api_client):
    from heaven.api import server
    store = server._engagement_store_factory("invtest")
    store.create_engagement(name="invtest")
    store.record_scan_start("s1", name="10.0.0.5", mode="network")
    store.record_scan_complete("s1", {"scan_id": "s1", "assets": _ASSETS})

    r = api_client.get("/api/assets?engagement=invtest")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    host = body["assets"][0]
    assert host["host"] == "10.0.0.5"
    assert host["os_label"] == "Linux 5.4 (fingerprinted, 97%)"
    assert host["ports"][0]["service_version"] == "OpenSSH 8.9p1"
    assert body["totals"]["open_ports"] == 1
    assert body["totals"]["os_identified"] == 1
    # A single scan still exposes the picker list (one entry) and its id.
    assert [s["scan_id"] for s in body["scans"]] == ["s1"]
    assert body["scan_id"] == "s1"


def test_api_assets_scopes_to_one_scan_not_merged(api_client):
    """Two separate scans must NOT blend into one host table.

    Regression for the reported bug: running two different scans made the
    Host & Service Inventory show both scans' ports merged together. The view
    is now scoped to a single scan (latest by default) with a picker.
    """
    from heaven.api import server
    store = server._engagement_store_factory("mergetest")
    store.create_engagement(name="mergetest")
    store.record_scan_start("scanA", name="10.0.0.5", mode="network")
    store.record_scan_complete("scanA", {"scan_id": "scanA", "assets": _ASSETS})
    assets_b = [{"host": "192.168.1.10", "ip": "192.168.1.10", "is_alive": True,
                 "open_ports": [{"port": 443, "service": "https", "protocol": "tcp"}]}]
    store.record_scan_start("scanB", name="192.168.1.10", mode="network")
    store.record_scan_complete("scanB", {"scan_id": "scanB", "assets": assets_b})

    expect = {"scanA": "10.0.0.5", "scanB": "192.168.1.10"}

    # Default view = exactly one scan's hosts, never the union of both.
    body = api_client.get("/api/assets?engagement=mergetest").json()
    assert body["total"] == 1, "two scans must not merge into one host table"
    assert {s["scan_id"] for s in body["scans"]} == {"scanA", "scanB"}
    assert body["scan_id"] in expect
    assert body["assets"][0]["host"] == expect[body["scan_id"]]

    # Selecting the other scan shows the other host (independent inventories).
    other = "scanA" if body["scan_id"] == "scanB" else "scanB"
    b2 = api_client.get(f"/api/assets?engagement=mergetest&scan_id={other}").json()
    assert b2["total"] == 1
    assert b2["assets"][0]["host"] == expect[other]

    # ?all=1 is the explicit opt-in for the engagement-wide union (lateral page).
    b3 = api_client.get("/api/assets?engagement=mergetest&all=1").json()
    assert b3["total"] == 2
    assert {h["host"] for h in b3["assets"]} == {"10.0.0.5", "192.168.1.10"}
