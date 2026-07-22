"""Detectors added to close the gap against real-world pen-test reports:

* CMS / WordPress hardening (admin panel, XML-RPC + pingback, version, user enum)
* Server software-version banner exposure
* End-of-life / unsupported software (CWE-1104)
* Network exposure deepening: IPMI RAKP hash-dump, SNMP GETBULK amplification,
  anonymous-FTP login, RDP-NLA — packet builders, parsers and FP-safety.

Every network probe is exercised offline: the WordPress/banner tests run against
a local mock HTTP server; the raw-protocol probes are tested for well-formed
packets, correct parsing of crafted replies, and no-false-positive behaviour
when the active probes are disabled.
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest

from heaven.devsecops.vuln_kb import enrich_finding
from heaven.recon import network_exposure as nx
from heaven.vulnscan.eol_scanner import scan_eol_from_net

pytest.importorskip("aiohttp")

from heaven.vulnscan.cms_scanner import scan_cms          # noqa: E402
from heaven.vulnscan.misconfig_scanner import scan_misconfig  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _types(findings):
    return {f["vuln_type"] for f in findings}


# ── a tiny routable mock HTTP server (one request per connection) ────────────
class MockHTTP:
    """Serves canned responses keyed by request path. ``routes`` maps a path to
    (status, headers-dict, body-str)."""

    def __init__(self, routes: dict):
        self.routes = routes

    async def __aenter__(self):
        self._s = await asyncio.start_server(self._h, "127.0.0.1", 0)
        self.port = self._s.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        return self

    async def __aexit__(self, *e):
        self._s.close()
        with contextlib.suppress(Exception):
            await self._s.wait_closed()

    async def _h(self, reader, writer):
        with contextlib.suppress(Exception):
            req = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=1.0)
            line = req.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"
            status, headers, body = self.routes.get(
                path, self.routes.get("*", (404, {}, "not found")))
            body_b = body.encode() if isinstance(body, str) else body
            head = f"HTTP/1.1 {status} X\r\n"
            hdrs = dict(headers)
            hdrs.setdefault("Content-Length", str(len(body_b)))
            hdrs.setdefault("Connection", "close")
            for k, v in hdrs.items():
                head += f"{k}: {v}\r\n"
            writer.write(head.encode() + b"\r\n" + body_b)
            await writer.drain()
            writer.close()


_WP_LOGIN = ("<html><body><form name='loginform' id='loginform'>"
             "<input name='log' id='user_login'>"
             "<input type='submit' id='wp-submit' value='Log In'></form></body></html>")
_WP_HOME = ("<html><head>"
            "<meta name='generator' content='WordPress 6.4.2'>"
            "<link rel='stylesheet' href='/wp-content/themes/x/style.css'>"
            "</head><body>Welcome</body></html>")
_XMLRPC_METHODS = ("<?xml version='1.0'?><methodResponse><params><param><value>"
                   "<array><data>"
                   "<value><string>system.listMethods</string></value>"
                   "<value><string>pingback.ping</string></value>"
                   "<value><string>wp.getUsersBlogs</string></value>"
                   "</data></array></value></param></params></methodResponse>")
_WP_USERS = '[{"id":1,"name":"Admin User","slug":"admin"},' \
            '{"id":2,"name":"Editor","slug":"editor"}]'


def _wordpress_routes():
    return {
        "/": (200, {"Content-Type": "text/html", "X-Pingback": "http://x/xmlrpc.php",
                    "Server": "nginx/1.22.1"}, _WP_HOME),
        "/wp-login.php": (200, {"Content-Type": "text/html"}, _WP_LOGIN),
        "/wp-admin/": (302, {"Location": "http://x/wp-login.php?redirect_to=/wp-admin/"}, ""),
        "/xmlrpc.php": (200, {"Content-Type": "text/xml"}, _XMLRPC_METHODS),
        "/wp-json/wp/v2/users": (200, {"Content-Type": "application/json"}, _WP_USERS),
        "/readme.html": (200, {"Content-Type": "text/html"},
                         "<html>WordPress <br/> Version 6.4.2</html>"),
    }


# ── CMS / WordPress scanner ──────────────────────────────────────────────────
def test_cms_detects_full_wordpress_hardening_set():
    async def _go():
        async with MockHTTP(_wordpress_routes()) as srv:
            return await scan_cms([srv.base + "/"])
    res = _run(_go())
    types = _types(res["findings"])
    assert "admin_panel_exposed" in types
    assert "xmlrpc_enabled" in types
    assert "wordpress_version_disclosure" in types
    assert "wordpress_user_enumeration" in types
    # xmlrpc must be HIGH because pingback.ping was advertised
    xr = next(f for f in res["findings"] if f["vuln_type"] == "xmlrpc_enabled")
    assert xr["severity"] == "high"
    assert xr["evidence"]["pingback_ping"] is True
    ue = next(f for f in res["findings"] if f["vuln_type"] == "wordpress_user_enumeration")
    assert "admin" in ue["evidence"]["usernames"]
    # everything enriches to real taxonomy
    for f in res["findings"]:
        e = enrich_finding(f)
        assert e.get("cwe") and e.get("cvss_vector")


def test_cms_no_findings_on_non_wordpress_site():
    routes = {"/": (200, {"Content-Type": "text/html", "Server": "nginx"},
                    "<html><body>Just a plain site</body></html>"),
              "*": (404, {}, "nope")}

    async def _go():
        async with MockHTTP(routes) as srv:
            return await scan_cms([srv.base + "/"])
    res = _run(_go())
    assert res["findings"] == []


def test_cms_xmlrpc_only_medium_without_pingback():
    routes = _wordpress_routes()
    # advertise RPC but WITHOUT pingback.ping
    routes["/xmlrpc.php"] = (200, {"Content-Type": "text/xml"},
                             "<?xml version='1.0'?><methodResponse><params><param>"
                             "<value><array><data>"
                             "<value><string>demo.sayHello</string></value>"
                             "</data></array></value></param></params></methodResponse>")

    async def _go():
        async with MockHTTP(routes) as srv:
            return await scan_cms([srv.base + "/"])
    res = _run(_go())
    xr = next(f for f in res["findings"] if f["vuln_type"] == "xmlrpc_enabled")
    assert xr["severity"] == "medium"
    assert xr["evidence"]["pingback_ping"] is False


# ── server-banner version exposure (misconfig scanner) ───────────────────────
def test_banner_version_disclosure_flagged():
    routes = {"/": (200, {"Content-Type": "text/html", "Server": "nginx/1.22.1",
                          "X-Content-Type-Options": "nosniff",
                          "Content-Security-Policy": "default-src 'self'",
                          "X-Frame-Options": "DENY"},
                    "<html><body>hi</body></html>")}

    async def _go():
        async with MockHTTP(routes) as srv:
            return await scan_misconfig([srv.base + "/"])
    res = _run(_go())
    banners = [f for f in res["findings"] if f["vuln_type"] == "server_version_disclosure"]
    assert banners, "expected a server_version_disclosure finding"
    assert "nginx/1.22.1" in banners[0]["evidence"]["disclosed_headers"].get("Server", "")


def test_banner_not_flagged_without_version():
    # A bare product token with no version is not actionable → no finding.
    routes = {"/": (200, {"Content-Type": "text/html", "Server": "nginx",
                          "X-Content-Type-Options": "nosniff",
                          "Content-Security-Policy": "default-src 'self'",
                          "X-Frame-Options": "DENY"},
                    "<html><body>hi</body></html>")}

    async def _go():
        async with MockHTTP(routes) as srv:
            return await scan_misconfig([srv.base + "/"])
    res = _run(_go())
    assert "server_version_disclosure" not in _types(res["findings"])


# ── EOL / unsupported software ───────────────────────────────────────────────
def test_eol_flags_os_and_components():
    net = {"hosts": [{
        "ip": "192.168.2.125", "os_guess": "Microsoft Windows 10 22H2",
        "open_ports": [
            {"port": 80, "service": "http", "product": "Apache httpd",
             "version": "2.2.15", "banner": "Apache/2.2.15"},
            {"port": 8080, "service": "http", "product": "PHP", "version": "7.4.3",
             "banner": "PHP/7.4.3"},
        ]}]}
    res = _run(scan_eol_from_net(net))
    types = {f["evidence"]["product"] for f in res["findings"]}
    assert any("Windows 10" in t for t in types)
    assert any("Apache" in t for t in types)
    assert any("PHP" in t for t in types)
    for f in res["findings"]:
        assert f["vuln_type"] == "unsupported_software"
        assert f["evidence"]["eol_date"]
        e = enrich_finding(f)
        assert e.get("cwe") == "CWE-1104"


def test_eol_no_false_positive_on_supported_stack():
    net = {"hosts": [{
        "ip": "10.0.0.5", "os_guess": "Ubuntu Linux 22.04",
        "open_ports": [
            {"port": 443, "service": "https", "product": "nginx", "version": "1.24.0",
             "banner": "nginx/1.24.0"},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6",
             "banner": "OpenSSH 9.6"},
            {"port": 8080, "service": "http", "product": "PHP", "version": "8.3.1",
             "banner": "PHP/8.3.1"},
        ]}]}
    res = _run(scan_eol_from_net(net))
    assert res["findings"] == []


def test_eol_flags_always_eol_product_by_name():
    net = {"hosts": [{"ip": "192.168.2.138", "os_guess": "",
                      "open_ports": [{"port": 80, "service": "http",
                                      "product": "Microsoft Silverlight", "version": "",
                                      "banner": "Silverlight"}]}]}
    res = _run(scan_eol_from_net(net))
    assert any("Silverlight" in f["evidence"]["product"] for f in res["findings"])


# ── network exposure: new packet builders + parsers ──────────────────────────
def test_snmp_getbulk_packet_well_formed():
    pkt = nx._snmp_getbulk_packet("public", 0x1234, nx.MIB2_OID, max_repetitions=50)
    assert pkt[0] == 0x30              # outer SEQUENCE
    assert 0xA5 in pkt                 # GetBulkRequest-PDU tag
    assert b"public" in pkt
    assert nx.MIB2_OID in pkt


def test_ipmi_open_session_and_rakp1_are_rmcp_plus():
    op = nx._ipmi_open_session_request(0xAABBCCDD)
    assert op[:4] == bytes([0x06, 0x00, 0xFF, 0x07])   # RMCP header
    assert op[4] == 0x06               # RMCP+ auth type
    assert op[5] == 0x10               # Open Session Request payload type
    r1 = nx._ipmi_rakp1(0xAABBCCDD, b"\x01\x02\x03\x04", "admin")
    assert r1[5] == 0x12               # RAKP Message 1 payload type
    assert b"admin" in r1


def test_rdp_neg_request_is_tpkt_x224():
    pkt = nx._rdp_neg_request(0x00000000)
    assert pkt[0] == 0x03              # TPKT version
    assert pkt[5] == 0xE0              # X.224 Connection Request code
    assert pkt[11] == 0x01             # RDP Negotiation Request type (after 6-byte X.224 hdr)
    assert pkt[4] == 6 + 8             # X.224 LI = fixed header (6) + neg payload (8)


def test_active_probes_disabled_gives_no_ftp_or_rdp_findings():
    # IPMI/FTP/RDP present but active_probes off → IPMI stays a medium exposure,
    # and NO ftp_anonymous / rdp_nla_disabled findings are fabricated.
    net = {"hosts": [{"ip": "10.0.0.9", "open_ports": [
        {"port": 21, "service": "ftp"},
        {"port": 3389, "service": "ms-wbt-server"},
        {"port": 623, "service": "asf-rmcp"},
    ]}]}
    res = _run(nx.analyze_network_exposure(net, active_snmp=False, active_probes=False))
    types = _types(res["findings"])
    assert "ftp_anonymous" not in types
    assert "rdp_nla_disabled" not in types
    assert "ipmi_hash_disclosure" not in types
    # FTP still flagged as a cleartext service, IPMI still flagged as exposed.
    assert "cleartext_service" in types
    assert "ipmi_exposed" in types
