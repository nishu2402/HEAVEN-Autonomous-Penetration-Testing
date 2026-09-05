"""Tests for the edge/VPN appliance KEV fingerprint (heaven.vulnscan.edge_kev).

The header/cookie matcher is pure; the active probe runs against a fake aiohttp
session. No exploit payloads are ever sent — the probe only GETs login surfaces.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import edge_kev as e


def _vtypes(findings):
    return {f["vuln_type"] for f in findings}


def test_citrix_cookie_fingerprint():
    f = e.match_edge_kev_headers({"Set-Cookie": "NSC_AAAC=abc; path=/"}, target="h")
    assert "edge_citrix_netscaler" in _vtypes(f)
    ev = f[0]["evidence"]
    assert "CVE-2023-4966" in ev["kev_cves"]  # Citrix Bleed
    assert f[0]["severity"] == "medium"       # no version → verify


def test_fortinet_cookie_fingerprint():
    f = e.match_edge_kev_headers({"Set-Cookie": "SVPNCOOKIE=xyz"}, target="h")
    assert "edge_fortinet_fortios" in _vtypes(f)
    assert "CVE-2024-21762" in f[0]["evidence"]["kev_cves"]


def test_exchange_version_header_is_high():
    f = e.match_edge_kev_headers({"X-OWA-Version": "15.2.986.5"}, target="mail")
    assert "edge_microsoft_exchange" in _vtypes(f)
    assert f[0]["severity"] == "high"
    assert f[0]["evidence"]["version"] == "15.2.986.5"


def test_f5_cookie_fingerprint():
    f = e.match_edge_kev_headers({"Set-Cookie": "BIGipServerpool=123.456"}, target="h")
    assert "edge_f5_bigip" in _vtypes(f)


def test_paloalto_server_header():
    f = e.match_edge_kev_headers({"Server": "PanWeb Server/"}, target="h")
    assert "edge_paloalto_globalprotect" in _vtypes(f)
    assert "CVE-2024-3400" in f[0]["evidence"]["kev_cves"]


def test_ivanti_body_fingerprint():
    # A real Ivanti/Pulse login page carries the product brand in the body.
    f = e.match_edge_kev_headers(
        {}, target="h", body="<title>Pulse Secure</title> Ivanti Connect Secure")
    assert "edge_ivanti_pulse" in _vtypes(f)


def test_reflected_probe_path_in_error_body_is_not_a_match():
    """Regression (live Metasploitable FP): a body_regex that is a bare URL-path
    fragment ("/dana-na/", "/tmui/", …) must NOT fingerprint an appliance, because
    a normal web server reflects the requested path in its error page. Probing the
    appliance login paths against one Ubuntu/Apache box otherwise flagged it as
    Citrix AND Ivanti AND Fortinet AND Palo Alto AND F5 at once (five FPs)."""
    for path in ("/dana-na/", "/tmui/", "/vpn/index.html", "/remote/login",
                 "/global-protect/login.esp"):
        body = ("<html><head><title>404 Not Found</title></head><body>"
                f"<h1>Not Found</h1><p>The requested URL {path} was not found "
                "on this server.</p><address>Apache/2.2.8 (Ubuntu) DAV/2</address>"
                "</body></html>")
        f = e.match_edge_kev_headers(
            {"Server": "Apache/2.2.8 (Ubuntu) DAV/2"}, target="h", body=body)
        assert f == [], f"path reflection {path} produced a false appliance match: {f}"


def test_benign_server_no_match():
    assert e.match_edge_kev_headers({"Server": "nginx/1.24.0"}, target="h") == []


def test_no_headers_no_match():
    assert e.match_edge_kev_headers({}, target="h") == []


# ── active probe with a fake session ────────────────────────────────────────────

class _Content:
    def __init__(self, body: bytes):
        self._b = body

    async def read(self, n: int = -1) -> bytes:
        return self._b[:n] if n and n > 0 else self._b


class _Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.content = _Content(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, routes):
        self._routes = routes

    def get(self, url, **kw):
        for substr, make in self._routes:
            if substr in url:
                return make()
        return _Resp(status=404, body=b"")

    async def close(self):
        return None


def test_active_probe_fingerprints_citrix_login_page():
    session = _Session([
        ("/vpn/index.html", lambda: _Resp(
            200, {"Set-Cookie": "NSC_AAAC=x"}, b"Citrix Gateway")),
    ])
    res = asyncio.run(e.scan_edge_appliances(
        ["https://vpn.corp.example/"], session=session))
    findings = res["findings"]
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "edge_citrix_netscaler"


def test_active_probe_dedups_family_across_paths():
    # Two different paths both reveal Citrix — only one finding for the host.
    session = _Session([
        ("/vpn/index.html", lambda: _Resp(200, {"Set-Cookie": "NSC_AAAC=x"}, b"Citrix")),
        ("/logon/LogonPoint", lambda: _Resp(200, {}, b"Citrix Gateway")),
    ])
    res = asyncio.run(e.scan_edge_appliances(
        ["https://vpn.corp.example/"], session=session))
    assert len(res["findings"]) == 1


def test_active_probe_clean_host_no_findings():
    session = _Session([])  # everything 404
    res = asyncio.run(e.scan_edge_appliances(
        ["https://plain.example/"], session=session))
    assert res["findings"] == []


def test_active_probe_no_urls():
    res = asyncio.run(e.scan_edge_appliances([]))
    assert res["findings"] == []
