"""P0 — Web-exploitation-depth tests.

Covers the round that closed real gaps in HEAVEN's web coverage:

* taxonomy — the anomaly-probe categories that previously rendered with blank
  OWASP/MITRE/CVSS now resolve to a curated KB entry (no blank columns);
* the new XPath-injection detector (error-based + boolean-differential, benign
  target stays silent);
* the new WebSocket detector (cleartext ws:// + CSWSH, with the near-zero-FP
  guards: cookieless / origin-validated / third-party stay silent);
* the Playwright XSS execution prover — authorization gate, graceful fallback
  when Playwright is absent, and (via a mock browser) that a fired dialog
  carrying the token is what turns a detected XSS into a proven one.

All browser-dependent behaviour is exercised with a mock Playwright so the
suite stays fast and deterministic and needs no Chromium in CI.
"""
from __future__ import annotations

import asyncio
import sys
import types

import pytest

from heaven.devsecops.vuln_kb import enrich_finding
from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
from heaven.vulnscan.exploit_proof import XSSExecutionProver


# ── shared async HTTP fakes ──────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, text: str, headers: dict | None = None):
        self._t = text
        self.headers = headers or {}

    async def text(self) -> str:
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _ReqSession:
    """Fake aiohttp session whose response body is a function of the param value."""

    def __init__(self, fn):
        self._fn = fn

    def request(self, method, url, params=None, **kw):
        val = list(params.values())[0] if params else ""
        return _FakeResp(self._fn(val))


# ── taxonomy: no blank columns for anomaly categories ────────────────────────

ANOMALY_CATEGORIES = [
    "nosql_injection", "ldap_injection", "xpath_injection", "prototype_pollution",
    "integer_overflow", "format_string", "buffer_overflow", "resource_exhaustion",
    "version_regression", "ip_restriction_bypass",
    "websocket_hijacking", "websocket_cleartext",
]


@pytest.mark.parametrize("category", ANOMALY_CATEGORIES)
def test_anomaly_category_has_full_taxonomy(category):
    f = enrich_finding({"vuln_type": category, "severity": "high", "target": "http://t/"})
    assert f.get("cwe", "").startswith("CWE-"), f"{category} blank CWE"
    assert f.get("owasp", ""), f"{category} blank OWASP"
    assert f.get("mitre_technique", ""), f"{category} blank MITRE"
    assert f.get("cvss_vector", "").startswith("CVSS:3.1/"), f"{category} blank CVSS vector"


def test_injection_categories_bucket_to_owasp_injection():
    for c in ("nosql_injection", "ldap_injection", "xpath_injection", "format_string"):
        f = enrich_finding({"vuln_type": c, "severity": "high"})
        assert "Injection" in f["owasp"], f"{c} -> {f['owasp']}"


# ── XPath injection detector ─────────────────────────────────────────────────

def _run_xpath(fn):
    p = WebAnomalyProbe(timeout=2)
    return asyncio.run(p._test_xpath_injection(_ReqSession(fn), "http://t/", "id", "GET"))


def test_xpath_error_based_detected():
    def fn(val):
        if val in ("'", "']", "' or '", "count(//*)", "']|//*|/x['"):
            return "<html>javax.xml.xpath.XPathException: A closing quote expected</html>"
        return f"<html>page {val}</html>"
    c = _run_xpath(fn)
    assert c and c.category == "xpath_injection" and c.technique == "xpath_error_based"
    assert c.cwe_id == "CWE-643"


def test_xpath_boolean_differential_detected():
    def fn(val):
        if val == "x' or '1'='1":
            return "<rows>" + "R" * 900 + "</rows>"
        if val == "x' or '1'='2":
            return "<rows></rows>"
        return "<rows>" + "R" * 100 + "</rows>"
    c = _run_xpath(fn)
    assert c and c.category == "xpath_injection"
    assert c.technique == "xpath_boolean_differential"


def test_xpath_benign_no_false_positive():
    # Parameter is ignored: identical static page every time.
    c = _run_xpath(lambda val: "<html>Static content. Param ignored.</html>")
    assert c is None


# ── WebSocket detector ───────────────────────────────────────────────────────

class _WSResp(_FakeResp):
    pass


class _WSSession:
    def __init__(self, body, set_cookie=False, ws_accepts=True):
        self._body = body
        self._cookie = set_cookie
        self._accepts = ws_accepts

    def get(self, url, **kw):
        h = {"Set-Cookie": "sid=abc; HttpOnly"} if self._cookie else {}
        return _WSResp(self._body, h)

    async def ws_connect(self, url, headers=None, **kw):
        if self._accepts:
            class _WS:
                async def close(self):
                    return None
            return _WS()
        raise ConnectionError("403 Origin rejected")


def _run_ws(session):
    p = WebAnomalyProbe(timeout=2)
    return asyncio.run(p._test_websocket(session, "https://target.tld/app"))


def _cats(cands):
    return sorted(c.category for c in cands)


def test_websocket_cleartext_flagged():
    c = _run_ws(_WSSession('<script>new WebSocket("ws://target.tld/live")</script>'))
    assert _cats(c) == ["websocket_cleartext"]


def test_websocket_cswsh_flagged_when_cookie_auth_and_origin_open():
    c = _run_ws(_WSSession('new WebSocket("wss://target.tld/ws")',
                           set_cookie=True, ws_accepts=True))
    assert _cats(c) == ["websocket_hijacking"]
    assert c[0].cwe_id == "CWE-1385"


def test_websocket_cookieless_no_cswsh():
    # Origin ignored but no cookie auth → not exploitable → not reported.
    c = _run_ws(_WSSession('new WebSocket("wss://target.tld/ws")',
                           set_cookie=False, ws_accepts=True))
    assert _cats(c) == []


def test_websocket_origin_validated_no_cswsh():
    # Cookie auth but the server rejects the foreign Origin → correct handling.
    c = _run_ws(_WSSession('new WebSocket("wss://target.tld/ws")',
                           set_cookie=True, ws_accepts=False))
    assert _cats(c) == []


def test_websocket_third_party_out_of_scope():
    c = _run_ws(_WSSession('connect("ws://evil-cdn.example/rt")'))
    assert _cats(c) == []


# ── XSS execution prover ─────────────────────────────────────────────────────

def test_xss_prover_unauthorized_refuses():
    r = asyncio.run(XSSExecutionProver(authorized=False).prove("http://t/", "q"))
    assert r.proved is False and "not authorized" in r.notes


def test_xss_prover_without_playwright_gives_install_hint(monkeypatch):
    # Ensure the import fails even if Playwright happens to be installed.
    monkeypatch.setitem(sys.modules, "playwright", None)
    r = asyncio.run(XSSExecutionProver(authorized=True).prove("http://t/", "q"))
    assert r.proved is False
    assert "Playwright not installed" in r.notes


# --- mock Playwright: simulates a headless browser that "runs" alert() ---

def _install_mock_playwright(monkeypatch, *, vulnerable: bool):
    from urllib.parse import unquote
    import re as _re

    class _Dialog:
        def __init__(self, message):
            self.message = message

        async def dismiss(self):
            return None

    class _Page:
        def __init__(self):
            self._handler = None

        def on(self, event, handler):
            if event == "dialog":
                self._handler = handler

        async def _maybe_fire(self, content):
            if not vulnerable or self._handler is None:
                return
            # Mirror the real browser: URL-decode the GET query and HTML-unescape
            # the POST form value (the browser decodes &#x27; back to ' before it
            # submits, then the vulnerable server reflects it verbatim).
            import html as _html
            decoded = _html.unescape(unquote(content))
            m = _re.search(r"alert\('([^']+)'\)", decoded)
            if m:
                await self._handler(_Dialog(m.group(1)))

        async def goto(self, url, **kw):
            await self._maybe_fire(url)

        async def set_content(self, html, **kw):
            await self._maybe_fire(html)

        async def wait_for_timeout(self, ms):
            return None

        async def close(self):
            return None

    class _Context:
        async def new_page(self):
            return _Page()

    class _Browser:
        async def new_context(self, **kw):
            return _Context()

        async def close(self):
            return None

    class _Chromium:
        async def launch(self, **kw):
            return _Browser()

    class _PW:
        def __init__(self):
            self.chromium = _Chromium()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    mod = types.ModuleType("playwright.async_api")
    mod.async_playwright = lambda: _PW()
    pkg = types.ModuleType("playwright")
    pkg.async_api = mod
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", mod)


def test_xss_prover_confirms_execution_in_browser(monkeypatch):
    _install_mock_playwright(monkeypatch, vulnerable=True)
    r = asyncio.run(XSSExecutionProver(authorized=True).prove(
        "http://vuln.tld/echo", "q", method="GET"))
    assert r.proved is True
    assert r.technique == "xss_dom_execution"
    assert r.evidence["signals"] == ["javascript_executed_in_browser"]
    assert r.evidence["token"] in r.evidence["dialog_message"]


def test_xss_prover_benign_target_not_proved(monkeypatch):
    _install_mock_playwright(monkeypatch, vulnerable=False)
    r = asyncio.run(XSSExecutionProver(authorized=True).prove(
        "http://safe.tld/echo", "q", method="GET"))
    assert r.proved is False
    assert r.technique == "xss_dom_execution"


def test_xss_prover_post_path_confirms(monkeypatch):
    _install_mock_playwright(monkeypatch, vulnerable=True)
    r = asyncio.run(XSSExecutionProver(authorized=True).prove(
        "http://vuln.tld/comment", "body", method="POST"))
    assert r.proved is True
