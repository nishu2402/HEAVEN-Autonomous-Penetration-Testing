"""Regression tests for the OWASP-WSTG "all-AUTO" reconciliation.

The OWASP Testing Guide methodology page is data-driven: every technical WSTG
test now names a real, confirmation-based detector (only Business Logic remains
analyst-led). These tests lock in three things so the page can never silently
regress to the old under-mapped state:

1. The doc classifies all 86 technical rows as automated, 0 manual.
2. `VULN_MODULE` maps the real detector-emitted vuln_types to their module
   token, so a finding lights the right WSTG row.
3. The new detectors (client_audit static analysis, misconfig/auth/web_fuzzer
   probes) fire on real signals and stay silent on clean content, and each new
   vuln_type carries non-blank OWASP/CWE taxonomy.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven import methodology as M
from heaven.devsecops.vuln_kb import enrich_finding
from heaven.devsecops.frameworks import normalize_owasp

pytest.importorskip("aiohttp")


# ── 1. Doc classification: all technical rows AUTO, only BUSL analyst-led ──────
def test_owasp_wstg_is_fully_automated() -> None:
    owasp = next(s for s in M.load_standards() if s["name"] == "owasp_testing_guide")
    summ = owasp["summary"]
    assert summ["total"] == 86
    assert summ["automated"] == 86
    assert summ["partial"] == 0
    assert summ["manual"] == 0
    # Business Logic stays a prose note (analyst-led) — not fabricated as AUTO.
    busl = next((c for c in owasp["categories"] if c["code"] == "BUSL"), None)
    assert busl is not None and busl["rows"] == []
    assert "analyst-led" in busl["note"].lower()


def test_previously_manual_rows_now_name_a_real_detector() -> None:
    owasp = next(s for s in M.load_standards() if s["name"] == "owasp_testing_guide")
    rows = {r["id"]: r for c in owasp["categories"] for r in c["rows"]}
    # A representative sample of formerly (manual)/partial rows.
    for rid, token in [
        ("WSTG-INFO-05", "client_audit"),
        ("WSTG-CONF-06", "web_fuzzer"),
        ("WSTG-CONF-08", "misconfig_scanner"),
        ("WSTG-ATHN-05", "misconfig_scanner"),
        ("WSTG-ATHZ-02", "web_fuzzer"),
        ("WSTG-SESS-03", "auth_scanner"),
        ("WSTG-SESS-04", "misconfig_scanner"),
        ("WSTG-INPV-08", "web_fuzzer"),
        ("WSTG-INPV-09", "anomaly_probe"),
        ("WSTG-CRYP-02", "misconfig_scanner"),
        ("WSTG-CLNT-09", "misconfig_scanner"),
        ("WSTG-CLNT-11", "client_audit"),
        ("WSTG-CLNT-12", "client_audit"),
    ]:
        assert rows[rid]["status"] == "automated", f"{rid} not AUTO"
        assert token in rows[rid]["coverage"], f"{rid} does not name {token}"


# ── 2. VULN_MODULE maps real emitters to module tokens ────────────────────────
def test_real_detector_tokens_are_mapped() -> None:
    cases = {
        # web_fuzzer
        "dangerous_http_method": "web_fuzzer",
        "http_parameter_pollution": "web_fuzzer",
        "403_bypass_ip_header": "web_fuzzer",
        "ssi_injection": "web_fuzzer",
        # misconfig_scanner
        "cors_misconfig": "misconfig_scanner",
        "clickjacking": "misconfig_scanner",
        "permissive_crossdomain_policy": "misconfig_scanner",
        "session_token_in_url": "misconfig_scanner",
        "padding_oracle": "misconfig_scanner",
        # auth_scanner
        "session_fixation": "auth_scanner",
        "weak_session_id": "auth_scanner",
        "open_registration": "auth_scanner",
        # anomaly_probe
        "xpath_injection": "anomaly_probe",
        "ldap_injection": "anomaly_probe",
        "websocket_hijacking": "anomaly_probe",
        # client_audit
        "dom_xss_sink": "client_audit",
        "insecure_postmessage": "client_audit",
        "sensitive_browser_storage": "client_audit",
        # injection stored XSS
        "xss_stored": "injection_scanner",
    }
    for vt, token in cases.items():
        assert token in M.modules_for_vuln(vt), f"{vt} → missing {token}"


def test_overlay_lights_formerly_manual_rows_on_real_findings() -> None:
    findings = [{"vuln_type": vt} for vt in (
        "clickjacking", "session_token_in_url", "xpath_injection",
        "dangerous_http_method", "dom_xss_sink", "session_fixation",
        "permissive_crossdomain_policy", "ssi_injection",
    )]
    built = M.build(findings)
    owasp = next(s for s in built["standards"] if s["name"] == "owasp_testing_guide")
    rows = {r["id"]: r for c in owasp["categories"] for r in c["rows"]}
    for rid in ("WSTG-CLNT-09", "WSTG-SESS-04", "WSTG-INPV-09", "WSTG-CONF-06",
                "WSTG-CLNT-01", "WSTG-SESS-03", "WSTG-CONF-08", "WSTG-INPV-08"):
        assert rows[rid]["exercised"] is True, f"{rid} did not light"


# ── 3a. New vuln_types carry non-blank OWASP/CWE taxonomy ──────────────────────
@pytest.mark.parametrize("vt", [
    "source_comment_disclosure", "dom_xss_sink", "insecure_postmessage",
    "sensitive_browser_storage", "cross_site_script_inclusion", "css_injection",
    "client_resource_manipulation", "flash_crossdomain",
    "permissive_crossdomain_policy", "password_autocomplete_enabled",
    "sensitive_cache_control", "session_token_in_url", "long_session_timeout",
    "padding_oracle", "ssi_injection", "smtp_header_injection",
    "open_registration", "security_question_reset", "alt_channel_auth_weakness",
])
def test_new_slugs_have_full_taxonomy(vt: str) -> None:
    e = enrich_finding({"vuln_type": vt, "target": "http://t", "severity": "medium",
                        "title": "x"})
    assert e.get("owasp"), f"{vt} has blank OWASP"
    assert e.get("cwe"), f"{vt} has blank CWE"
    assert normalize_owasp(e["owasp"]), f"{vt} OWASP does not normalize"


# ── 3b. client_audit static analysis: positive + negative ─────────────────────
def test_client_audit_source_review_positive_and_negative() -> None:
    from heaven.vulnscan import client_audit as C
    leaky = ('<html><!-- TODO remove hardcoded admin password before ship -->'
             '<!-- db 192.168.1.5 password="Sup3rSecret" --></html>')
    hits = C._review_source("http://t", leaky)
    assert hits and hits[0]["vuln_type"] == "source_comment_disclosure"
    # Clean page → nothing.
    assert C._review_source("http://t", "<html><p>Welcome</p></html>") == []


def test_client_audit_js_sink_analysis_positive_and_negative() -> None:
    from heaven.vulnscan import client_audit as C
    dangerous = ("var x = location.hash; el.innerHTML = x; img.src = location.search;"
                 "window.addEventListener('message', function(e){use(e.data)});"
                 "localStorage.setItem('authToken', t);")
    vts = {f["vuln_type"] for f in C._analyse_js("http://t", dangerous, "inline")}
    assert {"dom_xss_sink", "client_resource_manipulation",
            "insecure_postmessage", "sensitive_browser_storage"} <= vts
    # Benign JS → nothing.
    assert C._analyse_js("http://t", "var a = 1 + 2; console.log(a);", "inline") == []


def test_client_audit_postmessage_with_origin_check_is_silent() -> None:
    from heaven.vulnscan import client_audit as C
    safe = ("window.addEventListener('message', function(e){"
            "if (e.origin !== 'https://trusted.example') return; use(e.data);});")
    vts = {f["vuln_type"] for f in C._analyse_js("http://t", safe, "inline")}
    assert "insecure_postmessage" not in vts


# ── 3c. async end-to-end via a fake aiohttp session (no network) ──────────────
class _FakeHeaders(dict):
    def getall(self, key, default=None):
        v = self.get(key)
        return [v] if v is not None else (default or [])


class _FakeResp:
    def __init__(self, status=200, headers=None, body="", content_type="text/html"):
        self.status = status
        self.headers = _FakeHeaders(headers or {})
        self._body = body
        self.content_type = content_type

    async def __aenter__(self):
        return self

    async def __aexit__(self, *e):
        return False

    async def text(self, errors="strict"):
        return self._body


class _FakeSession:
    def __init__(self, resp: _FakeResp):
        self._resp = resp

    def get(self, url, **kw):
        return self._resp


def test_misconfig_clickjacking_fires_when_framable() -> None:
    from heaven.vulnscan import misconfig_scanner as MS
    # HTML 200 with NO X-Frame-Options and NO CSP frame-ancestors → framable.
    resp = _FakeResp(status=200, headers={}, body="<html></html>",
                     content_type="text/html")
    out = asyncio.run(MS._check_clickjacking(_FakeSession(resp), "http://t/"))
    assert out and out[0]["vuln_type"] == "clickjacking"
    # With X-Frame-Options: DENY → silent.
    resp2 = _FakeResp(status=200, headers={"X-Frame-Options": "DENY"},
                      body="<html></html>", content_type="text/html")
    assert asyncio.run(MS._check_clickjacking(_FakeSession(resp2), "http://t/")) == []


def test_misconfig_login_form_autocomplete_and_cache() -> None:
    from heaven.vulnscan import misconfig_scanner as MS
    body = '<form><input type="password" name="pw"></form>'
    resp = _FakeResp(status=200, headers={}, body=body, content_type="text/html")
    vts = {f["vuln_type"] for f in
           asyncio.run(MS._check_login_form(_FakeSession(resp), "http://t/login"))}
    assert "password_autocomplete_enabled" in vts
    assert "sensitive_cache_control" in vts
    # A page with no password field asserts nothing.
    clean = _FakeResp(status=200, headers={}, body="<p>hi</p>", content_type="text/html")
    assert asyncio.run(MS._check_login_form(_FakeSession(clean), "http://t/")) == []
