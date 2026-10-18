"""Round-3 false-positive regression tests for the live WEB/API-mode detectors.

Each test pins a concrete FP path that the deep-audit pass closed:

API scanner (``heaven/vulnscan/api_scanner.py``)
  * ``test_api_key_leakage`` no longer reports a normal session/CSRF *token* in a
    response, nor a placeholder ``api_key`` value, as a leaked credential — but a
    real provider key (AWS ``AKIA…``) and a real-looking generic secret still fire.
  * ``test_rate_limiting`` no longer flags an endpoint that does not exist
    (all-404) as "no rate limiting".
  * ``test_mass_assignment`` requires the injected *value* to round-trip, not just
    the field name (a normal profile object legitimately has a ``role`` field).

Injection scanner (``heaven/vulnscan/injection_scanner.py``)
  * header-injection XSS requires an *executable* reflection, not the bare canary.
  * POST time-based SQLi uses a baseline + reproduce guard, so a uniformly slow
    POST endpoint is not flagged.
"""

from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import api_scanner as api
from heaven.vulnscan import injection_scanner as ij


# ── minimal fake aiohttp session ──────────────────────────────────────────────

class _FakeResp:
    def __init__(self, status=200, text="", json_data=None, headers=None):
        self.status = status
        self._text = text
        self._json = json_data
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._text

    async def read(self, *a, **k):
        return self._text.encode()

    async def json(self, *a, **k):
        if self._json is None:
            raise ValueError("response is not JSON")
        return self._json


class _FakeSession:
    """`session.get/post/put(...)` return an async-context-manager response,
    exactly like aiohttp — so the scanner code path is exercised unchanged.

    ``post`` is URL-aware so the rate-limit catch-all guard can be exercised: the
    guard first probes a random ``/api/login-<hex>`` sibling that must NOT exist,
    then the real ``/api/login``. ``catch_all=True`` makes every path (sibling
    included) answer identically — the shared-hosting / SPA shell behaviour that
    previously produced a bogus ``no_rate_limit`` on every guessed API path."""

    def __init__(self, *, get_text="", get_status=200,
                 put_status=200, put_json=None, post_status=200,
                 post_ctype="application/json", post_text="", catch_all=False):
        self._get_text, self._get_status = get_text, get_status
        self._put_status, self._put_json = put_status, put_json
        self._post_status = post_status
        self._post_ctype = post_ctype
        self._post_text = post_text
        self._catch_all = catch_all

    def get(self, url, **kw):
        return _FakeResp(self._get_status, text=self._get_text)

    def put(self, url, **kw):
        return _FakeResp(self._put_status, json_data=self._put_json)

    def post(self, url, **kw):
        # Random non-existent sibling probed by the catch-all guard.
        if "/api/login-" in url and not self._catch_all:
            return _FakeResp(404, text="not found",
                             headers={"Content-Type": "application/json"})
        return _FakeResp(self._post_status, text=self._post_text,
                         headers={"Content-Type": self._post_ctype})


# ── pure-helper unit checks ───────────────────────────────────────────────────

def test_looks_like_real_secret_rejects_placeholders():
    assert not api._looks_like_real_secret("your_api_key_here_xxxxxx")
    assert not api._looks_like_real_secret("EXAMPLE_SECRET_VALUE_1234")
    assert not api._looks_like_real_secret("aaaaaaaaaaaaaaaaaaaaaa")   # low variety
    assert not api._looks_like_real_secret("short")                    # too short
    assert api._looks_like_real_secret("a1B2c3D4e5F6g7H8i9J0k1L2")     # real-looking


def test_value_reflected_requires_the_injected_value():
    # field name present but a DIFFERENT value → not reflected
    assert not api._value_reflected({"role": "user"}, "role", "admin")
    # injected value round-trips (flat and nested)
    assert api._value_reflected({"role": "admin"}, "role", "admin")
    assert api._value_reflected({"user": {"is_admin": True}}, "is_admin", True)


# ── api_key_leakage FP fixes ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_token_in_response_is_not_reported_as_key_leak():
    # a login response returning an auth/CSRF token is NORMAL, not a leak
    body = '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payloadpayloadpayload.sig"}'
    findings = await api.RESTAPIScanner.test_api_key_leakage(
        _FakeSession(get_text=body), "http://t")
    assert findings == [], "a session/CSRF token must not be a key-leak finding"


@pytest.mark.asyncio
async def test_placeholder_api_key_is_not_reported():
    body = 'api_key = "your_api_key_here_replace_me"'
    findings = await api.RESTAPIScanner.test_api_key_leakage(
        _FakeSession(get_text=body), "http://t")
    assert findings == [], "a placeholder api_key must not be reported"


@pytest.mark.asyncio
async def test_real_aws_key_is_critical():
    body = '{"config":{"aws":"AKIAIOSFODNN7EXAMPLE"}}'
    findings = await api.RESTAPIScanner.test_api_key_leakage(
        _FakeSession(get_text=body), "http://t")
    assert findings and findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_real_generic_secret_is_medium_verify():
    body = 'client_secret: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"'
    findings = await api.RESTAPIScanner.test_api_key_leakage(
        _FakeSession(get_text=body), "http://t")
    assert findings and findings[0].severity == "medium"
    assert findings[0].confidence <= 0.6


# ── rate-limiting FP fix ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_endpoint_is_not_no_rate_limit():
    findings = await api.RESTAPIScanner.test_rate_limiting(
        _FakeSession(post_status=404), "http://t")
    assert findings == [], "an all-404 endpoint is not evidence of missing rate limiting"


@pytest.mark.asyncio
async def test_live_unlimited_endpoint_flags_no_rate_limit():
    # A real JSON login API (distinguishable from a non-existent sibling) that
    # processes 50 POSTs with no 429 still fires.
    findings = await api.RESTAPIScanner.test_rate_limiting(
        _FakeSession(post_status=200, post_ctype="application/json"), "http://t")
    assert findings and findings[0].vuln_type == "no_rate_limit"


@pytest.mark.asyncio
async def test_html_catch_all_is_not_no_rate_limit():
    # Shared hosting / SPA / parked domain: every path (incl. /api/login) returns
    # the same 200 HTML shell. That is not a live login API, so the 50 "processed"
    # 200s must NOT be read as "no rate limiting" (observed live on a cPanel host
    # that returned its homepage for every guessed /api, /graphql, /v1 ... path).
    findings = await api.RESTAPIScanner.test_rate_limiting(
        _FakeSession(post_status=200, post_ctype="text/html",
                     post_text="<!doctype html><html>home</html>",
                     catch_all=True),
        "http://t")
    assert findings == [], "an HTML catch-all is not evidence of a missing rate limiter"


@pytest.mark.asyncio
async def test_json_catch_all_sibling_match_is_not_no_rate_limit():
    # Even a JSON catch-all that answers a non-existent /api/login-<rand> sibling
    # identically to /api/login is not a confirmed endpoint — suppress.
    findings = await api.RESTAPIScanner.test_rate_limiting(
        _FakeSession(post_status=200, post_ctype="application/json",
                     post_text='{"ok":true}', catch_all=True),
        "http://t")
    assert findings == [], "an indistinguishable sibling means no confirmed login endpoint"


# ── mass-assignment FP fix ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_field_name_echo_is_not_mass_assignment():
    # response contains a 'role' field but keeps the value 'user' → NOT accepted
    findings = await api.RESTAPIScanner.test_mass_assignment(
        _FakeSession(put_status=200, put_json={"role": "user", "active": True}), "http://t")
    assert findings == [], "field-name presence alone must not be mass assignment"


@pytest.mark.asyncio
async def test_accepted_privileged_value_is_mass_assignment():
    findings = await api.RESTAPIScanner.test_mass_assignment(
        _FakeSession(put_status=200, put_json={"role": "admin"}), "http://t")
    assert findings and findings[0].vuln_type == "mass_assignment"


# ── header-injection XSS FP fix ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_escaped_header_reflection_is_not_xss(monkeypatch):
    async def fake_get(session, url, headers=None, timeout=8.0):
        payload = (headers or {}).get("X-Forwarded-For", "") or next(
            (v for v in (headers or {}).values() if ij._XSS_CANARY in v), "")
        # server reflects the header but HTML-escapes it → canary present, inert
        escaped = (payload.replace("<", "&lt;").replace(">", "&gt;")
                          .replace('"', "&quot;"))
        return 200, f"<p>Your header: {escaped}</p>"

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_header_injection(object(), "http://t/")
    assert sc._findings == [], "an escaped header reflection must not be flagged XSS"


@pytest.mark.asyncio
async def test_raw_header_reflection_is_xss(monkeypatch):
    async def fake_get(session, url, headers=None, timeout=8.0):
        payload = next((v for v in (headers or {}).values() if ij._XSS_CANARY in v), "")
        return 200, f"<p>Your header: {payload}</p>"   # reflected raw → executable

    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_header_injection(object(), "http://t/")
    assert any(f["vuln_type"] == "xss" for f in sc._findings)


# ── POST time-based SQLi FP fix ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_uniformly_slow_post_is_not_time_based_sqli(monkeypatch):
    # Tiny probe so the test is fast; error-based phase disabled to isolate timing.
    monkeypatch.setattr(ij, "SQLI_TIME_PROBES", [("' AND SLEEP(1)-- ", 0.3, "sleep")])
    monkeypatch.setattr(ij, "SQLI_ERROR_PROBES", [])

    async def slow_post(session, url, data, headers=None, timeout=10.0):
        await asyncio.sleep(0.3)      # EVERY request is slow (natural latency)
        return 200, "<html>ok</html>"

    monkeypatch.setattr(ij, "_post", slow_post)
    sc = ij.InjectionScanner()
    await sc._test_sqli_post(object(), "http://t/x", "q", "<html>ok</html>", {})
    assert sc._findings == [], "a uniformly slow endpoint must not be flagged as SQLi"


@pytest.mark.asyncio
async def test_injectable_post_is_time_based_sqli(monkeypatch):
    # A genuine time-based oracle: the delay SCALES with the injected SLEEP value
    # (SLEEP(0.5) → 0.5s, and the scanner's double-the-sleep confirmation turns it
    # into SLEEP(1.0) → 1.0s). The probe's sleep_secs matches the value embedded in
    # the payload so the doubling substitution works, exactly as in production.
    import re as _re

    monkeypatch.setattr(ij, "SQLI_TIME_PROBES", [("' AND SLEEP(0.5)-- ", 0.5, "sleep")])
    monkeypatch.setattr(ij, "SQLI_ERROR_PROBES", [])

    async def cond_post(session, url, data, headers=None, timeout=10.0):
        m = _re.search(r"SLEEP\(([\d.]+)\)", str(data.get("q", "")))
        await asyncio.sleep(float(m.group(1)) if m else 0.02)  # delay scales with SLEEP(n)
        return 200, "<html>ok</html>"

    monkeypatch.setattr(ij, "_post", cond_post)
    sc = ij.InjectionScanner()
    await sc._test_sqli_post(object(), "http://t/x", "q", "<html>ok</html>", {})
    assert any(f["vuln_type"] == "sqli" for f in sc._findings)
