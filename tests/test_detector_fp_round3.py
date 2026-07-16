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
    def __init__(self, status=200, text="", json_data=None):
        self.status = status
        self._text = text
        self._json = json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._text

    async def json(self, *a, **k):
        if self._json is None:
            raise ValueError("response is not JSON")
        return self._json


class _FakeSession:
    """`session.get/post/put(...)` return an async-context-manager response,
    exactly like aiohttp — so the scanner code path is exercised unchanged."""

    def __init__(self, *, get_text="", get_status=200,
                 put_status=200, put_json=None, post_status=200):
        self._get_text, self._get_status = get_text, get_status
        self._put_status, self._put_json = put_status, put_json
        self._post_status = post_status

    def get(self, url, **kw):
        return _FakeResp(self._get_status, text=self._get_text)

    def put(self, url, **kw):
        return _FakeResp(self._put_status, json_data=self._put_json)

    def post(self, url, **kw):
        return _FakeResp(self._post_status)


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
    findings = await api.RESTAPIScanner.test_rate_limiting(
        _FakeSession(post_status=200), "http://t")
    assert findings and findings[0].vuln_type == "no_rate_limit"


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
    monkeypatch.setattr(ij, "SQLI_TIME_PROBES", [("' AND SLEEP(1)-- ", 0.3, "sleep")])
    monkeypatch.setattr(ij, "SQLI_ERROR_PROBES", [])

    async def cond_post(session, url, data, headers=None, timeout=10.0):
        # only the SLEEP payload is slow → genuine time-based oracle
        if "SLEEP" in str(data.get("q", "")):
            await asyncio.sleep(0.4)
        else:
            await asyncio.sleep(0.02)
        return 200, "<html>ok</html>"

    monkeypatch.setattr(ij, "_post", cond_post)
    sc = ij.InjectionScanner()
    await sc._test_sqli_post(object(), "http://t/x", "q", "<html>ok</html>", {})
    assert any(f["vuln_type"] == "sqli" for f in sc._findings)
