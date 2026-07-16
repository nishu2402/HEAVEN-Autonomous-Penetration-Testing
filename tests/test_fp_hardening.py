"""Tests for the false-positive hardening pass.

Three independent guarantees:
  * apply_verdict honours the "strong needs two independent signals" contract and
    never reports an unsubstantiated finding as high-confidence;
  * boolean-blind SQLi is only reported when the oracle *reproduces* on a second
    round (the fix for the live DVWA false positives);
  * GraphQL introspection is confirmation-based (a real schema must come back).
"""
from __future__ import annotations

from urllib.parse import unquote

import pytest

from heaven.vulnscan.fp_suppress import SuppressionVerdict, apply_verdict


# ── apply_verdict calibration floors ─────────────────────────────────────────

def test_strong_capped_to_high_with_single_signal():
    f = {"vuln_type": "sqli", "evidence": {"signals": ["time_diff"]}}
    v = SuppressionVerdict(keep=True, final_confidence=0.97, bucket="strong",
                           reasons=["time_diff_reproducible_2/3"])
    apply_verdict(f, v)
    assert f["confidence"] == 0.94
    assert f["confidence_bucket"] == "high"
    assert any("capped_at_high_single_signal" in r for r in f["fp_check_reasons"])


def test_strong_allowed_with_two_independent_signals():
    f = {"vuln_type": "sqli", "evidence": {"signals": ["error_based", "union"]}}
    v = SuppressionVerdict(keep=True, final_confidence=0.97, bucket="strong",
                           reasons=["error_only_on_payload_strong_signal"])
    apply_verdict(f, v)
    assert f["confidence"] == 0.97
    assert f["confidence_bucket"] == "strong"


def test_strong_allowed_with_definitive_oob_proof():
    f = {"vuln_type": "ssrf", "evidence": {"oob_callback_received": True}}
    v = SuppressionVerdict(keep=True, final_confidence=0.98, bucket="strong",
                           reasons=["oob_callback_received"])
    apply_verdict(f, v)
    assert f["confidence"] == 0.98
    assert f["confidence_bucket"] == "strong"


def test_unproven_finding_capped_to_review():
    # No evidence, no confirming reason → never reported above "medium".
    f = {"vuln_type": "sqli"}
    v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high",
                           reasons=["some_unrelated_note"])
    apply_verdict(f, v)
    assert f["confidence"] == 0.59
    assert any("no_proof_artifact" in r for r in f["fp_check_reasons"])


def test_finding_with_evidence_not_capped():
    f = {"vuln_type": "sqli", "evidence": {"payload": "1' OR '1'='1"}}
    v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high",
                           reasons=["note"])
    apply_verdict(f, v)
    assert f["confidence"] == 0.85


def test_suppressed_finding_left_alone():
    f = {"vuln_type": "sqli"}
    v = SuppressionVerdict(keep=False, final_confidence=0.2, bucket="discarded")
    apply_verdict(f, v)
    assert f["confidence"] == 0.2
    assert f["suppressed"] is True


# ── boolean-blind SQLi co-confirmation ───────────────────────────────────────

_CHROME = "<html><head><title>App</title></head><body>" + ("x" * 4000)
_FOOT = ("y" * 400) + "</body></html>"


def _page(body: str) -> str:
    return _CHROME + body + _FOOT


_ROW = _page("<pre>First name: admin\nSurname: admin</pre>")
_EMPTY = _page("")


@pytest.mark.asyncio
async def test_boolean_sqli_reported_when_reproduced(monkeypatch):
    import heaven.vulnscan.injection_scanner as inj

    async def fake_get(session, url, headers=None, timeout=8.0):
        # TRUE condition (1=1) returns the row; FALSE (1=2) hides it — every time.
        return 200, (_ROW if "1=1" in unquote(url) else _EMPTY)

    monkeypatch.setattr(inj, "_get", fake_get)
    scanner = inj.InjectionScanner()
    await scanner._test_sqli_boolean_param(None, "http://t/x?id=1", "id", _ROW)

    assert len(scanner._findings) == 1
    ev = scanner._findings[0]["evidence"]
    assert ev["reproduced"] is True
    assert "boolean_oracle_reproduced" in ev["signals"]


@pytest.mark.asyncio
async def test_boolean_sqli_suppressed_when_not_reproduced(monkeypatch):
    import heaven.vulnscan.injection_scanner as inj
    calls = {"n": 0}

    async def flaky_get(session, url, headers=None, timeout=8.0):
        # TRUE returns the row on the first round but not the second → a dynamic
        # page that differed once by chance. Must NOT be reported.
        calls["n"] += 1
        if "1=1" in unquote(url):
            return 200, (_ROW if calls["n"] <= 2 else _EMPTY)
        return 200, _EMPTY

    monkeypatch.setattr(inj, "_get", flaky_get)
    scanner = inj.InjectionScanner()
    await scanner._test_sqli_boolean_param(None, "http://t/x?id=1", "id", _ROW)

    assert scanner._findings == []


# ── GraphQL introspection detection ──────────────────────────────────────────

class _FakeResp:
    def __init__(self, status, body, ctype="application/json"):
        self.status = status
        self._body = body
        self.headers = {"Content-Type": ctype}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._body


class _FakeSession:
    def __init__(self, responder):
        self._responder = responder

    def post(self, url, **kwargs):
        return self._responder(url)


@pytest.mark.asyncio
async def test_graphql_introspection_detected():
    from heaven.vulnscan.misconfig_scanner import _check_graphql

    schema = ('{"data":{"__schema":{"queryType":{"name":"Query"},'
              '"types":[{"name":"User"},{"name":"Query"}]}}}')

    def responder(url):
        if url.endswith("/graphql"):
            return _FakeResp(200, schema)
        return _FakeResp(404, "not found", ctype="text/html")

    findings = await _check_graphql(_FakeSession(responder), "http://target")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "graphql_introspection"
    assert findings[0]["evidence"]["type_count"] == 2


@pytest.mark.asyncio
async def test_graphql_no_false_positive_when_disabled():
    from heaven.vulnscan.misconfig_scanner import _check_graphql

    def responder(url):
        # Endpoint exists but rejects introspection (no __schema in the reply).
        return _FakeResp(200, '{"errors":[{"message":"introspection disabled"}]}')

    findings = await _check_graphql(_FakeSession(responder), "http://target")
    assert findings == []


# ── Suppression actually takes effect (dedup chokepoint) ─────────────────────
# A finding the FP layer rejected must never survive via its raw candidate copy.

def test_dedup_purges_suppressed_identity_and_its_raw_candidate():
    from heaven.engagement import dedup_findings

    raw = {"target": "http://t/x?id=1", "vuln_type": "sqli", "param": "",
           "confidence": 0.8, "evidence": {"payload": "1' OR 1=1"}}
    verdict = {"target": "http://t/x?id=1", "vuln_type": "sqli", "param": "",
               "confidence": 0.2, "suppressed": True, "result": "false_positive",
               "fp_check_reasons": ["time_diff_not_reproducible"]}

    # Both orderings: the whole identity is purged, raw candidate included.
    assert dedup_findings([raw, verdict]) == []
    assert dedup_findings([verdict, raw]) == []


def test_dedup_keeps_clean_finding():
    from heaven.engagement import dedup_findings
    clean = {"target": "http://t/a", "vuln_type": "xss", "param": "q",
             "confidence": 0.9, "evidence": {"canary": "h3av3n"}}
    assert len(dedup_findings([clean])) == 1


def test_richer_finding_prefers_reviewed_over_higher_raw_confidence():
    from heaven.engagement import _richer_finding
    raw = {"confidence": 0.9, "evidence": {"payload": "x"}}
    reviewed = {"confidence": 0.55, "confidence_bucket": "low",
                "fp_check_reasons": ["length_diff_inconclusive"]}
    # The adjudicated (lower) confidence wins — the downgrade is not reverted.
    assert _richer_finding(raw, reviewed) is reviewed
    assert _richer_finding(reviewed, raw) is reviewed


# ── SSL forward-secrecy false positive ───────────────────────────────────────

def _patch_ssl(monkeypatch, *, tls13, tls12, ciphers, hsts_enabled=True,
               hsts_max_age=63072000):
    import heaven.vulnscan.ssl_scanner as sslmod

    class _Sock:
        def close(self):
            pass

    monkeypatch.setattr(sslmod.socket, "create_connection", lambda *a, **k: _Sock())

    def fake_proto(host, port, minv, maxv, *a, **k):
        V = sslmod.ssl.TLSVersion
        if maxv == V.TLSv1_3:
            return tls13
        if maxv == V.TLSv1_2:
            return tls12
        return False

    monkeypatch.setattr(sslmod, "_check_protocol", fake_proto)
    monkeypatch.setattr(sslmod, "_probe_sslv3", lambda *a, **k: False)
    monkeypatch.setattr(sslmod, "_get_certificate", lambda *a, **k: None)
    monkeypatch.setattr(sslmod, "_check_heartbleed", lambda *a, **k: False)
    monkeypatch.setattr(sslmod, "_check_hsts",
                        lambda *a, **k: (hsts_enabled, hsts_max_age, True, True))
    monkeypatch.setattr(sslmod, "_get_ciphers", lambda *a, **k: (ciphers, []))
    return sslmod


def test_ssl_hsts_short_not_flagged_on_plain_http(monkeypatch):
    # A plain-HTTP port: the HTTPS HEAD never reaches a TLS listener, so
    # _check_hsts returns (False, 0, ...). The max_age=0 must NOT be reported as
    # "HSTS max-age too short" — HSTS is a TLS-only control and no header was
    # ever observed. (Regression: the elif branch was ungated and fired 0s.)
    sslmod = _patch_ssl(monkeypatch, tls13=False, tls12=False, ciphers=[],
                        hsts_enabled=False, hsts_max_age=0)
    res = sslmod._run_ssl_scan("t.example", 8091)
    types = {f["vuln_type"] for f in res.findings}
    assert "hsts_short_maxage" not in types
    assert "no_hsts" not in types


def test_ssl_hsts_short_flagged_with_tls(monkeypatch):
    # A real TLS server that DOES send HSTS but with a too-short max-age → the
    # true positive must still fire.
    sslmod = _patch_ssl(monkeypatch, tls13=False, tls12=True,
                        ciphers=["ECDHE-RSA-AES128-GCM-SHA256"],
                        hsts_enabled=True, hsts_max_age=3600)
    res = sslmod._run_ssl_scan("t.example", 443)
    assert "hsts_short_maxage" in {f["vuln_type"] for f in res.findings}


def test_ssl_no_forward_secrecy_not_flagged_on_tls13(monkeypatch):
    # A modern TLS-1.3-only server: set_ciphers() can't enumerate 1.3 suites, so
    # the ≤1.2 cipher list is empty. Must NOT be flagged "no forward secrecy".
    sslmod = _patch_ssl(monkeypatch, tls13=True, tls12=False, ciphers=[])
    res = sslmod._run_ssl_scan("t.example", 443)
    assert res.forward_secrecy is True
    assert "no_forward_secrecy" not in {f["vuln_type"] for f in res.findings}


def test_ssl_no_forward_secrecy_not_flagged_when_enumeration_empty(monkeypatch):
    # Enumeration produced nothing AND no protocol negotiated (transient failure)
    # → we can't assert absence of FS, and can't have observed HSTS either.
    sslmod = _patch_ssl(monkeypatch, tls13=False, tls12=False, ciphers=[],
                        hsts_enabled=False)
    res = sslmod._run_ssl_scan("t.example", 443)
    types = {f["vuln_type"] for f in res.findings}
    assert "no_forward_secrecy" not in types
    assert "no_hsts" not in types  # TLS never worked → HSTS unobservable


def test_ssl_no_forward_secrecy_still_flagged_on_static_rsa(monkeypatch):
    # A genuine 1.2-only server offering only static-RSA ciphers HAS no forward
    # secrecy — the true positive must survive the fix.
    sslmod = _patch_ssl(monkeypatch, tls13=False, tls12=True,
                        ciphers=["AES128-SHA", "AES256-SHA"])
    res = sslmod._run_ssl_scan("t.example", 443)
    assert res.forward_secrecy is False
    assert "no_forward_secrecy" in {f["vuln_type"] for f in res.findings}


# ── Header-injection precision (anomaly probe) ───────────────────────────────

class _HResp:
    def __init__(self, status=200, body="", headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *args, **kwargs):
        return self._body

    async def read(self, *args, **kwargs):
        return self._body.encode("utf-8", "replace")


class _HSession:
    """Fake aiohttp session dispatching on (url, headers) → _HResp."""
    def __init__(self, handler):
        self._handler = handler

    def get(self, url, headers=None, **kwargs):
        return self._handler(url, headers or {})

    def request(self, method, url, **kwargs):
        return self._handler(url, kwargs.get("headers") or {})


class _ParamSession:
    """Fake session whose handler sees the injected params/body — for probes that
    inject via ``params=`` / ``data=`` (SSTI, prototype pollution)."""
    def __init__(self, render):
        self._render = render  # render(inputs: dict) -> (status, body)

    def request(self, method, url, params=None, **kwargs):
        return _HResp(*self._render(params or {}))

    def get(self, url, params=None, **kwargs):
        return _HResp(*self._render(params or {}))

    def post(self, url, data=None, **kwargs):
        return _HResp(*self._render({"__body__": data}))


@pytest.mark.asyncio
async def test_host_header_injection_needs_reflection_not_just_diff():
    import uuid
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()

    # Dynamic page: body differs every request but the canary is never reflected.
    def noreflect(url, headers):
        return _HResp(200, f"<html>{uuid.uuid4().hex}</html>")

    cands = await probe._test_header_injection(_HSession(noreflect), "http://t/")
    assert all(c.category != "host_header_injection" for c in cands)

    # Canary host reflected into the body → genuine host-header injection.
    def reflect(url, headers):
        host = headers.get("Host") or headers.get("X-Forwarded-Host") or ""
        return _HResp(200, f'<a href="https://{host}/x">link</a>')

    cands = await probe._test_header_injection(_HSession(reflect), "http://t/")
    assert any(c.category == "host_header_injection" for c in cands)


@pytest.mark.asyncio
async def test_ip_restriction_bypass_needs_deny_to_allow():
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()
    _IP_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
                   "X-Custom-IP-Authorization")

    # Baseline 403; spoofed client IP flips it to 200 → real bypass.
    def bypass(url, headers):
        if any(h in headers for h in _IP_HEADERS):
            return _HResp(200, "ok")
        return _HResp(403, "forbidden")

    cands = await probe._test_header_injection(_HSession(bypass), "http://t/")
    assert any(c.category == "ip_restriction_bypass" for c in cands)

    # Baseline 200; an X-header merely triggers a redirect → NOT a bypass.
    def redirect(url, headers):
        if any(h in headers for h in _IP_HEADERS):
            return _HResp(301, "", {"Location": "/elsewhere"})
        return _HResp(200, "home")

    cands = await probe._test_header_injection(_HSession(redirect), "http://t/")
    assert all(c.category != "ip_restriction_bypass" for c in cands)


# ── Auth-scanner false positives ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oauth_pkce_not_enforced_no_longer_emitted():
    from heaven.vulnscan.auth_scanner import _audit_oauth

    # Generic app: every OAuth path 302-redirects to /login (no OAuth behaviour).
    def handler(url, headers):
        return _HResp(302, "", {"Location": "/login"})

    findings = await _audit_oauth(_HSession(handler), "http://t/")
    assert all(f["vuln_type"] != "oauth_pkce_not_enforced" for f in findings)


@pytest.mark.asyncio
async def test_weak_password_policy_is_informational_only():
    from heaven.vulnscan.auth_scanner import _audit_password_policy

    def handler(url, headers):
        if url.endswith("/register"):
            return _HResp(200, '<form><input type="password" name="pw"></form>')
        return _HResp(404, "nope")

    findings = await _audit_password_policy(_HSession(handler), "http://t/")
    wp = [f for f in findings if f["vuln_type"] == "weak_password_policy"]
    assert wp, "expected the informational observation to still be recorded"
    assert wp[0]["severity"] == "info"
    assert wp[0]["confidence"] <= 0.5


# ── IDOR evidence gating ─────────────────────────────────────────────────────

def test_idor_verdict_requires_evidence():
    from heaven.vulnscan.idor_scanner import _idor_verdict
    # identical body → no signal at all
    assert _idor_verdict(200, "A" * 80, 200, "A" * 80) is None
    # non-200 → nothing
    assert _idor_verdict(200, "A" * 80, 403, "B" * 80) is None
    # different body, nothing sensitive → informational enumerable reference
    v = _idor_verdict(200, "A" * 80, 200, "B" * 80)
    assert v and v[0] == "enumerable_reference" and v[1] == "info"
    # different body that leaks another record's data → real IDOR (medium)
    leak = '{"email":"victim@example.com","balance":9999}' + "z" * 80
    v = _idor_verdict(200, "A" * 80, 200, leak)
    assert v and v[0] == "idor" and v[1] == "medium"


def test_mass_assignment_field_value_binding():
    from heaven.vulnscan.idor_scanner import _field_value_bound
    assert _field_value_bound('{"admin":"1","x":2}', "admin", "1")
    assert _field_value_bound('{"is_admin": true}', "is_admin", "1")
    assert _field_value_bound("role=1&x=2", "role", "1")
    # 'admin' merely present as page text is NOT a binding → no false positive
    assert not _field_value_bound("<a href=/admin>Admin panel</a>", "admin", "1")


@pytest.mark.asyncio
async def test_idor_param_enum_not_high_on_plain_diff():
    from urllib.parse import parse_qs, urlparse
    from heaven.vulnscan.idor_scanner import IDORScanner
    scanner = IDORScanner()

    def handler(url, headers):
        idv = parse_qs(urlparse(url).query).get("id", ["0"])[0]
        return _HResp(200, f"<html>product {idv} " + "z" * 200 + "</html>")

    await scanner._test_param_ids(_HSession(handler), "http://t/item?id=5")
    # A different-but-non-sensitive object is at most an informational note.
    assert all(f["vuln_type"] != "idor" for f in scanner._findings)
    if scanner._findings:
        assert scanner._findings[0]["severity"] == "info"


@pytest.mark.asyncio
async def test_idor_param_enum_flagged_on_data_leak():
    from urllib.parse import parse_qs, urlparse
    from heaven.vulnscan.idor_scanner import IDORScanner
    scanner = IDORScanner()

    def handler(url, headers):
        idv = parse_qs(urlparse(url).query).get("id", ["0"])[0]
        if idv == "5":
            return _HResp(200, "<html>your account " + "z" * 200 + "</html>")
        return _HResp(200, '{"email":"victim@example.com","first_name":"Al"}' + "z" * 200)

    await scanner._test_param_ids(_HSession(handler), "http://t/acct?id=5")
    idor = [f for f in scanner._findings if f["vuln_type"] == "idor"]
    assert idor and idor[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_idor_unauth_access_gated_on_real_auth():
    from heaven.vulnscan.idor_scanner import IDORScanner

    def handler(url, headers):
        return _HResp(200, '{"email":"a@b.com","balance":10}' + "z" * 200)

    # No auth token to strip → the unauth check must NOT fire (was a critical FP
    # firing on every id'd URL in the default scan).
    noauth = IDORScanner()
    await noauth._test_unauth_access(_HSession(handler), "http://t/user/5")
    assert noauth._findings == []

    # With a real token, an identical *protected* body served without it is real.
    authed = IDORScanner(auth_headers={"Authorization": "Bearer x"})
    await authed._test_unauth_access(_HSession(handler), "http://t/user/5")
    assert any(f["vuln_type"] == "idor" for f in authed._findings)


# ── dir_fuzzer soft-404 (catch-all) suppression ──────────────────────────────

@pytest.mark.asyncio
async def test_dir_fuzzer_softffour_band_suppresses_catchall():
    from urllib.parse import urlparse
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fuzzer = DirectoryFuzzer()

    # Soft-404: 200 for everything, body reflects the requested path (length-var).
    def handler(url, headers):
        path = urlparse(url).path
        return _HResp(200, f"<html>The page {path} was not found. " + "x" * 300 + "</html>")

    session = _HSession(handler)
    wildcard = await fuzzer._detect_wildcard(session, "http://t")
    assert wildcard is not None and wildcard[0] == 200
    # A normal probe against the catch-all is filtered, not reported as a hit.
    assert await fuzzer._probe(session, "http://t/admin", wildcard) is None


@pytest.mark.asyncio
async def test_dir_fuzzer_real_hit_survives_soft404_band():
    from urllib.parse import urlparse
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fuzzer = DirectoryFuzzer()

    def handler(url, headers):
        path = urlparse(url).path
        if path == "/admin":
            return _HResp(200, "<html>Admin Console" + "R" * 5000 + "</html>")
        return _HResp(200, f"<html>not found {path} " + "x" * 300 + "</html>")

    session = _HSession(handler)
    wildcard = await fuzzer._detect_wildcard(session, "http://t")
    r = await fuzzer._probe(session, "http://t/admin", wildcard)
    assert r is not None and r["target"].endswith("/admin")


# ── anomaly SSTI / prototype-pollution reflection FPs ────────────────────────

@pytest.mark.asyncio
async def test_ssti_no_fp_on_escaped_reflection():
    import html
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe

    # A correctly-escaping app that merely reflects input. It must NOT be flagged
    # SSTI even though the reflected payload contains "java.lang.Runtime" / the
    # math expression, and the page carries a token with stray "49"/"42" digits.
    def render(inputs):
        v = "".join(str(x) for x in inputs.values())
        return 200, f"<html>Hi {html.escape(v)} token=aa49bb42ccdd</html>"

    cand = await WebAnomalyProbe()._test_ssti(_ParamSession(render), "http://t/x", "id", "GET")
    assert cand is None


@pytest.mark.asyncio
async def test_ssti_detected_when_template_evaluates():
    import re
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe

    # A genuinely vulnerable app that evaluates the arithmetic (real SSTI).
    def render(inputs):
        v = "".join(str(x) for x in inputs.values())
        m = re.search(r"(\d{3,6})\s*\*\s*(\d{3,6})", v)
        if m:
            v = str(int(m.group(1)) * int(m.group(2)))
        return 200, f"<html>result {v}</html>"

    cand = await WebAnomalyProbe()._test_ssti(_ParamSession(render), "http://t/x", "id", "GET")
    assert cand is not None and cand.category == "ssti"


@pytest.mark.asyncio
async def test_prototype_pollution_no_fp_on_reflection():
    import html
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe

    # App echoes the injected key=value back — reflection, not pollution.
    def render(inputs):
        v = " ".join(f"{k}={x}" for k, x in inputs.items())
        return 200, f"<html>{html.escape(v)}</html>"

    cand = await WebAnomalyProbe()._test_prototype_pollution(
        _ParamSession(render), "http://t/x", "id", "GET")
    assert cand is None


# ── HTTP request-smuggling precision (web_fuzzer) ────────────────────────────

class _SmugResp:
    def __init__(self, status: int):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return ""


class _SmugSession:
    """Fake aiohttp session: distinguishes the well-formed POST baseline from an
    ambiguous-framing POST probe by the presence of a Transfer-Encoding header."""

    def __init__(self, *, normal_post: int, ambiguous_post: int):
        self._normal = normal_post
        self._ambiguous = ambiguous_post

    def get(self, *a, **k):
        return _SmugResp(200)

    def post(self, *a, headers=None, **k):
        h = headers or {}
        if any(kk.lower() == "transfer-encoding" for kk in h):
            return _SmugResp(self._ambiguous)
        return _SmugResp(self._normal)


@pytest.mark.asyncio
async def test_smuggling_not_flagged_when_post_route_is_404():
    # A GET-only route answers POST with 404. The baseline is now a POST (same
    # method), so the ambiguous POST (also 404) matches it → no indicator.
    # (Regression: a GET baseline made every 404-on-POST route look anomalous.)
    from heaven.vulnscan.web_fuzzer import _fuzz_request_smuggling

    sess = _SmugSession(normal_post=404, ambiguous_post=404)
    findings = await _fuzz_request_smuggling(sess, "http://t/only-get")
    assert findings == []


@pytest.mark.asyncio
async def test_smuggling_flagged_when_ambiguous_framing_deviates():
    # A server that answers the ambiguous CL+TE / dup-TE POST *differently* from a
    # well-formed POST is a genuine (weak) smuggling indicator — must still fire.
    from heaven.vulnscan.web_fuzzer import _fuzz_request_smuggling

    sess = _SmugSession(normal_post=200, ambiguous_post=405)
    findings = await _fuzz_request_smuggling(sess, "http://t/api")
    kinds = {f["vuln_type"] for f in findings}
    assert "http_smuggling_indicator" in kinds
    assert "http_smuggling_te_obfuscation" in kinds
