"""Regression tests for the web/API/cloud scan-mode false-positive + crash fixes.

Each test pins one defect that was reproduced live (against VAmPI, OWASP Juice
Shop, MinIO, a Modbus/OPC-UA stack, an IMDS-SSRF app) during the scan-mode audit,
so the fix cannot silently regress. Nothing here talks to the network — the HTTP
surface is a tiny in-process fake, and the rest are pure functions.
"""
from __future__ import annotations

import sys
import types

import pytest


# ── shared in-process HTTP fakes ─────────────────────────────────────────────
class _Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}
        self.url = ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self, *a, **k):
        return self._body

    async def read(self, *a, **k):
        return self._body.encode("utf-8", "replace")


class _Session:
    """Fake aiohttp session dispatching on (method, url, params) → _Resp."""
    def __init__(self, handler):
        self._handler = handler

    def request(self, method, url, params=None, **kwargs):
        return self._handler(method, url, params or {}, kwargs)

    def get(self, url, params=None, **kwargs):
        return self._handler("GET", url, params or {}, kwargs)


# ── 1. finding dedup: slash / double-slash variants collapse ─────────────────
def test_finding_hash_collapses_slash_and_double_slash_variants():
    from heaven.engagement import _canon_url_path, _finding_hash

    assert _canon_url_path("http://h:5001//users/v1") == "http://h:5001/users/v1"
    assert _canon_url_path("http://h:5001/") == "http://h:5001"

    h1 = _finding_hash("http://h:5001", "api_broken_auth",
                       endpoint="http://h:5001/users/v1")
    h2 = _finding_hash("http://h:5001/", "api_broken_auth",
                       endpoint="http://h:5001//users/v1")
    assert h1 == h2, "slash/double-slash variants of one endpoint must collapse"

    # A genuinely different endpoint must still be distinct.
    h3 = _finding_hash("http://h:5001", "api_broken_auth",
                       endpoint="http://h:5001/users/v2")
    assert h1 != h3


def test_dedup_findings_collapses_url_slash_variants():
    from heaven.engagement import dedup_findings
    findings = [
        {"target": "http://h:5001", "vuln_type": "api_docs_exposed",
         "endpoint": "http://h:5001/openapi.json"},
        {"target": "http://h:5001/", "vuln_type": "api_docs_exposed",
         "endpoint": "http://h:5001//openapi.json"},
    ]
    assert len(dedup_findings(findings)) == 1


# ── 2. proof_capture: never attach a status-contradicting response ───────────
def test_proof_capture_skips_status_mismatched_body():
    import heaven.vulnscan.proof_capture as pc
    tok = pc.begin()
    try:
        pc.record("http://x/users/v1", 405, "405 method not allowed")
        f = {"vuln_type": "api_broken_auth", "target": "http://x/users/v1",
             "evidence": {"status": 200}}
        assert pc.attach(f) is False
        assert "response_body" not in f["evidence"]

        # A matching-status capture IS attached.
        pc.record("http://x/users/v1", 200, "real 200 body")
        assert pc.attach(f) is True
        assert f["evidence"]["response_body"] == "real 200 body"
    finally:
        pc.end(tok)


# ── 3. enrich_finding backfills a blank title ────────────────────────────────
def test_enrich_finding_backfills_blank_title():
    from heaven.devsecops.vuln_kb import enrich_finding
    # A curated type gets the KB title.
    out = enrich_finding({"vuln_type": "integer_overflow", "severity": "high"})
    assert out.get("title")
    # An uncurated type gets a humanised fallback, never blank.
    out2 = enrich_finding({"vuln_type": "some_unknown_type_xyz", "severity": "low"})
    assert out2.get("title") and "_" not in out2["title"]
    # An existing title is preserved.
    out3 = enrich_finding({"vuln_type": "integer_overflow", "title": "Mine"})
    assert out3["title"] == "Mine"


# ── 4. dir_fuzzer: a 500 is not a discovered path ────────────────────────────
def test_dir_fuzzer_hit_codes_exclude_500():
    from heaven.vulnscan import dir_fuzzer
    assert 500 not in dir_fuzzer.HIT_CODES
    # ffuf match-codes are derived from HIT_CODES, so they stay in lock-step.
    for c in (200, 301, 401, 403, 405):
        assert c in dir_fuzzer.HIT_CODES


@pytest.mark.asyncio
async def test_dir_fuzzer_probe_ignores_500_reports_200():
    from urllib.parse import urlparse
    from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer
    fuzzer = DirectoryFuzzer()

    def handler(method, url, params, kwargs):
        path = urlparse(url).path
        if path == "/metrics":
            return _Resp(200, "# HELP big real metrics " + "m" * 5000)
        # every other path is a templated 500 "Unexpected path" catch-all
        return _Resp(500, f"<title>Error: Unexpected path: {path}</title>")

    session = _Session(handler)
    wildcard = await fuzzer._detect_wildcard(session, "http://t")
    # a 500 catch-all path is never a hit
    assert await fuzzer._probe(session, "http://t/api/v2", wildcard) is None
    # a genuine 200 exposure survives
    hit = await fuzzer._probe(session, "http://t/metrics", wildcard)
    assert hit is not None and hit["evidence"]["path"] == "/metrics"


# ── 5. web cache deception: cacheability + catch-all rule-out ─────────────────
def test_cacheable_for_deception_rules():
    from heaven.vulnscan.web_fuzzer import _cacheable_for_deception as c
    assert c("public, max-age=0") is False       # revalidates → not stale-served
    assert c("s-maxage=0") is False
    assert c("no-store") is False
    assert c("private, max-age=600") is False
    assert c("public, max-age=300") is True
    assert c("public") is True
    assert c("max-age=120") is True


def test_page_fingerprint_stable_across_tokens():
    from heaven.vulnscan.web_fuzzer import _page_fingerprint
    a = _page_fingerprint("<html>hello csrf=deadbeef1234 ts=1699999999</html>")
    b = _page_fingerprint("<html>hello csrf=cafebabe5678 ts=1700000001</html>")
    assert a == b  # volatile tokens stripped → same page, same fingerprint
    c = _page_fingerprint("<html>a completely different page</html>")
    assert a != c


# ── 6. integer_overflow needs a REPRODUCED 500 + healthy baseline ────────────
@pytest.mark.asyncio
async def test_integer_overflow_single_500_is_not_confirmed():
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()
    state = {"n": 0}

    def handler(method, url, params, kwargs):
        val = params.get("id", "")
        # baseline id=1 is healthy; the boundary payload 500s exactly once, then
        # the endpoint is healthy again (a transient / stateful blip).
        if val == "1":
            return _Resp(200, "ok")
        state["n"] += 1
        return _Resp(500 if state["n"] == 1 else 200, "seeded")

    cand = await probe._test_integer_overflow(_Session(handler), "http://t/createdb",
                                              "id", "GET")
    assert cand is None, "a single, non-reproduced 500 must not be integer_overflow"


@pytest.mark.asyncio
async def test_integer_overflow_reproduced_500_is_confirmed():
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()

    def handler(method, url, params, kwargs):
        val = params.get("id", "")
        if val == "1":
            return _Resp(200, "ok")           # baseline always healthy
        return _Resp(500, "overflow")          # boundary payload always 500s

    cand = await probe._test_integer_overflow(_Session(handler), "http://t/x",
                                              "id", "GET")
    assert cand is not None and cand.category == "integer_overflow"


# ── 7. ldap boolean-diff needs same successful status, not a routing gap ─────
@pytest.mark.asyncio
async def test_ldap_boolean_diff_suppressed_on_status_mismatch():
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()

    def handler(method, url, params, kwargs):
        val = params.get("q", "")
        if val == "*":
            return _Resp(200, "X" * 60000)     # wildcard: big 200
        if val.startswith("HEAVEN_LDAP"):
            return _Resp(405, "method not allowed")  # impossible value: 405
        return _Resp(200, "baseline")

    cand = await probe._test_ldap_injection(_Session(handler), "http://t/createdb",
                                            "q", "GET")
    assert cand is None, "a 200-vs-405 gap is a routing artifact, not LDAP injection"


@pytest.mark.asyncio
async def test_ldap_boolean_diff_fires_on_same_status_differential():
    from heaven.vulnscan.anomaly_probe import WebAnomalyProbe
    probe = WebAnomalyProbe()

    def handler(method, url, params, kwargs):
        val = params.get("q", "")
        if val == "testuser":
            return _Resp(200, "one record")
        if val == "*":
            return _Resp(200, "R" * 60000)     # wildcard matches everything (200)
        return _Resp(200, "")                   # impossible value: empty (200)

    cand = await probe._test_ldap_injection(_Session(handler), "http://t/search",
                                            "q", "GET")
    assert cand is not None and cand.category == "ldap_injection"


# ── 8. security-header audit ignores a 5xx error page ────────────────────────
@pytest.mark.asyncio
async def test_security_headers_skipped_on_server_error():
    from heaven.vulnscan import auth_scanner

    class _R(_Resp):
        async def __aenter__(self):
            self.url = "http://t/x"
            return self

    def handler(method, url, params, kwargs):
        return _R(500, "<html>Werkzeug debug error</html>")

    findings = await auth_scanner._audit_security_headers(_Session(handler),
                                                          "http://t/x")
    assert findings == [], "no header findings from a 500 error page"


# ── 9. advanced-attacks never crashes on a dict endpoint ─────────────────────
@pytest.mark.asyncio
async def test_run_advanced_tests_survives_dict_endpoints():
    from heaven.vulnscan import advanced_attacks

    def handler(method, url, params, kwargs):
        return _Resp(200, "ok")

    # A recon endpoint dict (not a URL string) used to reach url.lower() and crash.
    scan_data = {"jwt_tokens": [],
                 "critical_endpoints": [{"url": "http://t/race"}, {"action": ""}, 123]}
    out = await advanced_attacks.run_advanced_tests(
        _Session(handler), "http://t/", scan_data=scan_data)
    assert isinstance(out, list)  # returned cleanly, no AttributeError


# ── 10. cloud scan: a blanket-403 endpoint yields no fabricated buckets ──────
def _install_fake_aiohttp(monkeypatch, handler):
    """Install a minimal fake ``aiohttp`` module so CloudStorageScanner.scan runs
    fully in-process. ``handler(url) -> (status, body)``."""
    mod = types.ModuleType("aiohttp")

    class _CResp:
        def __init__(self, url):
            self._s, self._b = handler(url)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        @property
        def status(self):
            return self._s

        async def text(self, *a, **k):
            return self._b

    class _CSession:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def get(self, url, **k):
            return _CResp(url)

    def _timeout(*a, **k):
        return None

    mod.ClientSession = _CSession        # type: ignore[attr-defined]
    mod.ClientTimeout = _timeout         # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aiohttp", mod)


def test_cloud_scan_blanket_403_suppresses_fabricated_buckets(monkeypatch):
    import asyncio

    from heaven.vulnscan.cloud_scanner import CloudStorageScanner

    def handler(url):
        # MinIO-style: the one real bucket lists (200 XML); EVERY other name
        # (including the calibration control) returns 403 AccessDenied.
        if "/heaven-public/" in url and "heaven-public-" not in url:
            return 200, ('<?xml version="1.0"?><ListBucketResult '
                         'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                         '<Name>heaven-public</Name></ListBucketResult>')
        return 403, ("<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code>"
                     "<Message>Access Denied.</Message></Error>")

    _install_fake_aiohttp(monkeypatch, handler)
    sc = CloudStorageScanner(endpoint_url="http://127.0.0.1:9000")
    res = asyncio.run(sc.scan("127.0.0.1:9000",
                              extra_names=["heaven-public"], limit=60))
    findings = res.to_findings()
    # Only the PROVEN-listable bucket is reported; the blanket-403 permutations
    # are NOT fabricated as "bucket exists (private)".
    assert [f["vuln_type"] for f in findings] == ["exposed_storage_bucket"]
    assert findings[0]["evidence"]["bucket"] == "heaven-public"
