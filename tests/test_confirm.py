"""Regression: the unified Active-Confirmation dispatcher confirms EVERY finding
class honestly.

The web "Active Confirmation" panel used to call the injection-only exploit
prover, so any non-injection finding silently returned "Proved: no" with no
explanation. :func:`heaven.vulnscan.confirm.confirm_finding` now routes each
finding to the safest applicable live proof — an exploit canary, a CVE probe, an
HTTP/TLS re-check, or a TCP connect — and returns a structured, honest verdict,
with a manual next step for classes that have no safe automated proof. Every
probe here is mocked: no live traffic is sent.
"""
from __future__ import annotations

import pytest

from heaven.vulnscan import confirm
from heaven.vulnscan.confirm import (
    ALREADY_CONFIRMED,
    CONFIRMED,
    NOT_APPLICABLE,
    UNAUTHORIZED,
    UNCONFIRMED,
    classify,
    confirm_finding,
)


# ── A fake session whose _http_get we override per-test ──────────────────────

class _FakeSession:
    async def close(self):
        return None


@pytest.fixture(autouse=True)
def _no_live_sessions(monkeypatch):
    """Never open a real aiohttp session in these tests."""
    monkeypatch.setattr(confirm, "_new_session", lambda: _FakeSession())


def _patch_get(monkeypatch, status=200, headers=None, body=""):
    async def _fake(_session, _url, **_kw):
        return status, {k.lower(): v for k, v in (headers or {}).items()}, body
    monkeypatch.setattr(confirm, "_http_get", _fake)


# ── Classification ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("finding,expected", [
    ({"vuln_type": "sqli", "target": "http://x/", "evidence": {"parameter": "id"}}, "exploit"),
    ({"vuln_type": "security_headers", "target": "https://x/", "evidence": {}}, "http_header"),
    ({"vuln_type": "directory_listing", "target": "http://x/d/", "evidence": {}}, "http_dirlisting"),
    ({"vuln_type": "cors_misconfig", "target": "https://x/api", "evidence": {}}, "http_cors"),
    ({"vuln_type": "open_redirect", "target": "https://x/r?u=1", "evidence": {}}, "http_redirect"),
    ({"vuln_type": "sensitive_file_exposure", "target": "http://x/.env", "evidence": {}}, "http_endpoint"),
    ({"vuln_type": "cert_expired", "target": "x.com:443",
      "evidence": {"host": "x.com", "port": 443}}, "tls"),
    ({"vuln_type": "vulnerable_service", "target": "x.com:3306",
      "evidence": {"host": "x.com", "port": 3306}}, "tcp"),
    ({"vuln_type": "spf_missing", "target": "x.com", "evidence": {}}, "manual"),
    ({"vuln_type": "apache", "cve_id": "CVE-2021-41773", "target": "http://x/",
      "evidence": {}}, "cve_probe"),
])
def test_classify_routes_each_family(finding, expected):
    assert classify(finding) == expected


# ── Authorization gate: nothing sent without authorization ───────────────────

@pytest.mark.asyncio
async def test_http_family_requires_authorization(monkeypatch):
    sent = {"n": 0}

    async def _fake(_s, _u, **_k):
        sent["n"] += 1
        return 200, {}, ""
    monkeypatch.setattr(confirm, "_http_get", _fake)

    f = {"vuln_type": "security_headers", "target": "https://x/", "evidence": {}}
    out = await confirm_finding(f, authorized=False)
    assert out["status"] == UNAUTHORIZED
    assert out["proved"] is False
    assert sent["n"] == 0  # never probed


# ── HTTP header re-check ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_hsts_confirmed_when_absent(monkeypatch):
    _patch_get(monkeypatch, status=200, headers={"Server": "nginx"}, body="ok")
    f = {"vuln_type": "no_hsts", "title": "Missing HSTS header",
         "target": "https://x/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True
    assert out["method"] == "http-recheck"
    # Promotion is stamped onto the finding for persistence.
    assert f["evidence"]["validation_result"] == "confirmed"


@pytest.mark.asyncio
async def test_missing_hsts_unconfirmed_when_present(monkeypatch):
    _patch_get(monkeypatch, status=200,
               headers={"Strict-Transport-Security": "max-age=63072000"}, body="ok")
    f = {"vuln_type": "no_hsts", "title": "Missing HSTS header",
         "target": "https://x/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False


# ── Directory listing ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_directory_listing_confirmed(monkeypatch):
    _patch_get(monkeypatch, status=200, body="<html><title>Index of /uploads</title>")
    f = {"vuln_type": "directory_listing", "target": "http://x/uploads/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True


# ── Exposed file / endpoint ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exposed_env_file_confirmed(monkeypatch):
    _patch_get(monkeypatch, status=200, body="DB_PASSWORD=secret\nAPI_KEY=abc\n")
    f = {"vuln_type": "sensitive_file_exposure", "target": "http://x/.env", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True


@pytest.mark.asyncio
async def test_exposed_file_unconfirmed_on_404(monkeypatch):
    _patch_get(monkeypatch, status=404, body="not found")
    f = {"vuln_type": "sensitive_file_exposure", "target": "http://x/.env", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False


# ── CORS ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cors_reflected_origin_confirmed(monkeypatch):
    _patch_get(monkeypatch, status=200,
               headers={"Access-Control-Allow-Origin": "https://heaven-confirm.example",
                        "Access-Control-Allow-Credentials": "true"})
    f = {"vuln_type": "cors_misconfig", "target": "https://x/api", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True


# ── Open redirect ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_open_redirect_offsite_confirmed(monkeypatch):
    _patch_get(monkeypatch, status=302, headers={"Location": "https://evil.example/"})
    f = {"vuln_type": "open_redirect", "target": "https://x/r?u=evil", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True


# ── TCP reachability ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exposed_service_confirmed_by_tcp(monkeypatch):
    async def _reach(_h, _p, timeout=6.0):
        return True
    monkeypatch.setattr(confirm, "_tcp_reachable", _reach)
    f = {"vuln_type": "exposed_database", "target": "db.x:3306",
         "evidence": {"host": "db.x", "port": 3306}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True
    assert out["method"] == "tcp-connect"


@pytest.mark.asyncio
async def test_exposed_service_unconfirmed_when_unreachable(monkeypatch):
    async def _reach(_h, _p, timeout=6.0):
        return False
    monkeypatch.setattr(confirm, "_tcp_reachable", _reach)
    f = {"vuln_type": "exposed_database", "target": "db.x:3306",
         "evidence": {"host": "db.x", "port": 3306}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False


# ── TLS re-handshake ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tls_confirmed_when_issue_reappears(monkeypatch):
    import heaven.vulnscan.ssl_scanner as ssl_scanner

    async def _fake_scan(host, port=443):
        return {"findings": [{"vuln_type": "cert_expired"}]}
    monkeypatch.setattr(ssl_scanner, "scan_ssl", _fake_scan)
    f = {"vuln_type": "cert_expired", "target": "x.com:443",
         "evidence": {"host": "x.com", "port": 443}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True
    assert out["method"] == "tls-recheck"


@pytest.mark.asyncio
async def test_tls_unconfirmed_when_issue_gone(monkeypatch):
    import heaven.vulnscan.ssl_scanner as ssl_scanner

    async def _fake_scan(host, port=443):
        return {"findings": []}  # remediated
    monkeypatch.setattr(ssl_scanner, "scan_ssl", _fake_scan)
    f = {"vuln_type": "cert_expired", "target": "x.com:443",
         "evidence": {"host": "x.com", "port": 443}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == UNCONFIRMED and out["proved"] is False


# ── Injection delegation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_injection_delegates_to_exploit_prover(monkeypatch):
    import heaven.vulnscan.exploit_proof as ep

    async def _fake_prove(finding, **_kw):
        finding.setdefault("evidence", {})["exploit_proof"] = [
            {"technique": "sqlmap", "notes": "boolean-blind confirmed", "proved": True}]
        finding["proved"] = True
        return finding
    monkeypatch.setattr(ep, "prove_finding", _fake_prove)
    f = {"vuln_type": "sqli", "target": "http://x/item?id=1",
         "evidence": {"parameter": "id"}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == CONFIRMED and out["proved"] is True
    assert out["method"] == "exploit"


@pytest.mark.asyncio
async def test_injection_without_parameter_is_not_applicable():
    # An XSS finding with no injectable parameter can't fire a safe canary.
    f = {"vuln_type": "xss", "target": "http://x/", "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == NOT_APPLICABLE
    assert "parameter" in out["detail"].lower()


# ── Manual-guidance fallback (honest, never a misleading "no") ────────────────

@pytest.mark.asyncio
async def test_heuristic_finding_is_not_applicable_with_hint():
    # Low-confidence, no CVE, no safe automated proof → not_applicable + a hint.
    f = {"vuln_type": "race_condition", "title": "Possible race condition",
         "target": "https://x/checkout", "confidence": 0.3, "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == NOT_APPLICABLE
    assert out["detail"]  # a concrete manual next step is always provided


@pytest.mark.asyncio
async def test_directly_observed_finding_reports_already_confirmed():
    # An SPF-missing finding is proven by the DNS observation itself.
    f = {"vuln_type": "spf_missing", "title": "SPF record missing",
         "target": "example.com", "confidence": 0.95, "evidence": {}}
    out = await confirm_finding(f, authorized=True)
    assert out["status"] == ALREADY_CONFIRMED
    assert out["proved"] is False  # not a fresh probe — the detection is the proof
