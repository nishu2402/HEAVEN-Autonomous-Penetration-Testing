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
