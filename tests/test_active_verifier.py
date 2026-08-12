"""Regression: active verification promotes Potential findings honestly.

A version banner does not prove exploitability (the backport problem), so
banner-matched CVEs are Potential. This module runs SAFE, read-only behavioural
probes for a curated set of CVEs and promotes ONLY the ones a probe proves —
never fabricating a result, never deleting a finding a probe cannot reach, and
never probing without authorization. See ``heaven.vulnscan.active_verifier``.
"""
from __future__ import annotations

import pytest

from heaven.utils.cvss import confirmation_status, is_confirmed_finding
from heaven.vulnscan import active_verifier as av
from heaven.vulnscan.active_verifier import (
    _base_urls,
    _finding_cve,
    supported_cves,
    verify_finding,
    verify_findings,
)


# ── A fake aiohttp session so the REAL probes run without a network ──────────

class _FakeResp:
    def __init__(self, status: int, body: str):
        self._status = status
        self._body = body

    @property
    def status(self) -> int:
        return self._status

    async def text(self, *a, **k) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """Returns ``body_for(url, headers)`` — lets a test decide per-request."""

    def __init__(self, body_for):
        self._body_for = body_for
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, headers=None, **kw):
        headers = headers or {}
        self.calls.append((url, headers))
        status, body = self._body_for(url, headers)
        return _FakeResp(status, body)


def _apache_potential():
    return {"host": "10.0.0.9", "port": 80, "vuln_type": "vulnerable_service",
            "cve": "CVE-2021-41773", "severity": "critical", "source": "inline_db",
            "confidence": 0.9, "evidence": {}}


# ── Registry + classification ────────────────────────────────────────────────

def test_supported_cves_present():
    cves = supported_cves()
    assert "CVE-2021-41773" in cves and "CVE-2014-6271" in cves


def test_banner_finding_is_potential_candidate():
    f = _apache_potential()
    assert confirmation_status(f) == "Potential"
    assert _finding_cve(f) == "CVE-2021-41773"


def test_base_urls_from_host_port_and_target():
    assert _base_urls({"host": "h", "port": 80}) == ["http://h:80"]
    assert _base_urls({"host": "h", "port": 443}) == ["https://h:443"]
    assert _base_urls({"target": "https://ex.com/app?q=1"}) == ["https://ex.com"]


# ── Authorization + applicability gates (never probe/fabricate) ──────────────

@pytest.mark.asyncio
async def test_unauthorized_never_probes():
    out = await verify_finding(_apache_potential(), authorized=False)
    rec = out["evidence"]["active_verification"]
    assert rec["probed"] is False and rec["proved"] is False
    assert confirmation_status(out) == "Potential"


@pytest.mark.asyncio
async def test_unsupported_cve_is_skipped():
    f = {"host": "h", "port": 80, "vuln_type": "vulnerable_service",
         "cve": "CVE-2099-0001", "source": "nvd", "evidence": {}}
    out = await verify_finding(f, authorized=True)
    rec = out["evidence"]["active_verification"]
    assert rec["probed"] is False
    assert confirmation_status(out) == "Potential"


@pytest.mark.asyncio
async def test_batch_skips_when_no_candidates():
    f = {"host": "h", "cve": "CVE-2099-0001", "vuln_type": "vulnerable_service",
         "source": "nvd"}
    res = await verify_findings(findings=[f], authorized=True)
    assert res["skipped"] and res["promoted"] == 0


@pytest.mark.asyncio
async def test_batch_requires_authorization():
    res = await verify_findings(findings=[_apache_potential()], authorized=False)
    assert res["skipped"] and "authorized" in res["reason"].lower()
    assert res["candidates"] == 1 and res["promoted"] == 0


# ── The REAL probes, driven by a fake session ────────────────────────────────

@pytest.mark.asyncio
async def test_apache_traversal_probe_confirms_on_passwd():
    """/etc/passwd content in the response promotes Potential → Confirmed."""
    def body_for(url, headers):
        if "etc/passwd" in url:
            return 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        return 404, "not found"

    session = _FakeSession(body_for)
    out = await verify_finding(_apache_potential(), session=session, authorized=True)
    assert is_confirmed_finding(out)
    assert confirmation_status(out) == "Confirmed"
    rec = out["evidence"]["active_verification"]
    assert rec["proved"] and rec["technique"] == "path_traversal_file_read"
    # Round-trip safety: a reloaded finding (evidence only) still reads Confirmed.
    assert out["evidence"]["validation_result"] == "confirmed"


@pytest.mark.asyncio
async def test_apache_traversal_probe_negative_stays_potential():
    """A patched host that never returns passwd is NOT promoted or deleted."""
    session = _FakeSession(lambda url, h: (404, "Not Found"))
    f = _apache_potential()
    out = await verify_finding(f, session=session, authorized=True)
    assert confirmation_status(out) == "Potential"
    rec = out["evidence"]["active_verification"]
    assert rec["probed"] is True and rec["proved"] is False


@pytest.mark.asyncio
async def test_shellshock_probe_confirms_on_canary_reflection():
    """The injected canary echoed back in the body confirms Shellshock."""
    captured: dict[str, str] = {}

    def body_for(url, headers):
        ua = headers.get("User-Agent", "")
        # A vulnerable CGI executes the payload and echoes the canary.
        if "HVNSHOCK:" in ua and "/cgi-bin/" in url:
            token = ua.split("HVNSHOCK:")[-1]
            captured["token"] = token
            return 200, f"Content-Type: text/plain\n\nHVNSHOCK:{token}\n"
        return 404, "nope"

    f = {"host": "10.0.0.5", "port": 80, "vuln_type": "vulnerable_service",
         "cve": "CVE-2014-6271", "severity": "critical", "source": "inline_db",
         "evidence": {}}
    session = _FakeSession(body_for)
    out = await verify_finding(f, session=session, authorized=True)
    assert is_confirmed_finding(out)
    assert out["evidence"]["active_verification"]["technique"] == "shellshock_env_injection"


@pytest.mark.asyncio
async def test_already_confirmed_is_not_reprobed():
    """A finding already Confirmed by another signal is left as-is (no probe)."""
    f = _apache_potential()
    f["validated"] = True  # e.g. proven earlier by exploit_proof
    session = _FakeSession(lambda url, h: (200, "root:x:0:0:"))
    out = await verify_finding(f, session=session, authorized=True)
    assert session.calls == []  # never sent a request
    assert out["evidence"]["active_verification"]["reason"].startswith("already Confirmed")


@pytest.mark.asyncio
async def test_verify_findings_batch_promotes(monkeypatch):
    """End-to-end batch: a proving probe promotes; the summary reports it."""
    from heaven.vulnscan.active_verifier import VerifyResult

    async def _fake_probe(session, base):
        return VerifyResult(cve="", probed=True, proved=True,
                            technique="path_traversal_file_read", notes="ok",
                            evidence={"observable": "root:x:0:0:"})

    monkeypatch.setitem(av._PROBES, "CVE-2021-41773", _fake_probe)
    findings = [_apache_potential(),
                {"host": "h2", "cve": "CVE-2099-0001", "vuln_type": "vulnerable_service",
                 "source": "nvd"}]
    res = await verify_findings(findings=findings, authorized=True)
    assert res["candidates"] == 1 and res["promoted"] == 1
    assert is_confirmed_finding(findings[0])
