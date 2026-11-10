"""Chain of authorization + safe-by-default exploitation invariants."""

from __future__ import annotations

import pytest

from heaven.devsecops import authorization_record as ar


def _targets(**over):
    t = {"ips": ["10.0.0.5"], "urls": ["https://app.example.com"],
         "repositories": [], "cloud_providers": [], "ad_domain": "",
         "stealth_level": "normal", "verify": False, "auto_prove": False,
         "autonomous": False, "active_exploit": False}
    t.update(over)
    return t


def test_build_record_captures_core_fields(monkeypatch):
    monkeypatch.setenv("HEAVEN_OPERATOR", "pentester-jane")
    rec = ar.build_record(_targets(), method="flag")
    assert rec["operator"] == "pentester-jane"
    assert rec["method"] == "flag"
    assert rec["tool"] == "HEAVEN"
    assert "10.0.0.5" in rec["targets"]
    assert "https://app.example.com" in rec["targets"]
    assert rec["authorized_at"]  # UTC ISO timestamp present


def test_intrusive_block_reflects_flags():
    rec = ar.build_record(
        _targets(verify=True, auto_prove=True, autonomous=True, active_exploit=False),
        method="flag")
    intr = rec["intrusive"]
    assert intr["active_verification"] is True
    assert intr["exploit_proof"] is True
    assert intr["post_exploitation"] is True
    assert intr["active_exploitation"] is False


def test_intrusive_summary_read_only_vs_enabled():
    ro = ar.build_record(_targets(), method="flag")
    assert "read-only" in ar._intrusive_summary(ro)
    enabled = ar.build_record(_targets(auto_prove=True), method="flag")
    assert "exploit proof" in ar._intrusive_summary(enabled)


def test_infer_method_priority(monkeypatch):
    monkeypatch.delenv("HEAVEN_AUTHORIZED_SCOPE", raising=False)
    assert ar.infer_method(True) == "flag"
    assert ar.infer_method(False) == "interactive"
    monkeypatch.setenv("HEAVEN_AUTHORIZED_SCOPE", "10.0.0.5")
    assert ar.infer_method(False) == "env"
    # The explicit flag always wins over the env var.
    assert ar.infer_method(True) == "flag"


def test_operator_falls_back_without_env(monkeypatch):
    for v in ("HEAVEN_OPERATOR", "GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.delenv(v, raising=False)
    assert ar._operator()  # some non-empty OS login or 'unknown'


def test_render_markdown_block():
    rec = ar.build_record(_targets(auto_prove=True), method="flag", operator="jane")
    md = ar.render_markdown(rec)
    assert "## Authorization" in md
    assert "jane" in md
    assert "exploit proof" in md


def test_render_markdown_empty_when_absent():
    assert ar.render_markdown(None) == ""
    assert ar.render_markdown({}) == ""


def test_markdown_report_includes_authorization():
    from heaven.devsecops.evidence import export_findings_markdown
    rec = ar.build_record(_targets(), method="flag", operator="jane")
    report = export_findings_markdown([], engagement_name="Acme", authorization=rec)
    assert "## Authorization" in report
    assert "jane" in report


# ── safe-by-default: provers refuse without authorization ───────────────────

@pytest.mark.asyncio
async def test_exploit_provers_refuse_without_authorization():
    from heaven.vulnscan.exploit_proof import (
        RCECanaryProver, SSRFCallbackProver, XSSExecutionProver, prove_finding)
    assert (await RCECanaryProver(authorized=False).prove("http://t", "p")).proved is False
    assert (await SSRFCallbackProver(authorized=False).prove("http://t", "p")).proved is False
    assert (await XSSExecutionProver(authorized=False).prove("http://t", "p")).proved is False
    # Dispatch path: an RCE finding is never proved when unauthorized.
    f = {"vuln_type": "rce", "target": "http://t",
         "evidence": {"parameter": "p", "method": "GET"}}
    out = await prove_finding(f, authorized=False)
    assert out.get("proved") is not True


@pytest.mark.asyncio
async def test_active_verification_refuses_without_authorization():
    from heaven.vulnscan.active_verifier import verify_findings
    findings = [{"cve": "CVE-2017-9841", "vuln_type": "vulnerable_service",
                 "target": "http://t", "evidence": {}}]
    res = await verify_findings(findings=findings, authorized=False)
    assert res["skipped"] is True
    assert res["promoted"] == 0
