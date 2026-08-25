"""HEAVEN — tests for the methodology↔findings overlay, multi-framework
compliance reports, the AI model catalog, and the web self-update.

All offline: the compliance/methodology pieces are pure functions; the API tests
run against an in-process app with auth disabled; the self-update endpoints are
exercised with the git/network core monkeypatched, so no real git or remote is
touched.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

_DOCS = Path(__file__).resolve().parents[1] / "docs" / "methodology"


# ══════════════════════════════════════════════════════════════════════════
# Workstream A — methodology overlay attaches the concrete findings per row
# ══════════════════════════════════════════════════════════════════════════

def _sample_findings():
    return [
        {"id": "f1", "vuln_type": "sql_injection", "title": "SQLi in login",
         "severity": "high", "target": "http://x/login", "owasp": "A05:2025 Injection"},
        {"id": "f2", "vuln_type": "idor", "title": "IDOR on /api/user",
         "severity": "medium", "target": "http://x/api", "owasp": "A01:2025 Broken Access Control"},
        {"id": "f3", "vuln_type": "weak_tls", "title": "TLS 1.0 enabled",
         "severity": "low", "target": "https://x", "cwe": "CWE-319"},
    ]


def test_overlay_attaches_finding_refs_per_row():
    from heaven import methodology as M
    built = M.build(_sample_findings(), _DOCS)
    std = M.find_standard(built, "owasp_testing_guide")
    assert std is not None
    # At least one exercised row carries the concrete findings that lit it.
    exercised = [r for c in std["categories"] for r in c["rows"] if r.get("exercised")]
    assert exercised, "expected some exercised rows"
    for r in exercised:
        assert "findings" in r and isinstance(r["findings"], list)
        assert r["findings"], "an exercised row must name its findings"
        ref = r["findings"][0]
        assert set(ref) >= {"id", "title", "severity", "target", "vuln_type"}
    # The injection row must reference the SQLi finding specifically.
    inpv = next((r for c in std["categories"] for r in c["rows"]
                 if r["id"] == "WSTG-INPV-01"), None)
    assert inpv is not None and inpv["exercised"]
    assert any(f["id"] == "f1" for f in inpv["findings"])


def test_overlay_empty_engagement_has_no_findings_refs():
    from heaven import methodology as M
    built = M.build([], _DOCS)
    for s in built["standards"]:
        for c in s["categories"]:
            for r in c["rows"]:
                assert r["exercised"] is False
                assert r["findings"] == []


def test_render_coverage_html_and_markdown():
    from heaven import methodology as M
    built = M.build(_sample_findings(), _DOCS)
    std = M.find_standard(built, "owasp_testing_guide")
    html = M.render_coverage_html(std, "demo-eng")
    assert "<table" in html and "Coverage" in html
    assert "SQLi in login" in html  # aligned finding is surfaced
    md = M.render_coverage_markdown(std, "demo-eng")
    assert md.startswith("# OWASP Testing Guide — Coverage")
    assert "| Test |" in md


# ══════════════════════════════════════════════════════════════════════════
# Workstream B — compliance frameworks map findings to controls honestly
# ══════════════════════════════════════════════════════════════════════════

def test_finding_signals_from_owasp_cwe_and_keyword():
    from heaven.devsecops import compliance_frameworks as cf
    # CWE-319 (cleartext) → transport encryption + crypto.
    assert {"crypto", "transport_encryption"} <= cf.finding_signals(
        {"cwe": "CWE-319", "vuln_type": "weak_tls"})
    # OWASP A05 → injection.
    assert "injection" in cf.finding_signals({"owasp": "A05:2025 Injection"})
    # Keyword fallback for a finding with neither owasp nor a mapped CWE.
    assert "auth" in cf.finding_signals({"vuln_type": "default_credentials",
                                         "title": "Default password accepted"})
    # Nothing recognisable → no signals (honest, not forced).
    assert cf.finding_signals({"vuln_type": "totally_unknown_thing"}) == set()


@pytest.mark.parametrize("fw_id", ["hipaa", "uk_gdpr", "eu_gdpr", "pci_dss",
                                   "iso_27001", "soc2", "nist_csf"])
def test_every_framework_maps_findings(fw_id):
    from heaven.devsecops import compliance_frameworks as cf
    fw = cf.get_framework(fw_id)
    assert fw is not None and fw.controls
    findings = _sample_findings() + [
        {"id": "f4", "vuln_type": "default_credentials", "title": "Default creds",
         "severity": "critical", "cwe": "CWE-798"},
        {"id": "f5", "vuln_type": "vulnerable_service", "title": "Old Apache",
         "severity": "high", "owasp": "A03:2025 Software Supply Chain Failures"},
    ]
    buckets = cf.covered_controls(fw, findings)
    # Every framework should map at least some of this varied finding set.
    covered = sum(1 for cid, _ in fw.controls if buckets[cid])
    assert covered >= 1
    # A crypto/transport control must catch the cleartext-TLS finding.
    tls_hits = [cid for cid in buckets if any(f["id"] == "f3" for f in buckets[cid])]
    assert tls_hits, f"{fw_id}: cleartext TLS finding mapped to no control"


def test_transmission_security_specifically_maps_tls():
    from heaven.devsecops import compliance_frameworks as cf
    fw = cf.get_framework("hipaa")
    ids = cf.controls_for_finding(fw, {"cwe": "CWE-319", "vuln_type": "weak_tls"})
    assert "§164.312(e)(1)" in ids  # Transmission Security


def test_list_frameworks_shape():
    from heaven.devsecops import compliance_frameworks as cf
    lst = cf.list_frameworks()
    ids = {f["id"] for f in lst}
    assert {"hipaa", "uk_gdpr", "eu_gdpr", "pci_dss", "iso_27001", "soc2", "nist_csf"} <= ids
    for f in lst:
        assert f["controls_total"] > 0 and f["title"]


def test_html_report_includes_compliance_section():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    findings = _sample_findings()
    html = ComplianceReportGenerator().generate_html_report(
        findings, engagement_name="Acme", compliance_framework="hipaa")
    assert "HIPAA Security Rule Compliance Mapping" in html
    assert 'id="compliance"' in html
    assert "attestation of compliance" in html.lower()
    # A normal report (no framework) has no compliance section.
    plain = ComplianceReportGenerator().generate_html_report(findings, engagement_name="Acme")
    assert 'id="compliance"' not in plain
    # An unknown framework id is ignored, not an error.
    unknown = ComplianceReportGenerator().generate_html_report(
        findings, engagement_name="Acme", compliance_framework="not_a_framework")
    assert 'id="compliance"' not in unknown


def test_markdown_report_includes_compliance_section():
    from heaven.devsecops.evidence import export_findings_markdown
    md = export_findings_markdown(_sample_findings(), engagement_name="Acme",
                                  compliance_framework="uk_gdpr")
    assert "UK GDPR Compliance Mapping" in md
    assert "not an attestation of compliance" in md


def test_pdf_report_compliance_section_builds():
    import importlib.util
    if importlib.util.find_spec("reportlab") is None:
        pytest.skip("reportlab not installed")
    import tempfile
    from heaven.devsecops.pdf_report import PDFReportGenerator
    g = PDFReportGenerator()
    assert g.available
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()
    try:
        ok = g.generate({"engagement": "Acme", "findings": _sample_findings(),
                         "compliance_framework": "pci_dss"}, tmp.name, strict=True)
        assert ok and os.path.getsize(tmp.name) > 0
    finally:
        os.unlink(tmp.name)


# ══════════════════════════════════════════════════════════════════════════
# API tests (auth disabled) — endpoints wired correctly
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def api_client():
    os.environ["HEAVEN_DISABLE_AUTH"] = "1"
    from fastapi.testclient import TestClient

    from heaven.api.server import create_app
    app = create_app()
    yield TestClient(app)
    os.environ.pop("HEAVEN_DISABLE_AUTH", None)


def test_compliance_frameworks_endpoint(api_client):
    r = api_client.get("/api/compliance/frameworks")
    assert r.status_code == 200, r.text
    ids = {f["id"] for f in r.json()["frameworks"]}
    assert {"hipaa", "uk_gdpr", "pci_dss"} <= ids


def test_methodology_export_endpoint(api_client):
    r = api_client.get("/api/methodology/export",
                       params={"standard": "owasp_testing_guide", "format": "html"})
    assert r.status_code == 200, r.text
    assert "text/html" in r.headers["content-type"]
    assert "Coverage" in r.text
    rj = api_client.get("/api/methodology/export",
                        params={"standard": "iso_27001", "format": "json"})
    assert rj.status_code == 200
    assert "standard" in rj.json()
    r404 = api_client.get("/api/methodology/export",
                          params={"standard": "does_not_exist", "format": "html"})
    assert r404.status_code == 404


def test_ai_models_endpoint_shape_and_ollama_merge(api_client, monkeypatch):
    import heaven.ai.local_llm as local_llm
    monkeypatch.setattr(local_llm, "list_models",
                        lambda *a, **k: ["qwen2.5:7b", "custom-model:latest"])
    r = api_client.get("/api/ai/models")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "providers" in body and "provider" in body and "model" in body
    for p in ("anthropic", "openai", "gemini", "ollama", "local"):
        assert p in body["providers"]
        assert "models" in body["providers"][p]
    anth = {m["id"] for m in body["providers"]["anthropic"]["models"]}
    assert "claude-sonnet-5" in anth
    ollama_ids = [m["id"] for m in body["providers"]["ollama"]["models"]]
    # A pulled-but-uncurated model appears (as installed), and the curated one is kept.
    assert "custom-model:latest" in ollama_ids and "qwen2.5:7b" in ollama_ids


# ── Self-update endpoints (git/network core monkeypatched) ──────────────────

def _fake_check(**over):
    from heaven.cli.update import UpdateCheck
    base = dict(is_git=True, remote_reachable=True, available=True, dirty=False,
                current_version="3.0.0", latest_version="3.1.0", behind=2,
                branch="main", upstream="origin/main")
    base.update(over)
    return UpdateCheck(**base)


def test_update_status_reports_available(api_client, monkeypatch, tmp_path):
    import heaven.cli.update as upd
    monkeypatch.setattr(upd, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(upd, "check_for_update", lambda root, fetch=True: _fake_check())
    r = api_client.get("/api/update/status", params={"fetch": "false"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] is True
    assert body["current_version"] == "3.0.0"
    assert body["latest_version"] == "3.1.0"
    assert body["can_apply"] is True
    assert "auto_check" in body


def test_update_status_non_git_is_honest(api_client, monkeypatch):
    import heaven.cli.update as upd
    monkeypatch.setattr(upd, "find_repo_root", lambda: None)
    r = api_client.get("/api/update/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_git"] is False and body["can_apply"] is False
    assert body["available"] is False


def test_update_apply_runs_and_reports(api_client, monkeypatch, tmp_path):
    import heaven.cli.update as upd
    from heaven.cli.update import CodeUpdateResult
    monkeypatch.setattr(upd, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(upd, "check_for_update", lambda root, fetch=True: _fake_check())

    def _fake_apply(root, check, *, force=False, skip_ui=False):
        return CodeUpdateResult(applied=True, from_version="3.0.0", to_version="3.1.0",
                                notes=["dependencies changed — reinstalled"])
    monkeypatch.setattr(upd, "apply_code_update", _fake_apply)

    r = api_client.post("/api/update/apply", json={})
    assert r.status_code == 200, r.text
    assert r.json()["running"] is True

    # Poll until the background task finishes (it's near-instant with the fake).
    done = None
    for _ in range(50):
        s = api_client.get("/api/update/apply/status").json()
        if s["done"]:
            done = s
            break
        time.sleep(0.1)
    assert done is not None, "update apply never finished"
    assert done["ok"] is True
    assert any("3.1.0" in ln for ln in done["log"])


def test_update_apply_refuses_when_up_to_date(api_client, monkeypatch, tmp_path):
    import heaven.cli.update as upd
    monkeypatch.setattr(upd, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(upd, "check_for_update",
                        lambda root, fetch=True: _fake_check(available=False, behind=0))
    r = api_client.post("/api/update/apply", json={})
    assert r.status_code == 409, r.text


def test_web_update_kill_switch_blocks_apply(api_client, monkeypatch, tmp_path):
    """HEAVEN_DISABLE_WEB_UPDATE=1 → apply is refused (403) even for an admin,
    and status advertises web_apply_enabled=False / can_apply=False, while
    detection still works. This is the hosted-deployment safeguard."""
    import heaven.cli.update as upd
    monkeypatch.setenv("HEAVEN_DISABLE_WEB_UPDATE", "1")
    monkeypatch.setattr(upd, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(upd, "check_for_update", lambda root, fetch=True: _fake_check())

    status = api_client.get("/api/update/status", params={"fetch": "false"}).json()
    assert status["available"] is True            # detection unaffected
    assert status["web_apply_enabled"] is False
    assert status["can_apply"] is False           # button suppressed

    def _boom(*a, **k):  # apply must never even reach the core when disabled
        raise AssertionError("apply_code_update must not run when web-apply is off")
    monkeypatch.setattr(upd, "apply_code_update", _boom)

    r = api_client.post("/api/update/apply", json={})
    assert r.status_code == 403, r.text
    assert "HEAVEN_DISABLE_WEB_UPDATE" in r.json()["detail"]


def test_web_update_enabled_by_default(api_client, monkeypatch, tmp_path):
    """With the kill switch unset, web apply is available (the default the user
    asked for): status reports web_apply_enabled=True and can_apply=True."""
    import heaven.cli.update as upd
    monkeypatch.delenv("HEAVEN_DISABLE_WEB_UPDATE", raising=False)
    monkeypatch.setattr(upd, "find_repo_root", lambda: tmp_path)
    monkeypatch.setattr(upd, "check_for_update", lambda root, fetch=True: _fake_check())
    body = api_client.get("/api/update/status", params={"fetch": "false"}).json()
    assert body["web_apply_enabled"] is True
    assert body["can_apply"] is True


# ══════════════════════════════════════════════════════════════════════════
# Compliance registry is comprehensive (10 frameworks) + versions current
# ══════════════════════════════════════════════════════════════════════════

def test_registry_has_all_ten_frameworks():
    from heaven.devsecops import compliance_frameworks as cf
    ids = {f["id"] for f in cf.list_frameworks()}
    assert ids == {"hipaa", "uk_gdpr", "eu_gdpr", "pci_dss", "iso_27001", "soc2",
                   "nist_csf", "cyber_essentials", "cyber_essentials_plus",
                   "cis_controls_v8"}
    # CIS lists all 18 controls; Cyber Essentials the 5 technical controls.
    assert cf.get_framework("cis_controls_v8") is not None
    assert len(cf.get_framework("cis_controls_v8").controls) == 18
    assert len(cf.get_framework("cyber_essentials").controls) == 5


def test_pci_version_is_current():
    from heaven.devsecops import compliance_frameworks as cf
    assert cf.get_framework("pci_dss").title == "PCI DSS v4.0.1"


@pytest.mark.parametrize("fw_id", ["cyber_essentials", "cyber_essentials_plus",
                                   "cis_controls_v8"])
def test_new_frameworks_map_findings(fw_id):
    from heaven.devsecops import compliance_frameworks as cf
    cov = cf.coverage_for(fw_id, _sample_findings(), "eng")
    assert cov is not None
    assert cov["controls_total"] > 0
    # The TLS + SQLi + IDOR sample must light at least one control.
    assert cov["controls_covered"] >= 1
    assert cov["findings_total"] >= 1


def test_coverage_model_and_renders():
    from heaven.devsecops import compliance_frameworks as cf
    cov = cf.coverage_for("iso_27001", _sample_findings(), "Acme")
    assert cov and cov["title"] == "ISO/IEC 27001:2022"
    # Every control carries a status + count + (deduped) findings list.
    for c in cov["controls"]:
        assert c["status"] in ("Findings present", "Not observed")
        assert c["count"] == len(c["findings"])
    html = cf.render_coverage_html(cov)
    assert "Compliance coverage" in html and "not an attestation" in html.lower()
    md = cf.render_coverage_markdown(cov)
    assert md.startswith("# ISO/IEC 27001:2022: Compliance coverage")


def test_compliance_coverage_dedups_across_controls():
    """A finding mapped to several controls counts once per control but the
    engagement's distinct-findings total never double-counts it."""
    from heaven.devsecops import compliance_frameworks as cf
    cov = cf.coverage_for("nist_csf", _sample_findings(), "e")
    assert cov["findings_total"] == 3  # exactly the 3 sample findings, deduped


def test_compliance_pdf_render_builds():
    import importlib.util
    if importlib.util.find_spec("reportlab") is None:
        pytest.skip("reportlab not installed")
    from heaven.devsecops import compliance_frameworks as cf
    cov = cf.coverage_for("pci_dss", _sample_findings(), "Acme")
    pdf = cf.render_coverage_pdf(cov)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 1000


# ══════════════════════════════════════════════════════════════════════════
# Methodology exercised_count is DISTINCT (no "+N more" for shown findings)
# ══════════════════════════════════════════════════════════════════════════

def test_exercised_count_equals_distinct_findings():
    """exercised_count must equal the number of distinct findings attached to a
    row — never a token-hit sum — so the page never advertises phantom
    "+N more findings" it is actually already showing."""
    from heaven import methodology as M
    built = M.build(_sample_findings(), _DOCS)
    for std in built["standards"]:
        for cat in std["categories"]:
            for row in cat["rows"]:
                if row.get("exercised"):
                    # findings list holds the whole distinct set (cap is 500).
                    assert row["exercised_count"] == len(row["findings"])


# ══════════════════════════════════════════════════════════════════════════
# API — methodology PDF export + compliance coverage/export endpoints
# ══════════════════════════════════════════════════════════════════════════

def test_methodology_pdf_export_endpoint(api_client):
    import importlib.util
    if importlib.util.find_spec("reportlab") is None:
        pytest.skip("reportlab not installed")
    r = api_client.get("/api/methodology/export",
                       params={"standard": "owasp_testing_guide", "format": "pdf"})
    assert r.status_code == 200, r.text
    assert "application/pdf" in r.headers["content-type"]
    assert r.content[:5] == b"%PDF-"


def test_compliance_coverage_endpoint(api_client):
    r = api_client.get("/api/compliance/coverage", params={"framework": "hipaa"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "hipaa" and "controls" in body
    assert body["controls_total"] == len(body["controls"])
    r404 = api_client.get("/api/compliance/coverage", params={"framework": "nope"})
    assert r404.status_code == 404


def test_compliance_export_endpoint(api_client):
    r = api_client.get("/api/compliance/export",
                       params={"framework": "cis_controls_v8", "format": "html"})
    assert r.status_code == 200, r.text
    assert "text/html" in r.headers["content-type"]
    assert "Compliance coverage" in r.text
    rj = api_client.get("/api/compliance/export",
                        params={"framework": "soc2", "format": "json"})
    assert rj.status_code == 200 and rj.json()["id"] == "soc2"
    import importlib.util
    if importlib.util.find_spec("reportlab") is not None:
        rp = api_client.get("/api/compliance/export",
                            params={"framework": "pci_dss", "format": "pdf"})
        assert rp.status_code == 200 and rp.content[:5] == b"%PDF-"


# ══════════════════════════════════════════════════════════════════════════
# LLM false-positive review — manual review forces past the borderline band
# ══════════════════════════════════════════════════════════════════════════

def test_fp_reviewer_force_bypasses_band():
    """The band gates only the automatic bulk pass. A forced (operator-requested)
    review returns a verdict for an out-of-band finding; unforced returns None."""
    import asyncio

    from heaven.ai.fp_review import FPReviewer, FPReviewVerdict

    class _Resp:
        structured = FPReviewVerdict(keep=True, confidence_delta=0.1, reasoning="ok")
        error = None

        def ok(self):
            return True

    class _GW:
        available = True

        async def acomplete(self, req):
            return _Resp()

    r = FPReviewer(gateway=_GW())
    hi = {"confidence": 0.95, "vuln_type": "xss", "target": "t"}  # OUT of band
    assert asyncio.run(r.review(hi, force=True)) is not None
    assert asyncio.run(r.review(hi, force=False)) is None


def test_fp_review_endpoint_forces_and_reasons(api_client, monkeypatch):
    """The manual fp-review endpoint returns a verdict for an out-of-band finding
    when a provider is configured, and an honest reason (not always 'add a key')
    when one is not."""
    import heaven.ai as _ai

    class _FakeVerdict:
        def model_dump(self):
            return {"keep": True, "confidence_delta": 0.1, "reasoning": "solid",
                    "notable_signals": ["reflected"]}

    class _FakeReviewer:
        available = True

        def __init__(self, *a, **k):
            pass

        async def review(self, finding, *, force=False):
            assert force is True  # endpoint must force a manual review
            return _FakeVerdict()

    monkeypatch.setattr(_ai, "FPReviewer", _FakeReviewer)
    r = api_client.post("/api/ai/fp-review/run",
                        json={"finding": {"id": "x", "confidence": 0.98,
                                          "vuln_type": "xss"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("skipped") is False and body.get("keep") is True

    # No provider configured → skipped with an honest 'no_llm' reason.
    class _Unavailable(_FakeReviewer):
        available = False

    monkeypatch.setattr(_ai, "FPReviewer", _Unavailable)
    import heaven.ai.llm_gateway as gw

    class _GW:
        available = False
    monkeypatch.setattr(gw, "get_gateway", lambda: _GW())
    r2 = api_client.post("/api/ai/fp-review/run",
                         json={"finding": {"id": "x", "confidence": 0.5}})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2.get("skipped") is True and b2.get("reason") == "no_llm"
