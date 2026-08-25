"""HEAVEN — regression tests for the report + triage fixes.

Covers the operator-reported defects:
  * a finding flagged ``false_positive`` still appeared in the downloaded report;
  * the PDF export failed with the misleading "reportlab installed?" whenever the
    real build raised — the message now carries the true reason, and one bad
    finding can no longer take the whole PDF down;
  * operator notes typed without a status change were silently discarded;
  * report layout: CVSS floats rendered as ``9.2000000000001``, roadmap actions
    were cut mid-word, and findings with no HTTP artefact showed no proof at all.
"""

from __future__ import annotations

import pytest


# ── API-level fixtures (auth bypassed; same store the endpoints use) ──

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _seed(engagement: str, findings: list[dict]) -> object:
    from heaven.api.server import _engagement_store_factory
    store = _engagement_store_factory(engagement)
    store.create_engagement(name=engagement)
    store.record_scan_start("scan1", name="scan1", mode="web")
    ids = []
    for f in findings:
        ids.append(store.upsert_finding("scan1", f))
    store.record_scan_complete("scan1", summary={})
    return store, ids


# ── false-positive exclusion from the deliverable ──

def test_report_excludes_false_positives(client):
    client.post("/api/engagements/active", json={"name": "fp-eng"})
    store, ids = _seed("fp-eng", [
        {"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
         "severity": "high", "confidence": 0.9, "risk_score": 7.5},
        {"target": "https://b/admin/backup.zip", "vuln_type": "sensitive_file",
         "title": "Exposed backup archive", "severity": "medium",
         "confidence": 0.85, "risk_score": 5.3},
    ])
    # Flag the backup finding as a false positive via the real endpoint.
    fp_id = ids[1]
    r = client.put(f"/api/engagement/findings/{fp_id}/status",
                   json={"status": "false_positive", "notes": "redirects home"})
    assert r.status_code == 200, r.text

    for fmt in ("json", "html", "markdown"):
        rep = client.get(f"/api/report/export?format={fmt}")
        assert rep.status_code == 200, rep.text
        # the kept finding is present (vuln_type appears in every format) …
        assert "xss" in rep.text.lower(), f"kept finding missing from {fmt}"
        # … and the flagged false positive is gone from every format
        assert "backup" not in rep.text.lower(), f"FP leaked into {fmt}"


def test_report_all_false_positive_returns_404(client):
    client.post("/api/engagements/active", json={"name": "allfp"})
    _store, ids = _seed("allfp", [
        {"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
         "severity": "high", "confidence": 0.9, "risk_score": 7.5},
    ])
    client.put(f"/api/engagement/findings/{ids[0]}/status",
               json={"status": "false_positive"})
    rep = client.get("/api/report/export?format=json")
    assert rep.status_code == 404


# ── operator notes persist without a status change ──

def test_save_notes_without_status_change(client):
    client.post("/api/engagements/active", json={"name": "notes-eng"})
    _store, ids = _seed("notes-eng", [
        {"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
         "severity": "high", "confidence": 0.9, "risk_score": 7.5, "status": "open"},
    ])
    fid = ids[0]
    note = "Confirmed via Burp Repeater — reflected unescaped."
    r = client.put(f"/api/engagement/findings/{fid}/notes", json={"notes": note})
    assert r.status_code == 200, r.text

    ev = client.get(f"/api/engagement/findings/{fid}/evidence")
    assert ev.status_code == 200, ev.text
    f = ev.json()["finding"]
    assert f["operator_notes"] == note
    assert f["status"] == "open"   # status untouched by a notes-only save


def test_set_finding_notes_store_roundtrip(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(str(tmp_path / "e.db"))
    store.create_engagement(name="e")
    store.record_scan_start("s", name="s", mode="web")
    fid = store.upsert_finding("s", {
        "target": "t", "vuln_type": "xss", "title": "x",
        "severity": "low", "confidence": 0.5})
    assert store.set_finding_notes(fid, "hello") is True
    got = store.list_findings(limit=10)[0]
    assert got.operator_notes == "hello"
    assert got.status == "open"
    # unknown id → False, and empty string clears
    assert store.set_finding_notes("nope", "x") is False
    assert store.set_finding_notes(fid, "") is True
    assert store.list_findings(limit=10)[0].operator_notes == ""


# ── report helpers ──

def test_fmt_cvss_rounds_and_passes_through():
    from heaven.devsecops.compliance_report import _fmt_cvss
    assert _fmt_cvss(9.2000000000001) == "9.2"
    assert _fmt_cvss(8) == "8.0"
    assert _fmt_cvss("7.5") == "7.5"
    assert _fmt_cvss("n/a") == "n/a"
    assert _fmt_cvss(None) == ""
    assert _fmt_cvss("") == ""


def test_short_truncates_at_word_boundary():
    from heaven.devsecops.compliance_report import _short
    text = ("Remove sensitive files from the web root; serve nothing you don't "
            "intend to publish. Block dotfiles at the web server. Rotate any "
            "secret that was exposed.")
    out = _short(text, 60)
    assert out.endswith("…")
    # the char before the ellipsis is a full word, never a mid-word cut
    assert not out[:-1].endswith(" ")
    assert " s…" not in out
    # short input is returned untouched (no ellipsis)
    assert _short("short text", 60) == "short text"


def test_proof_blocks_always_non_empty():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    g = ComplianceReportGenerator()
    # finding with an explicit artefact → that artefact is the proof
    art = g._proof_blocks({"vuln_type": "sqli", "target": "t",
                           "evidence": {"payload": "' OR 1=1--"}})
    assert any(lbl == "Payload" for lbl, _c, _t in art)
    # finding with a class-appropriate repro command
    spf = g._proof_blocks({"vuln_type": "spf_missing", "target": "mail.acme.com",
                           "evidence": {"description": "no spf"}})
    assert spf, "every finding must have at least one proof block"
    # completely evidence-less finding still gets an honest fallback block
    bare = g._proof_blocks({"vuln_type": "weird", "target": "x", "evidence": {}})
    assert bare and bare[0][0] == "Evidence"


def test_candidate_cvss_formatted_in_html():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    f = {
        "target": "10.0.0.5", "vuln_type": "vulnerable_service",
        "title": "Apache potential", "severity": "info", "confidence": 0.3,
        "evidence": {"version": "undetermined", "candidate_details": [
            {"cve": "CVE-2023-1", "cvss": 9.2000000000001, "severity": "critical",
             "title": "x", "affected_versions": "< 2.4.57", "exploit_available": True},
        ]},
    }
    html = ComplianceReportGenerator().generate_html_report([f], engagement_name="e")
    assert "9.2000000000001" not in html
    assert ">9.2<" in html


# ── PDF export: honest strict error + defensive per-finding rendering ──

def test_pdf_strict_surfaces_real_error(monkeypatch):
    from heaven.devsecops.pdf_report import PDFReportGenerator
    gen = PDFReportGenerator()
    if not gen.available:
        pytest.skip("reportlab not installed")

    def boom(*a, **k):
        raise RuntimeError("synthetic build failure ZZZ")

    monkeypatch.setattr(gen, "_build_pdf", boom)
    with pytest.raises(RuntimeError, match="synthetic build failure ZZZ"):
        gen.generate({"engagement": "x", "findings": []}, "/tmp/heaven_t.pdf",
                     strict=True)
    # non-strict degrades gracefully (writes the HTML sibling, returns True)
    assert gen.generate({"engagement": "x", "findings": []}, "/tmp/heaven_t2.pdf",
                        strict=False) is True


def test_pdf_one_bad_finding_does_not_abort(tmp_path, monkeypatch):
    from heaven.devsecops.pdf_report import PDFReportGenerator
    import os
    gen = PDFReportGenerator()
    if not gen.available:
        pytest.skip("reportlab not installed")
    real = gen._finding_block

    def crash(idx, f, *a, **k):
        if f.get("id") == "bad":
            raise ValueError("boom")
        return real(idx, f, *a, **k)

    monkeypatch.setattr(gen, "_finding_block", crash)
    findings = [
        {"id": "bad", "target": "t", "vuln_type": "x", "title": "Bad",
         "severity": "high", "evidence": {"description": "d"}},
        {"id": "ok", "target": "t2", "vuln_type": "y", "title": "Good",
         "severity": "low", "evidence": {"description": "d2"}},
    ]
    out = str(tmp_path / "r.pdf")
    gen._build_pdf({"engagement": "E", "findings": findings,
                    "vulnerabilities": findings, "assets": [], "dns_records": []}, out)
    assert os.path.getsize(out) > 0   # PDF still produced despite the bad finding
