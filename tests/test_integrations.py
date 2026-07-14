"""Guards for external-integration correctness — the NVD-class bugs.

These are functional-contract checks that static analysis (ruff/mypy) and the
existing unit tests don't catch: wrong endpoints and refresh no-ops compile and
import fine but silently return nothing at runtime. All offline.
"""

from __future__ import annotations

import inspect


# ── ExploitDB CSV mirror: `heaven update` must actually re-download ──

def test_exploitdb_force_refresh_exists_and_is_async():
    """`heaven update` calls refresh_csv_mirror via getattr; if it's missing the
    refresh silently falls back to the lazy cache (a no-op when the file exists).
    """
    import heaven.vulnscan.exploitdb_client as edb
    assert hasattr(edb, "refresh_csv_mirror"), "refresh_csv_mirror is required by heaven update"
    assert inspect.iscoroutinefunction(edb.refresh_csv_mirror)
    assert hasattr(edb, "_download_csv_mirror")


# ── MITRE ATT&CK TAXII: must target the live server, not the retired one ──

def test_taxii_targets_current_server():
    """MITRE retired cti-taxii.mitre.org in 2022; only attack-taxii.mitre.org
    responds. Pointing at the old host hangs then returns an empty dataset.
    """
    from heaven.mitre import taxii_client as tc
    assert "cti-taxii.mitre.org" not in tc.TAXII_SERVER
    assert tc.TAXII_SERVER == "https://attack-taxii.mitre.org"
    assert tc.TAXII_API_ROOT.endswith("/api/v21")
    # current enterprise collection id is a STIX collection identifier
    assert tc.ENTERPRISE_COLLECTION_ID.startswith("x-mitre-collection--")


def test_mitre_config_default_endpoint_is_current():
    from heaven.config import MITREConfig
    assert "cti-taxii" not in MITREConfig().taxii_url
    assert "attack-taxii.mitre.org" in MITREConfig().taxii_url


# ── NVD client: must use virtualMatchString, never the 404-prone cpeName ──

def test_nvd_search_does_not_use_cpename():
    """Regression guard for the original NVD bug: cpeName 404s on wildcard CPEs."""
    import inspect as _inspect

    from heaven.vulnscan import nvd_client
    src = _inspect.getsource(nvd_client.NVDClient.search_by_cpe)
    assert "virtualMatchString" in src
    assert '"cpeName"' not in src and "'cpeName'" not in src


# ── Professional PDF report (reportlab) ─────────────────────────────

def test_pdf_report_generates_valid_pdf(tmp_path):
    """The PDF generator must use reportlab and emit a real multi-section PDF
    (regression guard for the old reportlab/weasyprint wiring mismatch)."""
    import pytest
    pytest.importorskip("reportlab")
    PdfReader = pytest.importorskip("pypdf").PdfReader

    from heaven.devsecops.pdf_report import PDFReportGenerator
    from heaven.devsecops.vuln_kb import enrich_finding

    findings = [
        enrich_finding({"id": "F-1", "target": "https://app.example.com/login",
                        "vuln_type": "sqli", "title": "SQL Injection",
                        "severity": "critical", "confidence": 0.96, "risk_score": 96,
                        "predicted_cvss_score": 9.8, "status": "open",
                        "evidence": {"payload": "' OR 1=1-- -"}}),
        enrich_finding({"id": "F-2", "target": "https://app.example.com",
                        "vuln_type": "xss", "title": "Reflected XSS",
                        "severity": "high", "confidence": 0.9, "risk_score": 80,
                        "status": "open", "evidence": {"payload": "<svg/onload=alert(1)>"}}),
    ]
    out = tmp_path / "report.pdf"
    ok = PDFReportGenerator().generate(
        {"engagement": "Example Corp", "findings": findings}, str(out))
    assert ok and out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"

    reader = PdfReader(str(out))
    text = "\n".join((p.extract_text() or "") for p in reader.pages)
    for section in ("Penetration Test Report", "Executive Summary",
                    "Detailed Findings", "Remediation Roadmap", "OWASP Top 10"):
        assert section in text, f"missing section: {section}"


def test_pdf_generator_uses_reportlab_not_weasyprint():
    import inspect as _inspect

    from heaven.devsecops import pdf_report
    src = _inspect.getsource(pdf_report)
    assert "reportlab" in src
    assert "weasyprint" not in src.lower()
