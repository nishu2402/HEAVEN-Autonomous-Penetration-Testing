"""Tests for the OWASP Top 10:2025 migration — the canonical crosswalk, the
report's dynamic per-finding CVSS, and multi-step remediation rendering."""

from __future__ import annotations

from heaven.devsecops import frameworks as fw
from heaven.devsecops.compliance_report import ComplianceReportGenerator
from heaven.devsecops.vuln_kb import enrich_finding


# ── 2021 → 2025 crosswalk ────────────────────────────────────────────────────

def test_crosswalk_maps_every_2021_category_to_2025():
    cases = {
        "A01:2021 Broken Access Control": "A01:2025 Broken Access Control",
        "A02:2021 Cryptographic Failures": "A04:2025 Cryptographic Failures",
        "A03:2021 Injection": "A05:2025 Injection",
        "A04:2021 Insecure Design": "A06:2025 Insecure Design",
        "A05:2021 Security Misconfiguration": "A02:2025 Security Misconfiguration",
        "A06:2021 Vulnerable and Outdated Components":
            "A03:2025 Software Supply Chain Failures",
        "A07:2021 Identification and Authentication Failures":
            "A07:2025 Authentication Failures",
        "A08:2021 Software and Data Integrity Failures":
            "A08:2025 Software or Data Integrity Failures",
        "A09:2021 Security Logging and Monitoring Failures":
            "A09:2025 Security Logging and Alerting Failures",
        "A10:2021 Server-Side Request Forgery": "A01:2025 Broken Access Control",
    }
    for old, new in cases.items():
        assert fw.normalize_owasp(old) == new, old


def test_crosswalk_accepts_id_only_and_underscore_and_hyphen_forms():
    assert fw.owasp_2025_id("A03:2021") == "A05:2025"
    assert fw.owasp_2025_id("A03_2021") == "A05:2025"
    assert fw.owasp_2025_id("A03:2021-Injection") == "A05:2025"


def test_crosswalk_is_idempotent_on_2025_input():
    assert fw.normalize_owasp("A02:2025 Security Misconfiguration") == \
        "A02:2025 Security Misconfiguration"
    assert fw.normalize_owasp("A05:2025") == "A05:2025 Injection"


def test_crosswalk_rejects_non_owasp_strings():
    assert fw.normalize_owasp("") == ""
    assert fw.normalize_owasp("not an owasp id") == ""
    assert fw.owasp_2025_id("CWE-89") == ""


def test_canon_has_ten_unique_2025_categories():
    ids = [cid for cid, _ in fw.OWASP_2025]
    assert len(ids) == 10
    assert len(set(ids)) == 10
    assert all(cid.endswith(":2025") for cid in ids)
    # The two structural 2025 additions are present with their new names.
    names = {name for _, name in fw.OWASP_2025}
    assert "Software Supply Chain Failures" in names
    assert "Mishandling of Exceptional Conditions" in names


# ── Report renders 2025, buckets SSRF→A01 and components→A03 ──────────────────

def test_report_headings_are_2025_not_2021():
    gen = ComplianceReportGenerator()
    html = gen.generate_html_report(
        [{"vuln_type": "sql_injection", "title": "SQLi", "severity": "high",
          "target": "https://x", "owasp": "A05:2025 Injection"}], "Eng")
    assert "OWASP Top 10 (2025) Coverage" in html
    assert "(2021)" not in html


def test_ssrf_and_components_bucket_to_2025_categories():
    gen = ComplianceReportGenerator()
    assert gen._owasp_category_id({"vuln_type": "ssrf"}) == "A01:2025"
    assert gen._owasp_category_id({"vuln_type": "vulnerable_service"}) == "A03:2025"
    # A legacy 2021 tag stored on a finding is upgraded on read.
    assert gen._owasp_category_id(
        {"vuln_type": "x", "owasp": "A05:2021 Security Misconfiguration"}) == "A02:2025"


def test_verbose_error_buckets_to_new_a10():
    gen = ComplianceReportGenerator()
    assert gen._owasp_category_id({"vuln_type": "verbose_error"}) == "A10:2025"


# ── Dynamic per-finding CVSS (no longer flat-by-severity) ─────────────────────

def test_cvss_prefers_real_published_score():
    gen = ComplianceReportGenerator()
    # A real CVE base score wins over any severity default.
    assert gen._finding_cvss(
        {"vuln_type": "vulnerable_service", "severity": "critical",
         "cvss_base": 8.1}) == "8.1"


def test_cvss_varies_across_classes_of_same_severity():
    gen = ComplianceReportGenerator()
    a = gen._finding_cvss(enrich_finding(
        {"vuln_type": "request_smuggling", "severity": "high", "target": "x"}))
    b = gen._finding_cvss(enrich_finding(
        {"vuln_type": "dkim_missing", "severity": "high", "target": "x"}))
    # Two different classes must not collapse to the same severity constant.
    assert a != b
    assert float(a) > 0 and float(b) > 0


def test_cvss_ignores_severity_anchored_prediction_when_class_known():
    gen = ComplianceReportGenerator()
    # A curated class prefers its own score, not a flat predicted value.
    f = enrich_finding({"vuln_type": "sql_injection", "severity": "critical",
                        "target": "x", "predicted_cvss_score": 6.2})
    assert gen._finding_cvss(f) != "6.2"


# ── Multi-step remediation renders one step per line ─────────────────────────

def test_steps_html_breaks_numbered_inline_text():
    gen = ComplianceReportGenerator()
    out = gen._steps_html("1. Do the first thing. 2. Then the second. 3. Finally this.")
    assert out.count("<br>") == 2
    assert out.startswith("1. Do the first thing.")


def test_steps_html_keeps_newline_separated_steps():
    gen = ComplianceReportGenerator()
    out = gen._steps_html("1. Alpha\n2. Beta\n3. Gamma")
    assert out.count("<br>") == 2


def test_steps_html_does_not_split_version_numbers():
    gen = ComplianceReportGenerator()
    # "9.9" must not be treated as a step boundary.
    out = gen._steps_html("1. Upgrade OpenSSH 9.9 to a fixed release. 2. Rotate keys.")
    assert out.count("<br>") == 1
    assert "OpenSSH 9.9 to a fixed release." in out.split("<br>")[0]
