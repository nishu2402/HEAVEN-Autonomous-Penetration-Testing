"""Regression: SARIF 2.1.0 + JUnit XML exports for CI ingestion.

The value of these exports is that a pipeline can *act* on them: SARIF needs
correct artifact locations and stable fingerprints so GitHub tracks a finding
across runs (and a numeric security-severity so it buckets it), and JUnit needs
findings above a threshold to appear as failing tests so a build can gate.
See ``heaven.devsecops.ci_export``.
"""
from __future__ import annotations

import xml.dom.minidom as minidom

from heaven.devsecops.ci_export import (
    findings_to_junit,
    findings_to_sarif,
    findings_to_sarif_str,
    summarize_gate,
)


def _findings():
    return [
        {"id": "f1", "vuln_type": "vulnerable_service", "cve": "CVE-2021-41773",
         "title": "Apache path traversal", "severity": "critical",
         "target": "http://10.0.0.9", "cvss_base": 9.8, "source": "inline_db",
         "confidence": 0.9, "cwe": "CWE-22"},
        {"id": "f2", "vuln_type": "missing_security_header", "title": "Missing CSP",
         "severity": "medium", "target": "https://10.0.0.9", "confidence": 0.9,
         "validated": True},
        {"id": "f3", "vuln_type": "spf_missing", "title": "SPF missing",
         "severity": "low", "target": "example.com"},
    ]


# ── SARIF ────────────────────────────────────────────────────────────────────

def test_sarif_shape_and_version():
    s = findings_to_sarif(_findings(), engagement_name="Acme")
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert len(run["results"]) == 3
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert "Acme" in run["tool"]["driver"]["name"]


def test_sarif_location_is_the_target_not_unknown():
    """The old exporter read a non-existent 'asset' key → every uri was 'unknown'."""
    run = findings_to_sarif(_findings())["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "http://10.0.0.9"


def test_sarif_has_fingerprints_and_security_severity():
    run = findings_to_sarif(_findings())["runs"][0]
    r0 = run["results"][0]
    assert r0["partialFingerprints"]["heavenFindingId/v1"] == "f1"
    # GitHub reads security-severity (a string number) to bucket the alert.
    assert r0["properties"]["security-severity"] == "9.8"
    assert r0["properties"]["confirmation"] == "Potential"       # banner CVE
    # A CVE rule links to its NVD page.
    assert run["tool"]["driver"]["rules"][0]["helpUri"].endswith("CVE-2021-41773")


def test_sarif_confirmation_reflects_validation():
    """A validated posture finding is Confirmed in the export."""
    run = findings_to_sarif(_findings())["runs"][0]
    header = next(r for r in run["results"] if r["ruleId"] == "missing_security_header")
    assert header["properties"]["confirmation"] == "Confirmed"


def test_sarif_str_is_valid_json():
    import json
    parsed = json.loads(findings_to_sarif_str(_findings()))
    assert parsed["version"] == "2.1.0"


# ── JUnit ────────────────────────────────────────────────────────────────────

def test_junit_is_well_formed_xml():
    xml = findings_to_junit(_findings(), engagement_name="Acme")
    minidom.parseString(xml)  # raises on malformed XML


def test_junit_fail_on_high_fails_only_critical_high():
    xml = findings_to_junit(_findings(), fail_on="high")
    # Only the critical finding is a failure; medium + low pass.
    assert 'failures="1"' in xml
    assert xml.count("<failure") == 1


def test_junit_fail_on_none_never_fails():
    xml = findings_to_junit(_findings(), fail_on="none")
    assert 'failures="0"' in xml
    assert "<failure" not in xml


def test_junit_escapes_special_characters():
    findings = [{"id": "x", "vuln_type": "xss", "severity": "high",
                 "title": 'Reflected <script> & "quotes"', "target": "http://h/?a=1&b=2"}]
    xml = findings_to_junit(findings, fail_on="high")
    minidom.parseString(xml)  # must stay well-formed despite &, <, "


# ── Gate summary ─────────────────────────────────────────────────────────────

def test_summarize_gate_counts_breaching():
    g = summarize_gate(_findings(), fail_on="high")
    assert g["total"] == 3
    assert g["breaching"] == 1          # only the critical
    assert g["passed"] is False
    assert g["by_severity"]["critical"] == 1
