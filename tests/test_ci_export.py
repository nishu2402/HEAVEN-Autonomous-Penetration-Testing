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


def test_junit_strips_xml_invalid_control_chars():
    """A finding field carrying a raw control byte (a scanned banner, a reflected
    response excerpt) must not corrupt the JUnit deliverable. XML 1.0 forbids NUL
    / BEL / ESC even when escaped, so they are stripped, keeping the file
    parseable by the CI reporter."""
    findings = [{"id": "x", "vuln_type": "xss\x00", "severity": "high",
                 "title": "Reflected \x00\x07\x1b <script> & ]]> bytes",
                 "target": "http://h/?a=]]>\x07", "cve_id": "CVE-2024-1"}]
    xml = findings_to_junit(findings, fail_on="high")
    doc = minidom.parseString(xml)  # must stay well-formed despite control bytes
    # The real text survives (just the illegal bytes are gone).
    assert "Reflected" in xml and "script" in xml
    assert "\x00" not in xml and "\x07" not in xml and "\x1b" not in xml
    assert doc is not None


# ── Gate summary ─────────────────────────────────────────────────────────────

def test_summarize_gate_counts_breaching():
    g = summarize_gate(_findings(), fail_on="high")
    assert g["total"] == 3
    assert g["breaching"] == 1          # only the critical
    assert g["passed"] is False
    assert g["by_severity"]["critical"] == 1


# ── Scored-but-unlabelled finding must not slip under the gate (FP Audit 16) ──
# A finding that carries a CVSS score but no explicit `severity` label was
# bucketed `info` (the `or "info"` default), so a high-scoring finding passed a
# `fail_on=high` gate as a false green. The band is now derived from the score.

def _unlabelled_critical():
    # No "severity" key at all, but a genuine 9.8 base score.
    return [{"id": "u1", "vuln_type": "rce", "title": "Unlabelled RCE",
             "target": "http://10.0.0.9", "cvss_base": 9.8, "confidence": 0.9}]


def test_gate_counts_scored_unlabelled_finding_as_breaching():
    g = summarize_gate(_unlabelled_critical(), fail_on="high")
    assert g["by_severity"].get("critical") == 1, g["by_severity"]
    assert g["breaching"] == 1
    assert g["passed"] is False


def test_junit_fails_scored_unlabelled_finding():
    xml = findings_to_junit(_unlabelled_critical(), fail_on="high")
    assert 'failures="1"' in xml
    assert xml.count("<failure") == 1


def test_sarif_level_follows_score_when_unlabelled():
    run = findings_to_sarif(_unlabelled_critical())["runs"][0]
    r0 = run["results"][0]
    assert r0["level"] == "error"                       # critical → error, not note
    assert r0["properties"]["security-severity"] == "9.8"


def test_explicit_info_severity_is_respected_over_score():
    # An explicit label always wins; an explicitly-info finding stays info even
    # if some score is present.
    f = [{"id": "i1", "vuln_type": "x", "severity": "info", "title": "note",
          "target": "h", "cvss_base": 9.8}]
    g = summarize_gate(f, fail_on="high")
    assert g["by_severity"].get("info") == 1
    assert g["breaching"] == 0


# ── JUnit CLI gate: --fail-on actually breaks the build ──────────────────────

def _seed_engagement(tmp_path, monkeypatch):
    """A tmp engagement with one critical finding, wired as the active one."""
    from heaven.engagement import EngagementStore
    db = tmp_path / "gate.db"
    store = EngagementStore(db, create=True)
    store.upsert_finding("scan1", {
        "vuln_type": "sqli", "title": "SQL injection", "severity": "critical",
        "target": "http://t/item", "confidence": 0.9, "cvss_base": 9.8,
    })
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))
    return db


def test_export_junit_explicit_fail_on_breaks_build(tmp_path, monkeypatch):
    """`heaven export --format junit --fail-on <sev>` exits non-zero when a
    finding breaches, so a CI step fails directly (matching the documented
    behaviour), and the XML is still written for the test reporter."""
    from click.testing import CliRunner
    from heaven.cli.findings import export
    _seed_engagement(tmp_path, monkeypatch)
    out = tmp_path / "r.xml"

    res = CliRunner().invoke(
        export, ["--format", "junit", "--fail-on", "critical", "-o", str(out)])
    assert res.exit_code == 1, res.output
    assert out.exists() and out.read_text().strip()  # XML still emitted


def test_export_junit_without_fail_on_stays_exit_zero(tmp_path, monkeypatch):
    """Omitting --fail-on keeps the plain emit-XML flow on exit 0 (the CI test
    reporter decides), so existing pipelines are unaffected."""
    from click.testing import CliRunner
    from heaven.cli.findings import export
    _seed_engagement(tmp_path, monkeypatch)
    out = tmp_path / "r.xml"

    res = CliRunner().invoke(export, ["--format", "junit", "-o", str(out)])
    assert res.exit_code == 0, res.output


def test_export_junit_fail_on_none_never_gates(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli.findings import export
    _seed_engagement(tmp_path, monkeypatch)
    out = tmp_path / "r.xml"

    res = CliRunner().invoke(
        export, ["--format", "junit", "--fail-on", "none", "-o", str(out)])
    assert res.exit_code == 0, res.output


# ── `heaven repro`: the finding-level repro command must be REACHABLE ─────────
# Regression: findings.py and replay.py both registered a `replay` command, so
# the finding-level one was silently overwritten by the scan-replay and could
# never be invoked. It was renamed to `repro` to resolve the collision.

def test_repro_command_is_reachable_and_prints_one_curl(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.engagement import EngagementStore
    from heaven.cli.findings import repro

    db = tmp_path / "repro.db"
    store = EngagementStore(db, create=True)
    fid = store.upsert_finding("scan1", {
        "vuln_type": "sqli_boolean", "title": "SQLi", "severity": "high",
        "target": "http://t/item", "confidence": 0.9,
        "evidence": {"method": "GET", "request_url": "http://t/item?id=1",
                     "param": "id", "payload": "1 OR 1=1"},
    })
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))

    res = CliRunner().invoke(repro, [fid])
    assert res.exit_code == 0, res.output
    assert res.output.strip().startswith("curl"), res.output


def test_repro_unknown_finding_exits_2(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.engagement import EngagementStore
    from heaven.cli.findings import repro

    db = tmp_path / "repro2.db"
    EngagementStore(db, create=True)
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db))

    res = CliRunner().invoke(repro, ["does-not-exist"])
    assert res.exit_code == 2, res.output


def test_repro_and_scan_replay_are_distinct_commands():
    """Both commands coexist: `repro` (finding) and `replay` (scan). Regression
    for the silent name collision that made the finding command unreachable."""
    from heaven.cli import cli
    assert "repro" in cli.commands
    assert "replay" in cli.commands
    assert "repro command" in (cli.commands["repro"].help or "")
    assert "scan" in (cli.commands["replay"].help or "").lower()
