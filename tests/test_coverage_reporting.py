"""Scan coverage & completeness reporting.

Workstream B of the "no silent misses" effort: a scanner that hits its soft time
budget (salvaging partial findings) or that times out / fails (contributing
none) must be DISCLOSED, so a throttled host does not look fully scanned. The
orchestrator attaches ``coverage_notes`` to its summary; the report renders a
"Scan Coverage & Completeness" section from them, and omits it entirely when
coverage was complete (a normal report is unchanged).
"""

from __future__ import annotations

from heaven.devsecops.compliance_report import ComplianceReportGenerator

_FINDING = {"vuln_type": "no_hsts", "target": "https://x", "severity": "medium"}


def test_coverage_section_omitted_when_complete():
    g = ComplianceReportGenerator()
    assert g._coverage_section(None) == ""
    assert g._coverage_section([]) == ""
    # A note with no impact text is not renderable → still omitted.
    assert g._coverage_section([{"scanner": "X"}]) == ""


def test_coverage_section_renders_partial_and_missing():
    g = ComplianceReportGenerator()
    notes = [
        {"type": "scanner_time_budget", "scanner": "Authentication Security Audit",
         "urls_audited": 120, "urls_requested": 361,
         "impact": "Authentication Security Audit reached its time budget after "
                   "auditing 120 of 361 target(s); the rest were not scanned.",
         "remediation": "re-run with a longer per-task timeout"},
        {"type": "scanner_incomplete", "scanner": "Nuclei Scanner",
         "impact": "Nuclei Scanner timed out and contributed no findings.",
         "remediation": "re-run the scan"},
    ]
    html = g._coverage_section(notes)
    assert "Scan Coverage" in html
    assert "Authentication Security Audit" in html
    assert "Nuclei Scanner" in html
    assert "not fully assessed" in html  # the honest framing


def test_full_report_includes_coverage_only_when_notes_present():
    g = ComplianceReportGenerator()
    with_notes = g.generate_html_report(
        [_FINDING],
        coverage_notes=[{"scanner": "Web Fuzzer",
                         "impact": "Web Fuzzer reached its time budget; coverage partial."}])
    assert 'id="coverage"' in with_notes
    assert "Web Fuzzer" in with_notes

    without = g.generate_html_report([_FINDING])
    assert 'id="coverage"' not in without


def test_coverage_section_escapes_scanner_and_impact():
    g = ComplianceReportGenerator()
    html = g._coverage_section([
        {"scanner": "<script>x</script>",
         "impact": "bad & <b>markup</b> in impact"}])
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html
