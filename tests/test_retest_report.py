"""Regression: remediation-retest posture + rendered report.

The retest turns the scan-diff buckets into a client deliverable: how many of the
findings present at the baseline are verified fixed (remediated), still open,
reintroduced (a previously-fixed finding that returned — urgent), or newly
introduced. The remediation rate counts only the set under retest (baseline
findings); new findings never flatter or penalise it. See
``heaven.devsecops.retest_report``.
"""
from __future__ import annotations

from heaven.devsecops.diff_finder import DiffReport, FindingDiffRow
from heaven.devsecops.retest_report import render_retest_html, retest_posture


def _row(sev: str, vt: str, tgt: str, title: str = "") -> FindingDiffRow:
    return FindingDiffRow(id="x", target=tgt, vuln_type=vt, title=title or vt,
                          severity=sev, confidence=0.9)


def _mixed_report() -> DiffReport:
    r = DiffReport(baseline_scan_id="baseAAAAAA", current_scan_id="currBBBBBB")
    r.resolved = [_row("high", "sqli", "a"), _row("medium", "xss", "b"),
                  _row("low", "header", "c")]                       # 3 fixed
    r.unchanged = [_row("critical", "rce", "d"), _row("medium", "idor", "e")]  # 2 open
    r.regressed = [_row("high", "sqli", "f")]                        # 1 reintroduced
    r.new = [_row("low", "info", "g")]                               # 1 new
    return r


def test_posture_rate_counts_only_baseline_set():
    p = retest_posture(_mixed_report())
    assert p["remediated"] == 3
    assert p["still_open"] == 3          # unchanged (2) + reintroduced (1)
    assert p["reintroduced"] == 1
    assert p["newly_introduced"] == 1
    assert p["prior_total"] == 6         # remediated + still_open, NOT the new one
    assert p["remediation_rate"] == 50.0
    assert p["regressed_critical_or_high"] == 1


def test_posture_all_fixed_is_100pct():
    r = DiffReport(baseline_scan_id="b", current_scan_id="c")
    r.resolved = [_row("high", "sqli", "a"), _row("low", "hdr", "b")]
    p = retest_posture(r)
    assert p["remediation_rate"] == 100.0 and p["still_open"] == 0


def test_posture_no_baseline_findings_rate_is_none():
    r = DiffReport(baseline_scan_id="b", current_scan_id="c")
    r.new = [_row("low", "info", "g")]
    p = retest_posture(r)
    assert p["remediation_rate"] is None and p["prior_total"] == 0


def test_render_html_is_self_contained_and_labelled():
    html = render_retest_html(_mixed_report(), engagement_name="Acme Q3",
                              baseline_label="baseAAAA", current_label="currBBBB")
    assert html.lstrip().startswith("<!doctype html>")
    # Posture headline + every bucket section + the reintroduced urgency banner.
    for token in ("Remediation Retest", "50%", "Remediated", "Reintroduced",
                  "Still open", "Newly introduced", "Acme Q3", "sqli",
                  "previously-fixed"):
        assert token in html, token
    # No external resource references (CSP-safe / offline).
    assert "http://" not in html and "src=" not in html


def test_render_html_all_remediated_no_urgent_banner():
    r = DiffReport(baseline_scan_id="b", current_scan_id="c")
    r.resolved = [_row("high", "sqli", "a")]
    html = render_retest_html(r, engagement_name="E")
    assert "100%" in html
    assert "previously-fixed" not in html  # no reintroduced → no urgency banner
