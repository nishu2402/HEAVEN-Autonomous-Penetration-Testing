"""SPA coverage notes: HEAVEN must DISCLOSE when it could not fully see a JS app.

Live regression (OWASP Juice Shop, an Angular SPA): the scan returned a handful
of shell-level findings and no warning, so the app looked 'clean' when really the
client-rendered attack surface was never reached. The crawler produced an honest
`coverage_notes` entry, but nothing consumed it — the orchestrator dropped it and
the operator never saw it. These tests pin the two halves of the fix:

  * the note itself is honest in both the no-browser and render-failed cases;
  * the crawl result always carries a `coverage_notes` list for consumers.
"""

from __future__ import annotations

from heaven.recon.web_crawler import _spa_render_gap_note


def test_gap_note_no_browser_is_actionable():
    note = _spa_render_gap_note("http://t/", ["Angular"], 5, 3, browser_failed=False)
    assert note["type"] == "spa_render_reduced_fidelity"
    assert note["browser_failed"] is False
    assert "Angular" in note["impact"]
    assert "UNDER-REPORTED" in note["impact"]
    # The remediation must name the one-command arm for full fidelity.
    assert "playwright install chromium" in note["remediation"] or "install-tools" in note["remediation"]


def test_gap_note_render_failed_is_distinct_and_louder():
    note = _spa_render_gap_note("http://t/", ["Angular"], 0, 0, browser_failed=True)
    assert note["browser_failed"] is True
    # The render-failed case is the dangerous one — the app looked reachable but
    # was not — so the wording must say the render FAILED, not merely "no browser".
    assert "FAILED" in note["impact"]
    assert "UNDER-REPORTED" in note["impact"]
    assert note["remediation"]


def test_gap_note_defaults_to_no_browser_case():
    note = _spa_render_gap_note("http://t/", ["React"])
    assert note["browser_failed"] is False
    assert "React" in note["impact"]


def test_orchestrator_summary_carries_coverage_notes_key():
    # The orchestrator must expose coverage_notes in its summary so the CLI/report
    # can surface them. Guard the contract by source inspection (a full scan is an
    # integration test); the aggregation + summary wiring must both be present.
    import inspect

    from heaven import orchestrator
    src = inspect.getsource(orchestrator)
    assert 'all_coverage_notes' in src, "orchestrator must collect coverage_notes"
    assert 'data.get("coverage_notes"' in src, "must read coverage_notes off task results"
    assert '"coverage_notes": all_coverage_notes' in src, "must expose it in the summary"
