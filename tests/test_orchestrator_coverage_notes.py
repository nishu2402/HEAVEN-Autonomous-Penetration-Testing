"""``_build_coverage_notes`` — the orchestrator's honest coverage caveats.

A fan-out scanner that hit its soft budget COMPLETED with partial findings, and
a task that failed / timed out contributed none. Both are silent misses unless
disclosed; this pins exactly which task states produce a note and that a
cancelled scan does not flood the report with per-task failure notes.
"""

from __future__ import annotations

from heaven.orchestrator import TaskResult, TaskState, _build_coverage_notes


def _r(name, state, *, data=None, error=None):
    return TaskResult(task_id=name, name=name, state=state, data=data, error=error)


def test_budget_exhausted_completed_task_yields_partial_note():
    results = {
        "a": _r("Authentication Security Audit", TaskState.COMPLETED,
                data={"findings": [1, 2], "budget_exhausted": True,
                      "urls_audited": 120, "urls_requested": 361}),
        "b": _r("Nmap", TaskState.COMPLETED, data={"findings": [1]}),  # clean, no note
    }
    notes = _build_coverage_notes(results)
    assert len(notes) == 1
    n = notes[0]
    assert n["type"] == "scanner_time_budget"
    assert n["scanner"] == "Authentication Security Audit"
    assert "120 of 361" in n["impact"]
    assert "PARTIAL" in n["impact"]
    assert n["remediation"]


def test_failed_and_timed_out_tasks_yield_missing_notes():
    results = {
        "a": _r("Nuclei Scanner", TaskState.FAILED, error="Timeout after 900s"),
        "b": _r("CMS Scan", TaskState.FAILED, error="connection reset"),
        "c": _r("Done", TaskState.COMPLETED, data={"findings": []}),
        "d": _r("Not run", TaskState.SKIPPED),  # intentional → no note
    }
    notes = _build_coverage_notes(results)
    kinds = {n["scanner"]: n for n in notes}
    assert set(kinds) == {"Nuclei Scanner", "CMS Scan"}
    assert "timed out" in kinds["Nuclei Scanner"]["impact"]
    assert "Timeout after 900s" in kinds["Nuclei Scanner"]["impact"]
    assert "failed" in kinds["CMS Scan"]["impact"]
    assert all(n["type"] == "scanner_incomplete" for n in notes)


def test_cancelled_scan_suppresses_failure_notes_but_keeps_salvage():
    results = {
        "a": _r("Web Fuzzer", TaskState.COMPLETED,
                data={"budget_exhausted": True, "urls_audited": 5, "urls_requested": 40}),
        "b": _r("Pending Scan", TaskState.FAILED, error="Timeout after 60s"),
        "c": _r("Also Pending", TaskState.CANCELLED),
    }
    notes = _build_coverage_notes(results, cancelled=True)
    # The completed-with-partial salvage is still worth reporting; the failures
    # are suppressed (a scan-wide stop already makes coverage obviously partial).
    assert [n["scanner"] for n in notes] == ["Web Fuzzer"]


def test_clean_scan_produces_no_notes():
    results = {
        "a": _r("Nmap", TaskState.COMPLETED, data={"findings": [1]}),
        "b": _r("SSL", TaskState.COMPLETED, data={"findings": [], "urls_audited": 3,
                                                  "urls_requested": 3}),
    }
    assert _build_coverage_notes(results) == []
