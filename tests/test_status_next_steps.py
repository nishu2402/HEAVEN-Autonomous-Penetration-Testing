"""Regression tests for `heaven doctor`/`status` next-step suggestions.

`_engagement_status` returns the engagement's *display* name (e.g. "demo (sample
data)") for humans, but that string contains spaces/parens and is NOT a valid
`--engagement` value. The suggested copy-paste commands must use the DB stem
(`selector`), so a user can paste them verbatim. These lock that in.
"""
from __future__ import annotations

from heaven.cli.status import _next_steps


def test_report_suggestion_uses_selector_not_display_name(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "x" * 12)  # skip the init step
    report = {
        "engagement": {
            "name": "demo (sample data)",   # friendly display name
            "selector": "demo",              # DB stem — the real selector
            "exists": True,
            "total_findings": 12,
        }
    }
    steps = _next_steps(report)
    joined = "\n".join(steps)
    assert "--engagement demo" in joined
    # The un-pasteable display name must never appear in a suggested command.
    assert "demo (sample data)" not in joined


def test_scan_suggestion_uses_selector_when_no_findings(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "x" * 12)
    report = {
        "engagement": {
            "name": "ACME Q3 (external)",
            "selector": "acme-q3",
            "exists": True,
            "total_findings": 0,
        }
    }
    joined = "\n".join(_next_steps(report))
    assert "--engagement acme-q3" in joined
    assert "ACME Q3 (external)" not in joined


def test_missing_tools_suggest_install_tools(monkeypatch):
    """A missing scanner binary surfaces the one-shot `heaven install-tools` step."""
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "x" * 12)  # skip the init step
    report = {
        "engagement": {"name": "demo", "selector": "demo", "exists": True,
                       "total_findings": 3},
        "external_tools": {"nmap": True, "sqlmap": False, "ffuf": False},
    }
    joined = "\n".join(_next_steps(report))
    assert "heaven install-tools" in joined
    # Names the actual missing tools so the operator knows what will be installed.
    assert "sqlmap" in joined and "ffuf" in joined


def test_all_tools_present_no_install_step(monkeypatch):
    """When every tool is present, the install-tools step is suppressed."""
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "x" * 12)
    report = {
        "engagement": {"name": "demo", "selector": "demo", "exists": True,
                       "total_findings": 3},
        "external_tools": {"nmap": True, "sqlmap": True},
    }
    assert "install-tools" not in "\n".join(_next_steps(report))
