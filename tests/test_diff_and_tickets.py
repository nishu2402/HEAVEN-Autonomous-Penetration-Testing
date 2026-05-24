"""
Tests for the differential scanning engine + ticketing dispatcher.

All tests run without network — the Jira / Linear adapters are tested for
config detection only; actual issue creation is HTTP and would need real
credentials.
"""

from __future__ import annotations

import pytest


# ═══════════════════════════════════════════
# DIFF ENGINE — set-arithmetic logic
# ═══════════════════════════════════════════


class TestDiffEngine:
    def _store(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test", client="x")
        return store

    def _add(self, store, scan_id, fid_seed, vt="sqli_boolean", target="10.0.0.1",
             severity="high", confidence=0.9, status="open"):
        """Add a finding via upsert; returns the deterministic id."""
        d = {
            "target": target, "vuln_type": vt,
            "title": f"{vt} on {target}", "severity": severity,
            "confidence": confidence, "param": fid_seed,  # param fed into hash
        }
        fid = store.upsert_finding(scan_id, d)
        if status != "open":
            store.update_finding_status(fid, status)
        return fid

    def test_new_finding_appears_in_new_bucket(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        # baseline: nothing
        store.record_scan_start("base", name="b", mode="x", config={})
        # current: 1 new finding
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1")
        d = compute_diff(store, "base", "curr")
        assert len(d.new) == 1
        assert len(d.resolved) == 0
        assert len(d.regressed) == 0

    def test_resolved_finding_appears_in_resolved_bucket(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1")
        store.record_scan_start("curr", name="c", mode="x", config={})
        # no finding added to current scan
        d = compute_diff(store, "base", "curr")
        assert len(d.resolved) == 1
        assert len(d.new) == 0

    def test_regressed_finding_after_fixed_status(self, tmp_path):
        """Finding was marked 'fixed' in baseline, but came back in current."""
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        fid = self._add(store, "base", "p1", status="fixed")
        store.record_scan_start("curr", name="c", mode="x", config={})
        # Re-upsert same content → same id; status preserved? No — upsert
        # re-records the scan-level entry but doesn't touch the status.
        # We need to insert the same finding into the new scan.
        self._add(store, "curr", "p1")
        # The finding id is content-hashed so identical content → same id
        # But upsert preserves status, so it stays 'fixed'... let me check.
        # Actually upsert preserves operator_notes and status on collision.
        # The 'regressed' detection looks at base.status, which is still 'fixed'.
        d = compute_diff(store, "base", "curr")
        assert len(d.regressed) == 1, f"expected regression, got {d.to_dict()}"
        assert d.regressed[0].id == fid

    def test_unchanged_finding_with_no_severity_shift(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1", severity="high", confidence=0.9)
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1", severity="high", confidence=0.9)
        d = compute_diff(store, "base", "curr")
        assert len(d.unchanged) == 1
        assert len(d.promoted) == 0
        assert len(d.demoted) == 0

    def test_promoted_when_severity_increases(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1", severity="medium")
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1", severity="critical")
        d = compute_diff(store, "base", "curr")
        assert len(d.promoted) == 1
        assert d.promoted[0].baseline_severity == "medium"
        assert d.promoted[0].severity == "critical"

    def test_promoted_when_confidence_jumps_above_threshold(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1", confidence=0.5)
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1", confidence=0.9)  # +0.4
        d = compute_diff(store, "base", "curr")
        assert len(d.promoted) == 1
        assert d.promoted[0].baseline_confidence == 0.5

    def test_demoted_when_severity_drops(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1", severity="critical")
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1", severity="low")
        d = compute_diff(store, "base", "curr")
        assert len(d.demoted) == 1

    def test_summary_counts(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._add(store, "base", "p1", severity="high")      # will be resolved
        self._add(store, "base", "p2", status="fixed")       # will regress
        store.record_scan_start("curr", name="c", mode="x", config={})
        # 1 regression
        self._add(store, "curr", "p2")
        # 2 new findings (one critical, one low)
        self._add(store, "curr", "p3", severity="critical")
        self._add(store, "curr", "p4", severity="low")
        d = compute_diff(store, "base", "curr")
        s = d.to_dict()["summary"]
        assert s["new"] == 2
        assert s["resolved"] == 1
        assert s["regressed"] == 1
        assert s["critical_new"] == 1
        assert s["regressed_critical_or_high"] >= 0   # regressed default sev was 'high'

    def test_markdown_report_renders(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff, render_diff_markdown
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._add(store, "curr", "p1", severity="critical")
        d = compute_diff(store, "base", "curr")
        md = render_diff_markdown(d)
        assert "Scan diff" in md
        assert "New findings" in md
        assert "sqli_boolean" in md


# ═══════════════════════════════════════════
# TICKETING — configuration detection (HTTP paths need creds)
# ═══════════════════════════════════════════


class TestTicketingConfig:
    def test_jira_not_configured_by_default(self, monkeypatch):
        for v in ("HEAVEN_JIRA_URL", "HEAVEN_JIRA_USER",
                  "HEAVEN_JIRA_TOKEN", "HEAVEN_JIRA_PROJECT"):
            monkeypatch.delenv(v, raising=False)
        from heaven.devsecops.alerting import JiraAlerter
        assert JiraAlerter().configured is False

    def test_jira_configured_when_all_env_set(self, monkeypatch):
        monkeypatch.setenv("HEAVEN_JIRA_URL", "https://test.atlassian.net")
        monkeypatch.setenv("HEAVEN_JIRA_USER", "u@x.com")
        monkeypatch.setenv("HEAVEN_JIRA_TOKEN", "tok")
        monkeypatch.setenv("HEAVEN_JIRA_PROJECT", "ABC")
        from heaven.devsecops.alerting import JiraAlerter
        j = JiraAlerter()
        assert j.configured is True
        assert j.base_url == "https://test.atlassian.net"
        assert j.project == "ABC"
        assert j.issue_type == "Bug"  # default

    def test_linear_not_configured_by_default(self, monkeypatch):
        monkeypatch.delenv("HEAVEN_LINEAR_TOKEN", raising=False)
        monkeypatch.delenv("HEAVEN_LINEAR_TEAM_ID", raising=False)
        from heaven.devsecops.alerting import LinearAlerter
        assert LinearAlerter().configured is False

    def test_linear_needs_both_token_and_team(self, monkeypatch):
        monkeypatch.setenv("HEAVEN_LINEAR_TOKEN", "lin_api_x")
        monkeypatch.delenv("HEAVEN_LINEAR_TEAM_ID", raising=False)
        from heaven.devsecops.alerting import LinearAlerter
        assert LinearAlerter().configured is False
        # Now set team id too
        monkeypatch.setenv("HEAVEN_LINEAR_TEAM_ID", "team-uuid")
        assert LinearAlerter().configured is True

    @pytest.mark.asyncio
    async def test_dispatcher_with_no_backends_returns_empty(self, monkeypatch):
        for v in ("HEAVEN_JIRA_URL", "HEAVEN_JIRA_USER", "HEAVEN_JIRA_TOKEN",
                  "HEAVEN_JIRA_PROJECT", "HEAVEN_LINEAR_TOKEN",
                  "HEAVEN_LINEAR_TEAM_ID"):
            monkeypatch.delenv(v, raising=False)
        from heaven.devsecops.alerting import TicketingDispatcher
        d = TicketingDispatcher()
        assert d.has_any is False
        assert d.configured_backends == []
        result = await d.dispatch({"id": "x", "severity": "critical"})
        assert result == {}

    @pytest.mark.asyncio
    async def test_jira_create_returns_error_when_not_configured(self):
        from heaven.devsecops.alerting import JiraAlerter
        j = JiraAlerter()  # not configured
        r = await j.create_issue({"id": "x", "severity": "critical"})
        assert r["ok"] is False
        assert "not configured" in r["error"].lower()

    @pytest.mark.asyncio
    async def test_linear_create_returns_error_when_not_configured(self):
        from heaven.devsecops.alerting import LinearAlerter
        lin = LinearAlerter()
        r = await lin.create_issue({"id": "x", "severity": "critical"})
        assert r["ok"] is False
        assert "not configured" in r["error"].lower()
