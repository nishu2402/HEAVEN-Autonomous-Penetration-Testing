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
    """The diff engine anchors on scan timestamps (scans.started_at and
    scans.completed_at) and the findings' first_seen_at / last_seen_at,
    because HEAVEN dedupes findings globally on content-hash — the per-row
    scan_id is only the most-recent scan that observed the finding."""

    def _store(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test", client="x")
        return store

    def _add(self, store, scan_id, fid_seed, vt="sqli_boolean", target="10.0.0.1",
             severity="high", confidence=0.9, status="open"):
        d = {
            "target": target, "vuln_type": vt,
            "title": f"{vt} on {target}", "severity": severity,
            "confidence": confidence, "param": fid_seed,
        }
        fid = store.upsert_finding(scan_id, d)
        if status != "open":
            store.update_finding_status(fid, status)
        return fid

    def _mark_scan_complete(self, store, scan_id, ts: str):
        """Manually backdate a scan's completed_at — needed so tests can
        deterministically order finding timestamps vs. scan completion."""
        import sqlite3
        with sqlite3.connect(store.db_path) as c:
            c.execute("UPDATE scans SET status='completed', completed_at=? WHERE id=?",
                      (ts, scan_id))
            c.commit()

    def _backdate_finding(self, store, fid, first: str, last: str):
        """Manually pin a finding's first_seen/last_seen for deterministic tests."""
        import sqlite3
        with sqlite3.connect(store.db_path) as c:
            c.execute("UPDATE findings SET first_seen_at=?, last_seen_at=? WHERE id=?",
                      (first, last, fid))
            c.commit()

    def test_new_finding_first_seen_after_baseline_complete(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        # Baseline ran first, completed at T1
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        # Current scan started later at T2, completed at T3
        store.record_scan_start("curr", name="c", mode="x", config={})
        self._mark_scan_complete(store, "curr", "2020-01-01T11:00:00+00:00")
        # Add a finding "discovered" at 10:30 — AFTER baseline completed
        fid = self._add(store, "curr", "p1")
        self._backdate_finding(store, fid, "2020-01-01T10:30:00+00:00", "2020-01-01T10:30:00+00:00")
        d = compute_diff(store, "base", "curr")
        assert len(d.new) == 1
        assert d.new[0].id == fid

    def test_resolved_when_last_seen_before_current_start(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        # Finding was around in baseline timeframe
        fid = self._add(store, "base", "p1")
        self._backdate_finding(store, fid, "2020-01-01T09:30:00+00:00", "2020-01-01T09:45:00+00:00")
        # Current scan starts later — finding has not been re-observed since
        store.record_scan_start("curr", name="c", mode="x", config={})
        # record_scan_start sets started_at = now(), which is later than 09:45
        d = compute_diff(store, "base", "curr")
        assert len(d.resolved) == 1
        assert d.resolved[0].id == fid

    def test_regressed_when_fixed_finding_observed_again(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        fid = self._add(store, "base", "p1", status="fixed")
        # Finding observed in baseline window
        self._backdate_finding(store, fid, "2020-01-01T09:30:00+00:00", "2020-01-01T09:45:00+00:00")
        # Current scan starts later
        store.record_scan_start("curr", name="c", mode="x", config={})
        # Re-upsert SAME content → updates last_seen_at to now (which is >= curr.started_at)
        self._add(store, "curr", "p1")
        d = compute_diff(store, "base", "curr")
        assert len(d.regressed) == 1, f"expected regression, got {d.to_dict()['summary']}"
        assert d.regressed[0].id == fid

    def test_unchanged_when_open_and_recently_observed(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        fid = self._add(store, "base", "p1")
        self._backdate_finding(store, fid, "2020-01-01T09:30:00+00:00", "2020-01-01T09:45:00+00:00")
        store.record_scan_start("curr", name="c", mode="x", config={})
        # Re-observe — last_seen_at moves to now()
        self._add(store, "curr", "p1")
        d = compute_diff(store, "base", "curr")
        # status is still open, last_seen >= curr.started_at, first_seen <= base.completed_at
        assert len(d.unchanged) == 1
        assert d.unchanged[0].id == fid

    def test_summary_counts(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        # Finding A: present in baseline, NOT re-observed in current → resolved
        fid_a = self._add(store, "base", "p1", severity="high")
        self._backdate_finding(store, fid_a, "2020-01-01T09:30:00+00:00", "2020-01-01T09:45:00+00:00")
        # Finding B: fixed in baseline, re-observed in current → regressed
        fid_b = self._add(store, "base", "p2", severity="high", status="fixed")
        self._backdate_finding(store, fid_b, "2020-01-01T09:30:00+00:00", "2020-01-01T09:45:00+00:00")

        store.record_scan_start("curr", name="c", mode="x", config={})
        # Re-observe finding B → moves last_seen to now (regressed)
        self._add(store, "curr", "p2", severity="high")
        # New finding C in current
        fid_c = self._add(store, "curr", "p3", severity="critical")
        self._backdate_finding(store, fid_c, "2020-01-01T10:30:00+00:00", "2020-01-01T10:30:00+00:00")

        d = compute_diff(store, "base", "curr")
        s = d.to_dict()["summary"]
        assert s["new"] == 1, f"expected 1 new, got {s}"
        assert s["resolved"] == 1, f"expected 1 resolved, got {s}"
        assert s["regressed"] == 1, f"expected 1 regressed, got {s}"
        assert s["critical_new"] == 1

    def test_compute_diff_raises_for_unknown_scan(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff
        store = self._store(tmp_path)
        with pytest.raises(ValueError):
            compute_diff(store, "nope-base", "nope-curr")

    def test_markdown_report_renders(self, tmp_path):
        from heaven.devsecops.diff_finder import compute_diff, render_diff_markdown
        store = self._store(tmp_path)
        store.record_scan_start("base", name="b", mode="x", config={})
        self._mark_scan_complete(store, "base", "2020-01-01T10:00:00+00:00")
        store.record_scan_start("curr", name="c", mode="x", config={})
        fid = self._add(store, "curr", "p1", severity="critical")
        self._backdate_finding(store, fid, "2020-01-01T10:30:00+00:00", "2020-01-01T10:30:00+00:00")
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
