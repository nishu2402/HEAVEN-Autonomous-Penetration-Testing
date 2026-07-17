"""
HEAVEN — regression tests for the dynamic-progress + engagement-fallback batch.

Covers:

* **Dynamic scan progress** — an in-flight task earns fractional, time-based
  credit so the bar advances continuously instead of teleporting between task
  completions ("2 → 12 → 35 → 89"). Progress stays monotonic and never shows a
  premature 100 while the scan is still running.
* **Smarter engagement fallback** — when nothing is explicitly selected and no
  active pointer exists, the app resolves to the most-populated real engagement
  on disk instead of a blank ``default`` (which silently absorbed scans and made
  work look "lost").
"""

from __future__ import annotations

import time
import types

from heaven.engagement import (
    DEMO_DB_NAME,
    EngagementStore,
    best_populated_engagement,
)
from heaven.orchestrator import ScanProgress


# ── Dynamic progress: time-based partial credit for in-flight tasks ──────────

class TestProgressPartialCredit:
    def test_empty_is_zero(self):
        assert ScanProgress(scan_id="x", total_tasks=0).progress_pct == 0.0

    def test_completed_only(self):
        p = ScanProgress(scan_id="x", total_tasks=4, completed_tasks=1)
        assert 24.9 <= p.progress_pct <= 25.1

    def test_running_task_earns_fraction(self):
        # 1 done + a task 30s into its 60s expected window → ~0.5 credit.
        p = ScanProgress(scan_id="x", total_tasks=4, completed_tasks=1)
        p.running["t2"] = (time.time() - 30, 60)
        # (1 + 0.5) / 4 * 100 = 37.5
        assert 35.0 <= p.progress_pct <= 40.0

    def test_just_started_adds_almost_nothing(self):
        p = ScanProgress(scan_id="y", total_tasks=2)
        p.running["a"] = (time.time(), 60)
        assert p.progress_pct < 5.0

    def test_long_running_task_caps_at_ninety_percent_of_its_weight(self):
        # A task running far past its expected duration contributes at most 0.9,
        # so the last 10% lands only on real completion.
        p = ScanProgress(scan_id="z", total_tasks=1)
        p.running["a"] = (time.time() - 10_000, 60)
        assert 89.0 <= p.progress_pct <= 91.0

    def test_never_premature_hundred(self):
        # Even with everything "done" the property clamps below 100 — the final
        # 100 is set by the runner once run() returns the summary.
        p = ScanProgress(scan_id="z", total_tasks=4, completed_tasks=4)
        assert p.progress_pct <= 99.0

    def test_completion_does_not_regress(self):
        # A task finishing adds a full 1.0 while removing its <=0.9 running
        # credit, so the number only ever moves up.
        p = ScanProgress(scan_id="z", total_tasks=4, completed_tasks=1)
        p.running["t2"] = (time.time() - 45, 60)   # ~0.75 credit
        before = p.progress_pct
        p.running.pop("t2")
        p.completed_tasks = 2
        assert p.progress_pct >= before


# ── Smarter engagement fallback ──────────────────────────────────────────────

def _store_with_findings(path, cves):
    s = EngagementStore(path)
    for cve in cves:
        s.upsert_finding("scan1", {
            "host": "10.0.0.1", "port": 80, "vuln_type": "vulnerable_service",
            "cve": cve, "confidence": 0.9,
        })
    return s


class TestBestPopulatedEngagement:
    def _point_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "heaven.config.get_config",
            lambda: types.SimpleNamespace(data_dir=tmp_path),
        )

    def test_picks_richest(self, tmp_path, monkeypatch):
        eng = tmp_path / "engagements"
        eng.mkdir()
        _store_with_findings(eng / "alpha.db", ["CVE-2020-1", "CVE-2020-2", "CVE-2020-3"])
        _store_with_findings(eng / "beta.db", ["CVE-2020-9"])
        self._point_config(tmp_path, monkeypatch)
        assert best_populated_engagement() == "alpha"

    def test_none_when_no_dir(self, tmp_path, monkeypatch):
        self._point_config(tmp_path, monkeypatch)
        assert best_populated_engagement() is None

    def test_none_when_all_empty(self, tmp_path, monkeypatch):
        eng = tmp_path / "engagements"
        eng.mkdir()
        EngagementStore(eng / "empty.db")  # created but no findings/scans
        self._point_config(tmp_path, monkeypatch)
        assert best_populated_engagement() is None

    def test_skips_demo_db(self, tmp_path, monkeypatch):
        eng = tmp_path / "engagements"
        eng.mkdir()
        _store_with_findings(eng / f"{DEMO_DB_NAME}.db", ["CVE-2020-1", "CVE-2020-2"])
        _store_with_findings(eng / "real.db", ["CVE-2020-9"])
        self._point_config(tmp_path, monkeypatch)
        assert best_populated_engagement() == "real"


class TestResolverFallback:
    def test_precedence(self, monkeypatch):
        import heaven.api.server as srv
        monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

        # No pointer, but a populated engagement exists → use it, not 'default'.
        monkeypatch.setattr(srv, "_get_active_engagement", lambda: None)
        monkeypatch.setattr(srv, "_best_populated_engagement", lambda: "alpha")
        assert srv._resolve_engagement_name() == "alpha"

        # The active pointer still wins over the populated fallback.
        monkeypatch.setattr(srv, "_get_active_engagement", lambda: "ptr")
        assert srv._resolve_engagement_name() == "ptr"

        # An explicit name wins over everything.
        assert srv._resolve_engagement_name("explicit") == "explicit"

        # HEAVEN_ENGAGEMENT env wins over the pointer + fallback.
        monkeypatch.setenv("HEAVEN_ENGAGEMENT", "enveng")
        assert srv._resolve_engagement_name() == "enveng"
        monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

        # Nothing populated → the historical 'default'.
        monkeypatch.setattr(srv, "_get_active_engagement", lambda: None)
        monkeypatch.setattr(srv, "_best_populated_engagement", lambda: None)
        assert srv._resolve_engagement_name() == "default"
