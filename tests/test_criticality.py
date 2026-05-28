"""Tests for asset-criticality risk-score multiplier."""

from __future__ import annotations

import pytest


# ── EngagementStore ────────────────────────────────────────────────────


class TestScopeEntryCriticality:
    def test_add_scope_defaults_to_medium(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("10.0.0.5", kind="ip")
        entries = store.list_scope()
        assert len(entries) == 1
        assert entries[0].criticality == "medium"

    def test_add_scope_with_crown_jewel(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("https://payments.example.com", kind="url",
                        criticality="crown_jewel")
        entries = store.list_scope()
        assert entries[0].criticality == "crown_jewel"

    def test_invalid_criticality_raises(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        with pytest.raises(ValueError, match="criticality must be one of"):
            store.add_scope("x", criticality="nonsense")

    def test_criticality_multiplier_lookups(self, tmp_path):
        from heaven.engagement import CRITICALITY_MULTIPLIER, EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        for crit, expected in CRITICALITY_MULTIPLIER.items():
            target = f"host-{crit}.example.com"
            store.add_scope(target, kind="host", criticality=crit)
            assert store.criticality_multiplier(target) == expected

    def test_unknown_target_returns_neutral_multiplier(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        # not in scope at all
        assert store.criticality_multiplier("never-seen.example.com") == 1.0

    def test_prefix_match_inherits_criticality(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("https://app.example.com", kind="url",
                        criticality="crown_jewel")
        # A sub-path inherits the parent's criticality
        assert (store.criticality_multiplier("https://app.example.com/login")
                == 1.5)


# ── apply_verdict integration ─────────────────────────────────────────


class TestRiskScoreMultiplier:
    def test_risk_score_unchanged_without_engagement_store(self):
        from heaven.vulnscan.fp_suppress import (
            SuppressionVerdict, apply_verdict,
        )
        f = {"target": "x", "risk_score": 8.0}
        v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high")
        apply_verdict(f, v)
        assert f["risk_score"] == 8.0
        assert "asset_criticality" not in f

    def test_risk_score_multiplied_for_crown_jewel(self, tmp_path):
        from heaven.engagement import EngagementStore
        from heaven.vulnscan.fp_suppress import (
            SuppressionVerdict, apply_verdict,
        )
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("payments.example.com", kind="host",
                        criticality="crown_jewel")
        f = {"target": "payments.example.com", "risk_score": 8.0}
        v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high")
        apply_verdict(f, v, engagement_store=store)
        assert f["risk_score_raw"] == 8.0
        assert f["risk_score"] == 12.0          # 8.0 × 1.5
        assert f["asset_criticality"] == "crown_jewel"
        assert f["criticality_multiplier"] == 1.5

    def test_risk_score_demoted_for_low_criticality(self, tmp_path):
        from heaven.engagement import EngagementStore
        from heaven.vulnscan.fp_suppress import (
            SuppressionVerdict, apply_verdict,
        )
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("dev-vm.lab", kind="host", criticality="low")
        f = {"target": "dev-vm.lab", "risk_score": 10.0}
        v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high")
        apply_verdict(f, v, engagement_store=store)
        assert f["risk_score_raw"] == 10.0
        assert f["risk_score"] == 7.0           # 10.0 × 0.7
        assert f["asset_criticality"] == "low"

    def test_target_not_in_scope_uses_neutral_multiplier(self, tmp_path):
        from heaven.engagement import EngagementStore
        from heaven.vulnscan.fp_suppress import (
            SuppressionVerdict, apply_verdict,
        )
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        f = {"target": "not-in-scope.x", "risk_score": 5.5}
        v = SuppressionVerdict(keep=True, final_confidence=0.85, bucket="high")
        apply_verdict(f, v, engagement_store=store)
        assert f["risk_score_raw"] == 5.5
        assert f["risk_score"] == 5.5           # ×1.0
        assert f["asset_criticality"] == "medium"

    def test_missing_risk_score_defaults_to_zero(self, tmp_path):
        from heaven.engagement import EngagementStore
        from heaven.vulnscan.fp_suppress import (
            SuppressionVerdict, apply_verdict,
        )
        store = EngagementStore(tmp_path / "e.db")
        store.create_engagement("test")
        store.add_scope("x", kind="host", criticality="high")
        f = {"target": "x"}  # no risk_score key
        v = SuppressionVerdict(keep=True, final_confidence=0.5, bucket="low")
        apply_verdict(f, v, engagement_store=store)
        assert f["risk_score"] == 0.0
