"""Phase 1 tests: the existing agents adopted as fleet roles (registry).

Every role must (a) propose the right tasks from a given blackboard state, (b)
degrade honestly with no brain — deterministic roles still work, pure-enrichment
roles add nothing rather than guessing — and (c) keep an emitted scan's mode in
lockstep with the active scan mode. No live LLM is used: the brain is a hermetic
fake and the one enriched path is exercised by monkeypatching the underlying
agent, so these tests prove the ROLE logic, not the provider.
"""

from __future__ import annotations

import pytest

from heaven.ai.fleet import (
    CriticRole,
    FleetState,
    GapRole,
    HypothesisRole,
    KIND_HYPOTHESIS,
    KIND_REVIEW,
    KIND_SCAN,
    ReconRole,
    StrategistRole,
    default_roles,
    roles_for_mode,
)
from heaven.ai.fleet.roles import AgentRole, AgentTask


class _Brain:
    """Minimal FleetBrain stand-in for role tests."""

    def __init__(self, available=False, gateway=None):
        self.available = available
        self.gateway = gateway

    def slot(self):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _cm():
            yield
        return _cm()


DET = _Brain(available=False)   # deterministic tier (no brain)


# ── registry wiring ─────────────────────────────────────────────────────────
def test_default_roles_all_satisfy_protocol():
    roles = default_roles()
    assert len(roles) == 5
    assert all(isinstance(r, AgentRole) for r in roles)


def test_roles_for_mode_tracks_scanner_gating():
    from heaven.ai.fleet import BACKEND_MODES

    # web runs the web/api-only hypothesis role; network does not.
    web_names = {r.name for r in roles_for_mode("web")}
    net_names = {r.name for r in roles_for_mode("network")}
    assert "hypothesis" in web_names
    assert "hypothesis" not in net_names
    # each focused mode runs its own lead, not another mode's.
    assert "web-lead" in web_names and "network-lead" not in web_names
    # full runs every role: the five primitives + one lead per backend mode.
    assert len(roles_for_mode("full")) == 5 + len(BACKEND_MODES)


# ── ReconRole (deterministic) ────────────────────────────────────────────────
async def test_recon_scans_every_unscanned_seed():
    st = FleetState(seed_targets={"ips": ["10.0.0.5"], "urls": ["http://t/"]}, active_mode="full")
    tasks = await ReconRole().propose(st, DET)
    kinds = {(t.target, t.mode) for t in tasks}
    assert ("10.0.0.5", "full") in kinds
    assert ("http://t/", "web") in kinds
    assert all(t.kind == KIND_SCAN for t in tasks)


async def test_recon_focused_mode_scans_in_that_mode():
    st = FleetState(seed_targets={"ips": ["10.0.0.5"]}, active_mode="network")
    (t,) = await ReconRole().propose(st, DET)
    assert t.mode == "network"


async def test_recon_skips_already_scanned():
    hist = [AgentTask(kind=KIND_SCAN, target="10.0.0.5", mode="full")]
    st = FleetState(seed_targets={"ips": ["10.0.0.5"]}, active_mode="full", history=hist)
    assert await ReconRole().propose(st, DET) == []


# ── StrategistRole (deterministic chains from findings) ──────────────────────
async def test_strategist_builds_scan_from_findings_without_brain():
    findings = [{
        "id": "1", "target": "http://t/x", "vuln_type": "sql_injection",
        "title": "SQLi in q", "severity": "high", "confidence": 0.9,
    }]
    # The finding's host is in authorised scope (it came from scanning it), so the
    # strategist may propose a follow-on scan of it.
    st = FleetState(findings=findings, scope=["http://t/x"], active_mode="full")
    tasks = await StrategistRole().propose(st, DET)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.kind == KIND_SCAN and t.target == "t"  # host_of(http://t/x)
    assert t.params.get("technique_id")  # a MITRE technique was attached


async def test_strategist_noop_without_findings():
    assert await StrategistRole().propose(FleetState(), DET) == []


async def test_strategist_refuses_out_of_scope_finding_host():
    # A finding on a host the operator never authorised (a redirect target, say)
    # must not spawn a follow-on scan of that host.
    findings = [{
        "id": "1", "target": "http://evil.example/x", "vuln_type": "sql_injection",
        "title": "SQLi", "severity": "high", "confidence": 0.9,
    }]
    st = FleetState(findings=findings, scope=["http://t/x"], active_mode="full")
    assert await StrategistRole().propose(st, DET) == []


# ── HypothesisRole (pure enrichment) ─────────────────────────────────────────
async def test_hypothesis_adds_nothing_without_brain():
    st = FleetState(scope=["http://t/search"], active_mode="web")
    assert await HypothesisRole().propose(st, DET) == []


async def test_hypothesis_emits_verify_tasks_with_brain(monkeypatch):
    # Fake the underlying agent so no provider is contacted; prove the ROLE turns
    # hypotheses into verify tasks grouped by URL.
    from heaven.ai import vuln_hypothesis as vh

    class _FakeHyp:
        def __init__(self, cls, url, prior):
            self.vuln_class, self.target_url, self.param, self.rationale, self.prior = (
                cls, url, "q", "plausible", prior)

    class _Out:
        hypotheses = [_FakeHyp("sqli", "http://t/search", 0.8),
                      _FakeHyp("xss", "http://t/search", 0.6)]

    class _FakeAgent:
        def __init__(self, gateway=None):
            self.available = True

        async def propose(self, profile, endpoints, max_hypotheses=8):
            return _Out()

    monkeypatch.setattr(vh, "VulnHypothesisAgent", _FakeAgent)
    brain = _Brain(available=True, gateway=object())
    st = FleetState(scope=["http://t/search"], active_mode="web")
    tasks = await HypothesisRole().propose(st, brain)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.kind == KIND_HYPOTHESIS and t.target == "http://t/search"
    assert len(t.params["hypotheses"]) == 2 and t.estimated_value == pytest.approx(0.8)


# ── CriticRole (advisory) ────────────────────────────────────────────────────
async def test_critic_needs_brain_and_borderline():
    borderline = [{"id": "1", "confidence": 0.55, "severity": "medium"}]
    # no brain → nothing
    assert await CriticRole().propose(FleetState(findings=borderline), DET) == []
    # brain + borderline → one review task
    (t,) = await CriticRole().propose(FleetState(findings=borderline), _Brain(available=True))
    assert t.kind == KIND_REVIEW and t.params["review"] == "fp"
    # brain but only high-confidence findings → nothing
    solid = [{"id": "2", "confidence": 0.95, "severity": "high"}]
    assert await CriticRole().propose(FleetState(findings=solid), _Brain(available=True)) == []


# ── GapRole (deterministic self-grade, once) ─────────────────────────────────
async def test_gap_proposes_coverage_once():
    findings = [{"id": "1", "confidence": 0.9, "severity": "high"}]
    st = FleetState(findings=findings)
    (t,) = await GapRole().propose(st, DET)
    assert t.kind == KIND_REVIEW and t.params["review"] == "coverage"
    # idempotent once it is in history
    st2 = FleetState(findings=findings, history=[t])
    assert await GapRole().propose(st2, DET) == []
    # nothing to grade yet → nothing
    assert await GapRole().propose(FleetState(), DET) == []
