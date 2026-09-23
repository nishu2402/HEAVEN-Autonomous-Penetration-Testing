"""Phase 3 tests: the observe → plan → act coordinator.

Driven hermetically: an injected one-shot role proposes a scan per seed, and an
injected executor 'confirms' a finding without touching the network. That lets us
prove the loop's real behaviour — planning, dedup-driven convergence, budget and
iteration termination, objective-met early stop, metrics, and the finalised
summary (severity breakdown, combined-risk, coverage) — with no live scan.
"""

from __future__ import annotations

from types import SimpleNamespace

from heaven.ai.fleet import Blackboard, FleetCoordinator, run_fleet
from heaven.ai.fleet.roles import KIND_SCAN, AgentTask, FleetState


class _GrowStore:
    """Engagement store whose findings grow as the fake executor 'scans'."""

    def __init__(self):
        self._f: list[dict] = []
        self.starts = 0
        self.completes = 0

    def list_findings(self, limit=10000, **kw):
        return list(self._f)

    def list_scope(self, in_scope_only=True):
        return []

    def record_scan_start(self, *a, **k):
        self.starts += 1

    def record_scan_complete(self, *a, **k):
        self.completes += 1

    def upsert_finding(self, scan_id, finding):
        self._f.append(finding)
        return finding.get("id", "x")


class _OneShotRole:
    """Proposes exactly one scan per un-scanned seed host — deterministic."""

    name = "oneshot"
    modes = frozenset()

    async def propose(self, state: FleetState, brain):
        scanned = {t for (k, t, _m) in state.done_keys() if k == KIND_SCAN}
        out = []
        for h in state.seed_targets.get("ips", []) or []:
            if h not in scanned:
                out.append(AgentTask(kind=KIND_SCAN, role=self.name, target=h,
                                     mode="network", estimated_value=0.9))
        return out


class _FakeExecutor:
    """Confirms a single finding per scanned target, via the store's write path."""

    def __init__(self, store, sev="high", vuln="rce"):
        self.store = store
        self._n = 0
        self._sev = sev
        self._vuln = vuln

    async def execute(self, task: AgentTask) -> dict:
        if task.kind != KIND_SCAN:
            return {"noop": True}
        self._n += 1
        fid = f"f{self._n}"
        self.store.upsert_finding("fleet", {
            "id": fid, "target": task.target, "vuln_type": self._vuln,
            "title": f"{self._vuln} on {task.target}", "severity": self._sev,
            "confidence": 0.9,
        })
        return {"findings": 1, "target": task.target}


class _Brain:
    available = False
    gateway = None

    def describe(self):
        return {"tier": 0, "label": "deterministic", "available": False}


def _coord(store, **kw):
    ex = _FakeExecutor(store)
    return FleetCoordinator(
        Blackboard(store), SimpleNamespace(scan_mode=None),
        brain=_Brain(), roles=[_OneShotRole()], executor=ex, **kw,
    )


# ── the loop ─────────────────────────────────────────────────────────────────
async def test_loop_scans_seed_then_converges():
    store = _GrowStore()
    seen: list[dict] = []
    summary = await _coord(store).run(
        seed_targets={"ips": ["10.0.0.5"]}, active_mode="network",
        max_iterations=5, time_budget_s=None, on_iteration=seen.append,
    )
    # iter 0 scans the seed and confirms a finding; iter 1 has nothing new → stop.
    assert summary.stop_reason.startswith("converged")
    assert summary.iterations_run == 1
    assert summary.total_findings == 1
    assert summary.severity_breakdown["high"] == 1
    assert summary.hosts_engaged == ["10.0.0.5"]
    assert len(seen) == 1 and seen[0]["new_findings"] == 1


async def test_metrics_and_brain_recorded():
    store = _GrowStore()
    summary = await _coord(store).run(
        seed_targets={"ips": ["10.0.0.5"]}, active_mode="network",
        max_iterations=3, time_budget_s=None,
    )
    m = summary.metrics
    assert m["tasks_proposed"] >= 1 and m["tasks_run"] >= 1
    assert summary.brain.get("tier") == 0  # honest 'deterministic, AI optional'


async def test_combined_risk_present_with_findings():
    store = _GrowStore()
    summary = await _coord(store).run(
        seed_targets={"ips": ["10.0.0.5", "10.0.0.6"]}, active_mode="network",
        max_iterations=3, time_budget_s=None,
    )
    assert summary.total_findings == 2
    # correlate_findings always returns a summary dict (may have zero combinations).
    assert "total_combinations" in summary.combined_risk
    assert summary.coverage["modes_exercised"].get("network") == 2


async def test_objective_met_early_stop():
    store = _GrowStore()
    ex = _FakeExecutor(store, vuln="sql_injection")
    coord = FleetCoordinator(
        Blackboard(store), SimpleNamespace(scan_mode=None),
        brain=_Brain(), roles=[_OneShotRole()], executor=ex,
    )
    summary = await coord.run(
        seed_targets={"ips": ["10.0.0.5"]}, active_mode="network",
        objective="injection", max_iterations=5, time_budget_s=None,
    )
    # iter 0 confirms a 'sql_injection' finding; iter 1 observes it and the
    # free-text objective ('injection') matches → early stop.
    assert summary.objective_met is True
    assert summary.stop_reason == "objective_met"


async def test_iteration_cap_terminates():
    # A role that always proposes a NEW target never converges; the iteration cap
    # must stop it.
    class _Endless:
        name = "endless"
        modes = frozenset()

        async def propose(self, state, brain):
            n = state.iteration
            return [AgentTask(kind=KIND_SCAN, role=self.name,
                              target=f"10.0.0.{n}", mode="network")]

    store = _GrowStore()
    ex = _FakeExecutor(store)
    coord = FleetCoordinator(
        Blackboard(store), SimpleNamespace(scan_mode=None),
        brain=_Brain(), roles=[_Endless()], executor=ex,
    )
    summary = await coord.run(
        seed_targets={"ips": []}, active_mode="network",
        max_iterations=3, time_budget_s=None,
    )
    assert summary.stop_reason == "max_iterations_reached"
    assert summary.iterations_run == 3


# ── entrypoint smoke test (zero network, zero keys) ──────────────────────────
async def test_run_fleet_entrypoint_no_targets_is_clean():
    store = _GrowStore()
    summary = await run_fleet(
        seed_targets={"ips": [], "urls": []}, engagement_store=store,
        base_config=SimpleNamespace(scan_mode=None), active_mode="full",
        max_iterations=2, time_budget_s=5.0,
    )
    # Nothing to scan → converge immediately with zero findings, no exception.
    assert summary.total_findings == 0
    assert summary.stop_reason.startswith("converged")
    assert summary.brain  # describe() populated the honest status block
