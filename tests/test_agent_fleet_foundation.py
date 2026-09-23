"""Phase 0 foundation tests for the Agent Fleet (heaven.ai.fleet).

These lock the data contracts, the offline-safe blackboard, the intelligence
ladder's tier resolution, and the bounded/failure-isolating/authorization-gated
scheduler. Everything must work with NO LLM and NO keys — that is the whole point
of the deterministic-first design, so the brain is exercised with hermetic fakes
rather than a live provider.
"""

from __future__ import annotations

from heaven.ai.fleet import (
    AgentScheduler,
    AgentTask,
    Blackboard,
    FleetBrain,
    FleetMetrics,
    FleetState,
    KIND_EXPLOIT_PROOF,
    KIND_SCAN,
    TIER_CLOUD,
    TIER_DETERMINISTIC,
    TIER_LOCAL,
    fleet_enabled,
    noop,
    serves_mode,
)
from heaven.ai.fleet.roles import AgentRole
from heaven.ai.llm_gateway import LLMRequest, LLMResponse


# ── feature flag ──────────────────────────────────────────────────────────
def test_fleet_enabled_by_default(monkeypatch):
    # On by default: the fleet is a superset of the classic pipeline (same verify
    # oracles + fan-out), so default-on can only add coverage, never drop a finding.
    monkeypatch.delenv("HEAVEN_AGENT_FLEET", raising=False)
    assert fleet_enabled() is True
    # An empty/whitespace value is still the default (on), not a revert.
    monkeypatch.setenv("HEAVEN_AGENT_FLEET", "  ")
    assert fleet_enabled() is True


def test_fleet_flag_reverts_and_affirms(monkeypatch):
    # A single explicit flag reverts a process to the pre-fleet default.
    for off in ("0", "false", "NO", "off", "Off"):
        monkeypatch.setenv("HEAVEN_AGENT_FLEET", off)
        assert fleet_enabled() is False
    # Affirmative values keep it on (harmless, since on is already the default).
    for on in ("1", "true", "YES"):
        monkeypatch.setenv("HEAVEN_AGENT_FLEET", on)
        assert fleet_enabled() is True


# ── task / state contracts ────────────────────────────────────────────────
def test_agent_task_dedupe_and_serialize():
    t = AgentTask(kind=KIND_SCAN, role="web-lead", target="http://x", mode="web")
    assert t.dedupe_key() == (KIND_SCAN, "http://x", "web")
    d = t.to_dict()
    assert d["kind"] == KIND_SCAN and d["role"] == "web-lead" and d["requires_auth"] is False


def test_noop_is_explained():
    n = noop("coordinator", "playbook exhausted")
    assert n.kind == "noop" and n.estimated_value == 0.0 and "exhausted" in n.rationale


def test_serves_mode_semantics():
    class R:
        name = "web"
        modes = frozenset({"web", "api"})
    r = R()
    assert serves_mode(r, "full") is True       # full runs every role
    assert serves_mode(r, "web") is True
    assert serves_mode(r, "network") is False

    class AllModes:
        name = "recon"
        modes = frozenset()                       # empty = every mode
    assert serves_mode(AllModes(), "cloud") is True


def test_fleet_state_views():
    st = FleetState(
        findings=[{"id": "a"}, {"id": "b"}, {"no_id": True}],
        history=[AgentTask(kind=KIND_SCAN, target="h1", mode="network")],
    )
    assert st.finding_ids() == {"a", "b"}
    assert (KIND_SCAN, "h1", "network") in st.done_keys()
    assert st.has_findings() is True


def test_roles_protocol_is_runtime_checkable():
    class Good:
        name = "x"
        modes = frozenset()

        async def propose(self, state, brain):
            return []
    assert isinstance(Good(), AgentRole)


# ── metrics ────────────────────────────────────────────────────────────────
def test_metrics_counters():
    m = FleetMetrics()
    m.proposed("web-lead", "web", 3)
    m.ran(ok=True)
    m.ran(ok=False)
    m.verified(2)
    m.verified(0)
    m.brain(ok=True, tokens=42)
    m.brain(ok=False)
    d = m.to_dict()
    assert d["tasks_proposed"] == 3 and d["by_role"]["web-lead"] == 3 and d["by_mode"]["web"] == 3
    assert d["tasks_run"] == 2 and d["tasks_failed"] == 1
    assert d["findings_verified"] == 1 and d["findings_rejected"] == 1
    assert d["brain_calls"] == 2 and d["brain_errors"] == 1 and d["brain_tokens"] == 42


# ── blackboard ──────────────────────────────────────────────────────────────
def test_blackboard_none_store_is_empty():
    bb = Blackboard(None)
    assert bb.findings() == []
    assert bb.scope() == []
    st = bb.snapshot(seed_targets={"ips": ["10.0.0.1"]}, active_mode="network")
    assert st.findings == [] and st.seed_targets == {"ips": ["10.0.0.1"]}
    assert bb.record_findings("scan1", [{"target": "x", "vuln_type": "y"}]) == 0


def test_blackboard_reads_and_writes(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(str(tmp_path / "e.db"), create=True)
    store.record_scan_start("s1", name="s1", mode="web")
    bb = Blackboard(store, engagement_name="e")
    n = bb.record_findings("s1", [
        {"target": "http://t/a", "vuln_type": "sql_injection", "title": "SQLi",
         "severity": "high", "confidence": 0.9},
        {"target": "http://t/b", "vuln_type": "xss", "title": "XSS",
         "severity": "medium", "confidence": 0.7},
    ])
    assert n == 2
    fs = bb.findings()
    assert len(fs) == 2
    assert {f["vuln_type"] for f in fs} == {"sql_injection", "xss"}
    # snapshot carries the persisted findings through unchanged in shape
    st = bb.snapshot(active_mode="web")
    assert st.finding_ids() and all(isinstance(f["confidence"], float) for f in st.findings)


# ── intelligence ladder (hermetic fakes; no network, no keys) ───────────────
class _FakeGW:
    def __init__(self, *, available=False, provider="", model="", rate_limited=False, resp=None):
        self.available = available
        self.provider = provider
        self.model = model
        self.rate_limited = rate_limited
        self._resp = resp

    async def acomplete(self, req):
        return self._resp


def test_brain_deterministic_floor_when_no_provider():
    brain = FleetBrain(gateway=_FakeGW(available=False))
    assert brain.tier == TIER_DETERMINISTIC
    assert brain.available is False
    info = brain.describe()
    assert info["tier"] == TIER_DETERMINISTIC and info["label"] == "deterministic"
    # every key the doctor/UI reads must be present and typed
    for k in ("provider", "model", "available", "rate_limited", "concurrency",
              "local_enabled", "local_can_enable"):
        assert k in info


def test_brain_tier_resolution():
    assert FleetBrain(gateway=_FakeGW(available=True, provider="ollama")).tier == TIER_LOCAL
    assert FleetBrain(gateway=_FakeGW(available=True, provider="anthropic")).tier == TIER_CLOUD
    # rate-limited cloud is configured but not currently usable
    b = FleetBrain(gateway=_FakeGW(available=True, provider="openai", rate_limited=True))
    assert b.tier == TIER_CLOUD and b.available is False


async def test_brain_think_unavailable_returns_not_ok():
    brain = FleetBrain(gateway=_FakeGW(available=False))
    resp = await brain.think(LLMRequest(prompt="hi"))
    assert resp.ok() is False and "deterministic" in (resp.error or "")


async def test_brain_think_bounded_records_metrics():
    m = FleetMetrics()
    canned = LLMResponse(text="ok", output_tokens=7)
    brain = FleetBrain(gateway=_FakeGW(available=True, provider="ollama", resp=canned), metrics=m)
    resp = await brain.think(LLMRequest(prompt="hi"))
    assert resp.ok() is True
    assert m.brain_calls == 1 and m.brain_errors == 0 and m.brain_tokens == 7


# ── scheduler ────────────────────────────────────────────────────────────────
async def test_scheduler_runs_and_isolates_failures():
    async def executor(task: AgentTask) -> dict:
        if task.target == "boom":
            raise RuntimeError("detector crashed")
        return {"target": task.target}

    m = FleetMetrics()
    sched = AgentScheduler(executor, authorized=False, metrics=m)
    tasks = [
        AgentTask(kind=KIND_SCAN, target="a", mode="web"),
        AgentTask(kind=KIND_SCAN, target="boom", mode="web"),
        AgentTask(kind=KIND_SCAN, target="c", mode="web"),
    ]
    outcomes = await sched.run(tasks)
    by_target = {o.task.target: o for o in outcomes}
    assert by_target["a"].ok is True and by_target["c"].ok is True
    assert by_target["boom"].ok is False and "detector crashed" in by_target["boom"].error
    assert m.tasks_run == 3 and m.tasks_failed == 1


async def test_scheduler_authorization_gate():
    async def executor(task: AgentTask) -> dict:
        return {"ran": task.target}

    exploit = AgentTask(kind=KIND_EXPLOIT_PROOF, target="lab", mode="exploit")

    unauth = AgentScheduler(executor, authorized=False)
    (o,) = await unauth.run([exploit])
    assert o.skipped is True and "authorization" in o.skip_reason and o.ok is False

    authed = AgentScheduler(executor, authorized=True)
    (o2,) = await authed.run([exploit])
    assert o2.ok is True and o2.result == {"ran": "lab"}


async def test_scheduler_dedup_skips_already_done():
    async def executor(task: AgentTask) -> dict:
        return {"ran": task.target}

    sched = AgentScheduler(executor, authorized=True)
    t = AgentTask(kind=KIND_SCAN, target="h", mode="network")
    outcomes = await sched.run([t], done_keys={t.dedupe_key()})
    assert outcomes[0].skipped is True and outcomes[0].skip_reason == "already executed"


async def test_scheduler_budget_skips_new_tasks():
    async def executor(task: AgentTask) -> dict:
        return {"ran": task.target}

    sched = AgentScheduler(executor, authorized=True)
    tasks = [AgentTask(kind=KIND_SCAN, target=f"h{i}", mode="network") for i in range(3)]
    outcomes = await sched.run(tasks, time_budget_s=1e-9)
    assert all(o.skipped and "budget" in o.skip_reason for o in outcomes)
