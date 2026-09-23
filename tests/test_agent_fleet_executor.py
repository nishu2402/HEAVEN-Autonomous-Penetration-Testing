"""Phase 2 tests: the propose→verify executor (the honesty gate).

These prove the executor turns a task into REAL oracle activity and persists only
what the oracle returned — never a role's own claim. The oracles themselves
(orchestrator pipeline, verify_hypotheses, fp_review, coverage grader) are
monkeypatched to hermetic fakes so the tests exercise the executor's wiring and
its persistence contract, not the network.
"""

from __future__ import annotations

from types import SimpleNamespace

from heaven.ai.fleet import (
    Blackboard,
    FleetExecutor,
    FleetMetrics,
    scan_targets_for,
)
from heaven.ai.fleet.roles import (
    KIND_HYPOTHESIS,
    KIND_NOOP,
    KIND_REVIEW,
    KIND_SCAN,
    AgentTask,
)


class _FakeStore:
    """Minimal EngagementStore stand-in that records what the executor writes."""

    def __init__(self, findings=None):
        self._findings = list(findings or [])
        self.upserts: list[tuple[str, dict]] = []
        self.started: list[tuple[str, str]] = []
        self.completed: list[str] = []

    def record_scan_start(self, scan_id, name="", mode="", config=None):
        self.started.append((scan_id, mode))

    def record_scan_complete(self, scan_id, summary, **kw):
        self.completed.append(scan_id)

    def upsert_finding(self, scan_id, finding):
        self.upserts.append((scan_id, finding))
        return finding.get("id", "x")

    def list_findings(self, limit=10000, **kw):
        return list(self._findings)


class _FakeOrch:
    def __init__(self, scan_id, summary):
        self.scan_id = scan_id
        self._summary = summary

    async def run(self):
        return self._summary


def _base_config():
    return SimpleNamespace(scan_mode=None)


# ── scan_targets_for ────────────────────────────────────────────────────────
def test_scan_targets_url_vs_host():
    u = scan_targets_for("http://t/")
    assert u["urls"] == ["http://t/"] and u["ips"] == []
    h = scan_targets_for("10.0.0.5")
    assert h["ips"] == ["10.0.0.5"] and h["urls"] == []
    # Read-only by construction: a plain fleet scan never auto-proves or chains.
    assert u["auto_prove"] is False and u["autonomous"] is False


# ── KIND_SCAN: findings come from the orchestrator, persisted verbatim ───────
async def test_scan_persists_orchestrator_findings(monkeypatch):
    import heaven.orchestrator as orch_mod

    summary = {
        "scan_id": "s1", "vulnerabilities": [
            {"id": "f1", "target": "http://t/", "vuln_type": "xss",
             "title": "XSS", "severity": "high", "confidence": 0.9},
        ],
        "findings": [], "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0,
    }

    def _fake_build(targets, config, checkpoint_store=None, scan_mode=None, **kw):
        assert scan_mode is not None
        return _FakeOrch("s1", summary)

    monkeypatch.setattr(orch_mod, "build_full_scan", _fake_build)

    store = _FakeStore()
    metrics = FleetMetrics()
    ex = FleetExecutor(Blackboard(store), _base_config(), metrics=metrics)
    out = await ex.execute(AgentTask(kind=KIND_SCAN, target="http://t/", mode="web"))

    assert out["findings"] == 1 and out["persisted"] == 1 and out["high"] == 1
    # The finding that was persisted is the orchestrator's, not anything a role made.
    assert store.upserts and store.upserts[0][1]["id"] == "f1"
    assert store.completed == ["s1"]
    assert metrics.findings_verified == 1


async def test_scan_without_target_is_skipped():
    ex = FleetExecutor(Blackboard(None), _base_config())
    out = await ex.execute(AgentTask(kind=KIND_SCAN, target="", mode="web"))
    assert out["skipped"] is True


# ── scope backstop: the executor refuses a host the operator never authorised ─
async def test_scan_out_of_scope_is_refused(monkeypatch):
    import heaven.orchestrator as orch_mod

    def _must_not_build(*a, **kw):  # pragma: no cover — asserts it is never reached
        raise AssertionError("build_full_scan must not run for an out-of-scope target")

    monkeypatch.setattr(orch_mod, "build_full_scan", _must_not_build)
    store = _FakeStore()
    # Authorised scope is exactly scanme.nmap.org; a discovered parent domain is not.
    ex = FleetExecutor(Blackboard(store), _base_config(),
                       authorized_targets={"ips": ["scanme.nmap.org"]})
    out = await ex.execute(AgentTask(kind=KIND_SCAN, target="nmap.org", mode="network"))
    assert out["skipped"] is True and "scope" in out["reason"]
    assert store.upserts == []  # nothing scanned, nothing persisted


async def test_scan_in_scope_runs_with_guard(monkeypatch):
    import heaven.orchestrator as orch_mod

    summary = {"scan_id": "s2", "vulnerabilities": [], "findings": [],
               "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    monkeypatch.setattr(orch_mod, "build_full_scan",
                        lambda *a, **kw: _FakeOrch("s2", summary))
    store = _FakeStore()
    ex = FleetExecutor(Blackboard(store), _base_config(),
                       authorized_targets={"ips": ["scanme.nmap.org"]})
    out = await ex.execute(AgentTask(kind=KIND_SCAN, target="scanme.nmap.org", mode="network"))
    assert out.get("scan_id") == "s2"  # the authorised seed scanned normally


async def test_hypothesis_out_of_scope_urls_are_filtered(monkeypatch):
    import heaven.ai.vuln_hypothesis as vh

    seen: dict = {}

    async def _fake_verify(hyps, *, authorized, **kw):
        seen["urls"] = [h.get("target_url") for h in hyps]
        return {"findings": [], "verified": 0, "rejected": len(hyps), "probed_targets": len(hyps)}

    monkeypatch.setattr(vh, "verify_hypotheses", _fake_verify)
    ex = FleetExecutor(Blackboard(_FakeStore()), _base_config(), authorized=True,
                       authorized_targets={"urls": ["http://in.scope/"]})
    task = AgentTask(kind=KIND_HYPOTHESIS, target="http://in.scope/", mode="web",
                     params={"hypotheses": [
                         {"vuln_class": "sqli", "target_url": "http://in.scope/a"},
                         {"vuln_class": "sqli", "target_url": "http://evil.example/b"},
                     ]})
    await ex.execute(task)
    # Only the in-scope hypothesis reached the verifier; the other was dropped.
    assert seen["urls"] == ["http://in.scope/a"]


# ── KIND_HYPOTHESIS: only oracle-confirmed findings persist ──────────────────
async def test_hypothesis_persists_only_verified(monkeypatch):
    import heaven.ai.vuln_hypothesis as vh

    async def _fake_verify(hyps, *, authorized, **kw):
        assert authorized is True  # the run's authorization flows through
        return {"findings": [{"id": "h1", "target": "http://t/s", "vuln_type": "sqli",
                              "severity": "high", "confidence": 0.8}],
                "verified": 1, "rejected": 1, "probed_targets": 2}

    monkeypatch.setattr(vh, "verify_hypotheses", _fake_verify)
    store = _FakeStore()
    ex = FleetExecutor(Blackboard(store), _base_config(), authorized=True)
    task = AgentTask(kind=KIND_HYPOTHESIS, target="http://t/s", mode="web",
                     params={"hypotheses": [{"vuln_class": "sqli", "target_url": "http://t/s"}]})
    out = await ex.execute(task)
    assert out["verified"] == 1 and out["persisted"] == 1
    assert store.upserts[0][1]["id"] == "h1"


async def test_hypothesis_with_no_hyps_is_skipped():
    ex = FleetExecutor(Blackboard(_FakeStore()), _base_config(), authorized=True)
    out = await ex.execute(AgentTask(kind=KIND_HYPOTHESIS, target="http://t/", params={}))
    assert out["skipped"] is True


# ── KIND_REVIEW: advisory, never adds a finding ──────────────────────────────
async def test_review_coverage_returns_grade(monkeypatch):
    import heaven.ai.coverage_grader as cg

    report = SimpleNamespace(
        grade="B", scope_coverage_pct=80.0, owasp_coverage_pct=60.0,
        untested_scope_targets=["10.0.0.9"], recommendations=["scan the DB host"],
    )

    async def _fake_grade(store, use_llm=True):
        return report

    monkeypatch.setattr(cg, "grade_engagement", _fake_grade)
    store = _FakeStore()
    ex = FleetExecutor(Blackboard(store), _base_config())
    out = await ex.execute(AgentTask(kind=KIND_REVIEW, params={"review": "coverage"}))
    assert out["grade"] == "B" and out["scope_coverage_pct"] == 80.0
    assert out["untested_targets"] == ["10.0.0.9"]
    # Advisory: nothing was written to the store.
    assert store.upserts == []


async def test_review_fp_repersists_only_changed(monkeypatch):
    import heaven.ai.fp_review as fp

    async def _fake_review(findings, review_band=(0.4, 0.7)):
        # Downgrade the first borderline finding, leave the second untouched.
        if findings:
            findings[0]["confidence"] = 0.2
            findings[0]["status"] = "false_positive"
        return findings

    monkeypatch.setattr(fp, "review_borderline_findings", _fake_review)
    store = _FakeStore(findings=[
        {"id": "a", "scan_id": "s", "confidence": 0.55, "status": "confirmed",
         "severity": "medium", "target": "http://t/"},
        {"id": "b", "scan_id": "s", "confidence": 0.6, "status": "confirmed",
         "severity": "medium", "target": "http://t/"},
    ])
    ex = FleetExecutor(Blackboard(store), _base_config())
    out = await ex.execute(AgentTask(kind=KIND_REVIEW, params={"review": "fp"}))
    assert out["reviewed"] == 2 and out["adjusted"] == 1
    # Only the changed finding was re-persisted.
    assert len(store.upserts) == 1 and store.upserts[0][1]["id"] == "a"


async def test_noop_executes_cleanly():
    ex = FleetExecutor(Blackboard(None), _base_config())
    out = await ex.execute(AgentTask(kind=KIND_NOOP, rationale="done"))
    assert out["noop"] is True
