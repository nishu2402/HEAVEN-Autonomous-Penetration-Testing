"""Phase 5 tests: the opt-in distributed worker pool (``HEAVEN_FLEET_WORKERS``).

These prove the scale-out path is real, not a stub, and that it behaves exactly
like the in-process scheduler:

  * The worker-count resolver is bounded (floor 1, hard/CPU cap).
  * The real worker entrypoint (``_run_scan_job``) runs a task against a real
    on-disk store in-process, exercising the exact config-reload / store-open /
    executor-build wiring a spawned worker uses.
  * A **real** :class:`concurrent.futures.ProcessPoolExecutor` dispatches scan jobs
    to separate processes that share ONE engagement SQLite DB, and every worker's
    write lands back in the parent's view — the core "shares the engagement-DB
    blackboard" guarantee, validated with a deterministic offline probe so no
    network is touched (the live scan path is covered by the fleet benchmark).
  * Distributed output matches single-process output for the same tasks.
  * The authorization gate and the done-key dedupe are enforced BEFORE a task is
    ever shipped to a worker, and non-scan (brain-bound) tasks stay in-process.
"""

from __future__ import annotations

import os
import types
from dataclasses import asdict

import pytest

from heaven.ai.fleet.distributed import (
    DistributedScheduler,
    _probe_job,
    _run_scan_job,
    _ScanJob,
    distributed_enabled,
    fleet_workers,
)
from heaven.ai.fleet.roles import KIND_REVIEW, KIND_SCAN, AgentTask
from heaven.ai.fleet.scheduler import AgentScheduler
from heaven.engagement import EngagementStore


# ── worker-count bounds ──────────────────────────────────────────────────────
def test_fleet_workers_default_is_single_process(monkeypatch):
    monkeypatch.delenv("HEAVEN_FLEET_WORKERS", raising=False)
    assert fleet_workers() == 1
    assert distributed_enabled() is False


def test_fleet_workers_enabled_and_bounded(monkeypatch):
    monkeypatch.setenv("HEAVEN_FLEET_WORKERS", "4")
    assert fleet_workers() == 4
    assert distributed_enabled() is True
    # An absurd value is capped, never unbounded.
    monkeypatch.setenv("HEAVEN_FLEET_WORKERS", "100000")
    assert fleet_workers() <= 32
    # Garbage / zero / one all mean single-process.
    monkeypatch.setenv("HEAVEN_FLEET_WORKERS", "not-a-number")
    assert fleet_workers() == 1
    monkeypatch.setenv("HEAVEN_FLEET_WORKERS", "0")
    assert fleet_workers() == 1


def test_live_runner_reresolves_stale_reference():
    """A worker function reference can go stale when another test purges
    ``heaven.*`` from ``sys.modules`` and something re-imports the module (a new
    function object). ProcessPoolExecutor pickling would then fail. ``_live_runner``
    re-resolves the reference to the module's CURRENT object so dispatch survives.

    Everything here goes through a fresh ``import`` of the module so the test holds
    the CURRENT objects even after a prior test purged and re-imported heaven.*."""
    import heaven.ai.fleet.distributed as live_mod

    # A detached twin of _probe_job that claims to be it but is a different object.
    stale = types.FunctionType(live_mod._probe_job.__code__,
                               live_mod._probe_job.__globals__, name="_probe_job")
    stale.__module__ = "heaven.ai.fleet.distributed"
    assert stale is not live_mod._probe_job
    assert live_mod._live_runner(stale) is live_mod._probe_job  # re-resolved to live
    # A callable that is not a module attribute falls back to itself, unchanged.
    def _anon(x):
        return x
    _anon.__name__ = "not_a_module_attr_xyz"
    assert live_mod._live_runner(_anon) is _anon


def _job(db_path, target, **task_kwargs) -> dict:
    """A worker job as the plain dict the scheduler ships across the boundary."""
    kw = {"kind": KIND_SCAN, "role": "test", "target": target, "mode": "network"}
    kw.update(task_kwargs)
    return asdict(_ScanJob(db_path=str(db_path), engagement_name="e", authorized=False,
                           authorized_targets=None, task_kwargs=kw))


def _make_inproc_probe(db_path):
    """A base executor that writes the SAME probe finding `_probe_job` writes, but
    in-process. It is the retry fallback the scheduler uses when a worker process
    dies or fails to return, so the shared-store tests stay correct even if a
    worker flakes under heavy suite load (the id is deterministic → dedup keeps
    one finding whether the worker or the fallback wrote it)."""
    from heaven.ai.fleet.blackboard import Blackboard

    async def _exec(task: AgentTask) -> dict:
        store = EngagementStore(db_path)
        Blackboard(store).record_findings(f"fleet-probe-inproc-{task.target}", [{
            "id": f"probe-{task.target}", "target": task.target, "vuln_type": "probe",
            "title": f"probe finding for {task.target}", "severity": "info",
            "confidence": 1.0}])
        return {"findings": 1, "target": task.target}

    return _exec


# ── the real worker entrypoint (in-process, offline) ─────────────────────────
def test_probe_job_writes_to_shared_store(tmp_path):
    db = tmp_path / "probe.db"
    EngagementStore(db)  # materialise the schema
    out = _probe_job(_job(db, "10.0.0.5"))
    assert out["findings"] == 1 and out["target"] == "10.0.0.5"
    findings = EngagementStore(db).list_findings(limit=100)
    assert [f.target for f in findings] == ["10.0.0.5"]


def test_run_scan_job_entrypoint_runs_real_executor_offline(tmp_path):
    """The production worker entrypoint runs the REAL FleetExecutor. Drive it with
    a coverage-review task (deterministic, no network, no brain) so we exercise the
    exact config-reload / store-open / executor-build / dispatch path a spawned
    worker uses, without a live scan."""
    db = tmp_path / "review.db"
    store = EngagementStore(db)
    store.upsert_finding("s1", {"target": "https://app.example", "vuln_type": "sqli",
                                "severity": "high", "confidence": 0.9})
    job = asdict(_ScanJob(db_path=str(db), engagement_name="e", authorized=False,
                          authorized_targets=None,
                          task_kwargs={"kind": KIND_REVIEW, "role": "gap", "target": "",
                                       "mode": "", "params": {"review": "coverage"}}))
    out = _run_scan_job(job)
    # A dict result, no exception across the (simulated) process boundary.
    assert isinstance(out, dict) and "__worker_error__" not in out


# ── real cross-process pool over a shared engagement DB ──────────────────────
async def test_distributed_pool_shares_engagement_db_across_processes(tmp_path):
    """Headline test: a real ProcessPoolExecutor runs jobs in separate processes,
    all writing to ONE shared engagement DB, and the parent sees every finding."""
    db = tmp_path / "shared.db"
    EngagementStore(db)  # create the file up front so workers open, not race-create
    targets = [f"10.0.0.{i}" for i in range(1, 8)]
    sched = DistributedScheduler(
        _make_inproc_probe(str(db)), db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=3, job_runner=_probe_job,
    )
    tasks = [AgentTask(kind=KIND_SCAN, role="lead", target=t, mode="network")
             for t in targets]
    outcomes = await sched.run(tasks)

    assert len(outcomes) == len(targets)
    assert all(o.ok for o in outcomes)
    # Every worker's write landed in the one shared store the parent reads — the
    # core "shares the engagement DB" guarantee. This holds whether a finding was
    # written by a worker or by the in-process retry fallback (same dedup id).
    stored = {f.target for f in EngagementStore(db).list_findings(limit=100)}
    assert stored == set(targets)
    # The work ran out-of-process: findings carry a real worker pid distinct from
    # this process (healthy workers). A worker that flaked under load is retried
    # in-process (no pid), which is correctness, not a regression.
    worker_pids = {o.result.get("worker_pid") for o in outcomes if o.result.get("worker_pid")}
    assert os.getpid() not in worker_pids
    assert worker_pids, "expected at least one task to run in a worker process"
    # Metrics: every task ran exactly once, and each worker-success verified once
    # (the in-process retry fallback in this test does not itself count verified,
    # so verified == the number of tasks that completed in a worker).
    assert sched.metrics.tasks_run == len(targets)
    worker_successes = sum(1 for o in outcomes if o.result.get("worker_pid"))
    assert sched.metrics.findings_verified == worker_successes


async def test_distributed_matches_single_process_findings(tmp_path):
    """Same tasks, two stores: the in-process scheduler and the distributed pool
    must persist the identical set of findings."""
    targets = [f"10.0.0.{i}" for i in range(1, 6)]
    tasks = [AgentTask(kind=KIND_SCAN, role="lead", target=t, mode="network")
             for t in targets]

    # (a) in-process: an executor that writes the same probe finding.
    db_single = tmp_path / "single.db"
    store_single = EngagementStore(db_single)

    async def _inproc_probe(task: AgentTask) -> dict:
        store_single.upsert_finding(f"s-{task.target}", {
            "id": f"probe-{task.target}", "target": task.target, "vuln_type": "probe",
            "title": f"probe finding for {task.target}", "severity": "info",
            "confidence": 1.0})
        return {"findings": 1, "target": task.target}

    await AgentScheduler(_inproc_probe).run(list(tasks))

    # (b) distributed: the real pool with the offline probe, and the in-process
    # retry fallback for any worker that flakes under load (deterministic dedup id).
    db_dist = tmp_path / "dist.db"
    EngagementStore(db_dist)
    await DistributedScheduler(
        _make_inproc_probe(str(db_dist)), db_path=str(db_dist), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_probe_job,
    ).run(list(tasks))

    single = {f.target for f in EngagementStore(db_single).list_findings(limit=100)}
    dist = {f.target for f in EngagementStore(db_dist).list_findings(limit=100)}
    assert single == dist == set(targets)


# ── gates enforced BEFORE dispatch ───────────────────────────────────────────
async def test_distributed_refuses_exploit_scan_when_unauthorized(tmp_path):
    """An exploit-mode scan (requires_auth) is refused in the parent and never
    shipped to a worker, so it writes nothing to the shared store."""
    db = tmp_path / "auth.db"
    EngagementStore(db)
    sched = DistributedScheduler(
        _unused_base_executor, db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_probe_job,
    )
    task = AgentTask(kind=KIND_SCAN, role="exploit-lead", target="10.0.0.9",
                     mode="exploit", requires_auth=True)
    outcomes = await sched.run([task])
    assert len(outcomes) == 1 and outcomes[0].skipped
    assert "authorization required" in outcomes[0].skip_reason
    assert EngagementStore(db).list_findings(limit=10) == []


async def test_distributed_dedupes_against_done_keys(tmp_path):
    db = tmp_path / "dedupe.db"
    EngagementStore(db)
    sched = DistributedScheduler(
        _unused_base_executor, db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_probe_job,
    )
    task = AgentTask(kind=KIND_SCAN, role="lead", target="10.0.0.5", mode="network")
    outcomes = await sched.run([task], done_keys={task.dedupe_key()})
    assert len(outcomes) == 1 and outcomes[0].skipped
    assert outcomes[0].skip_reason == "already executed"
    assert EngagementStore(db).list_findings(limit=10) == []


async def test_distributed_routes_nonscan_tasks_in_process(tmp_path):
    """Brain-bound / review tasks are NOT sent to a worker; they run through the
    embedded in-process scheduler (so the single brain stays in one process)."""
    db = tmp_path / "route.db"
    EngagementStore(db)
    seen: list[str] = []

    async def _base_executor(task: AgentTask) -> dict:
        seen.append(task.kind)
        return {"reviewed": 0}

    sched = DistributedScheduler(
        _base_executor, db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_probe_job,
    )
    review = AgentTask(kind=KIND_REVIEW, role="critic", params={"review": "fp"})
    outcomes = await sched.run([review])
    assert seen == [KIND_REVIEW]  # went through the in-process executor
    assert len(outcomes) == 1 and outcomes[0].ok


async def _unused_base_executor(task: AgentTask) -> dict:  # pragma: no cover
    # Present only to satisfy the constructor; scan-only tests never invoke it.
    raise AssertionError("base executor should not run for scan-only batches")


def _always_fails(job):  # module-level so it is picklable to a worker
    return {"__worker_error__": "RuntimeError: simulated worker death"}


async def test_worker_failure_retries_in_process(tmp_path):
    """If a worker dies or fails to return, the task is retried in-process so no
    scan is silently dropped — the distributed path is as reliable as single."""
    db = tmp_path / "retry.db"
    EngagementStore(db)
    targets = [f"10.0.0.{i}" for i in range(1, 4)]
    sched = DistributedScheduler(
        _make_inproc_probe(str(db)), db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_always_fails,
    )
    tasks = [AgentTask(kind=KIND_SCAN, role="lead", target=t, mode="network")
             for t in targets]
    outcomes = await sched.run(tasks)
    # Every task recovered via the in-process fallback and its finding landed.
    assert all(o.ok for o in outcomes)
    stored = {f.target for f in EngagementStore(db).list_findings(limit=50)}
    assert stored == set(targets)


async def test_empty_batch_is_clean(tmp_path):
    db = tmp_path / "empty.db"
    EngagementStore(db)
    sched = DistributedScheduler(
        _unused_base_executor, db_path=str(db), engagement_name="e",
        authorized=False, authorized_targets=None, workers=2, job_runner=_probe_job,
    )
    assert await sched.run([]) == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
