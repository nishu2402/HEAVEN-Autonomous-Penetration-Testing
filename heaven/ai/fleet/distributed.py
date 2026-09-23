"""HEAVEN — Agent Fleet distributed worker pool (opt-in scale-out).

The default fleet runs its per-iteration batch of tasks through the in-process
:class:`~heaven.ai.fleet.scheduler.AgentScheduler` (bounded asyncio concurrency).
That already handles large CIDRs and thousands of endpoints, because the heavy
work inside each scan is itself I/O-bound and bounded by the orchestrator's own
per-segment semaphores. For the very biggest engagements an operator can opt into
a **cross-process** pool by setting ``HEAVEN_FLEET_WORKERS`` above 1: the scan
tasks in each coordinator iteration are then dispatched to a
:class:`concurrent.futures.ProcessPoolExecutor`, so scans run on separate CPUs and
separate event loops at the same time.

Why this is real and not a stub, and why it "matches single-process findings":

  * **Shared blackboard.** Every worker opens its own :class:`EngagementStore`
    against the SAME engagement ``.db``. That store already runs in WAL mode with a
    30-second busy timeout and opens a fresh connection per operation, which is
    exactly SQLite's supported multi-process pattern: concurrent readers plus a
    serialized writer, with contention absorbed by the busy timeout rather than
    lost as "database is locked". Findings a worker verifies are written straight
    to the shared store, so when the coordinator re-snapshots after the batch it
    sees every worker's findings — identical to the single-process path.

  * **Same honesty gate.** A worker runs the exact same
    :class:`~heaven.ai.fleet.executor.FleetExecutor` a scan task would run in
    process: recon -> detectors -> validation -> FP-suppression -> scoring, then
    persist only what a deterministic oracle confirmed. No agent authors a finding
    in a worker any more than it does in the parent. The scope backstop travels
    with the task (the worker rebuilds the same :class:`ScopeGuard` from the
    authorized targets), so a worker refuses an out-of-scope target the same way.

  * **Same authorization gate.** :func:`refuse_reason` is applied in the parent
    before a task is ever dispatched, so an exploit / post-ex task on an
    un-authorized run never reaches a worker.

Only ``KIND_SCAN`` tasks are distributed. They are brain-independent (the scan
pipeline is fully deterministic) and independent of each other (they share only
the DB, which is built for it), so they parallelise cleanly across processes.
Brain-bound and whole-engagement-review tasks (hypothesis / FP-critic / coverage)
stay in the coordinator process, where the single :class:`FleetBrain` and its
concurrency cap live; running them in a brainless worker would silently downgrade
them. This split keeps distributed output identical to single-process output.

The pool is created per :meth:`run` call inside a ``with`` block, so it always
tears its worker processes down cleanly and never leaks them across iterations.
"""

from __future__ import annotations

import asyncio
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from heaven.ai.fleet.metrics import FleetMetrics
from heaven.ai.fleet.roles import KIND_SCAN, AgentTask
from heaven.ai.fleet.scheduler import AgentScheduler, Executor, TaskOutcome, refuse_reason
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.distributed")


def fleet_workers() -> int:
    """How many worker processes the distributed pool should use.

    ``HEAVEN_FLEET_WORKERS`` (default 1 = in-process, no scale-out). Capped so an
    over-eager value can never spawn an unbounded number of processes; a sensible
    ceiling is the smaller of the request, a hard cap, and the machine's CPU count
    (scans are I/O-bound, so oversubscribing CPUs buys little and costs memory)."""
    try:
        want = int(os.environ.get("HEAVEN_FLEET_WORKERS", "1"))
    except (TypeError, ValueError):
        return 1
    if want <= 1:
        return 1
    hard_cap = 32
    cpus = os.cpu_count() or 4
    return max(2, min(want, hard_cap, cpus * 2))


def distributed_enabled() -> bool:
    """Whether the operator opted into the cross-process worker pool."""
    return fleet_workers() > 1


def _live_runner(runner: Callable[..., Any]) -> Callable[..., Any]:
    """Re-resolve a module-level worker function to the CURRENT object in its
    module, so a stale reference can never break dispatch.

    ``ProcessPoolExecutor`` pickles the target by its module + qualname and, on the
    pickling side, verifies the object it looks up in ``sys.modules`` IS the object
    being pickled. If this module was reloaded after the caller captured its
    reference (e.g. a test that purges ``heaven.*`` from ``sys.modules`` and
    re-imports), the two differ and pickling raises. Fetching the live attribute
    here realigns them; if anything is off we fall back to the reference as given
    (and the scheduler's in-process retry is the ultimate backstop)."""
    try:
        module = sys.modules.get(getattr(runner, "__module__", "") or "")
        name = getattr(runner, "__name__", "") or ""
        live = getattr(module, name, None) if module is not None else None
        if callable(live):
            return live  # type: ignore[no-any-return]
    except Exception as e:  # noqa: BLE001 — never let re-resolution break a run
        logger.debug("worker re-resolution fell back to the given reference: %s", e)
    return runner


@dataclass
class _ScanJob:
    """Everything a worker needs to run one scan task against the shared store.

    An internal, typed builder only. It is NEVER pickled to a worker as-is: the
    scheduler serialises it to a plain ``dict`` (built-in types) at the process
    boundary, so no custom class identity is pickled. That keeps dispatch immune to
    a module reload — if this module is purged from ``sys.modules`` and re-imported
    (which some tests do), a stale ``_ScanJob`` class would otherwise fail to
    pickle. The task is carried as its field kwargs so the worker reconstructs an
    identical :class:`AgentTask` from its own fresh import."""

    db_path: str
    engagement_name: str
    authorized: bool
    authorized_targets: Optional[dict[str, Any]]
    task_kwargs: dict[str, Any] = field(default_factory=dict)


def _run_scan_job(job: dict[str, Any]) -> dict[str, Any]:
    """Worker entrypoint: run one scan task in this process and return its result.

    ``job`` is a plain dict (built-in types only) so it pickles cleanly under the
    ``spawn`` start method regardless of module-reload state. Runs at module scope
    so it is importable and picklable. It rebuilds the config from the environment,
    opens the shared engagement store, and runs the real executor — the same code
    path the in-process scheduler runs, so the findings are identical. Never raises
    across the process boundary: any failure is returned as an error dict the
    parent turns into a failed :class:`TaskOutcome`."""
    try:
        from heaven.ai.fleet.blackboard import Blackboard
        from heaven.ai.fleet.executor import FleetExecutor
        from heaven.config import get_config
        from heaven.engagement import EngagementStore

        cfg = get_config()
        store = EngagementStore(job["db_path"])
        blackboard = Blackboard(store, engagement_name=job["engagement_name"])
        # brain=None: scan tasks are fully deterministic, so a worker needs no LLM.
        executor = FleetExecutor(
            blackboard, cfg, brain=None, authorized=job["authorized"],
            authorized_targets=job["authorized_targets"],
        )
        task = AgentTask(**job["task_kwargs"])
        return asyncio.run(executor.execute(task))
    except Exception as e:  # noqa: BLE001 — never let a worker crash the pool
        return {"__worker_error__": f"{type(e).__name__}: {e}"}


def _probe_job(job: dict[str, Any]) -> dict[str, Any]:
    """Deterministic, offline worker used to validate the cross-process plumbing.

    It exercises the exact thing the distributed path relies on — a worker process
    opening the SHARED engagement store and writing a finding to it — without the
    non-determinism of a live network scan (that path is covered by the live
    benchmark). The scheduler's ``job_runner`` seam swaps this in for tests; the
    default runner is always :func:`_run_scan_job`. ``job`` is a plain dict, so it
    is reload-immune. Runs at module scope so it is importable and picklable."""
    try:
        from heaven.ai.fleet.blackboard import Blackboard
        from heaven.engagement import EngagementStore

        target = (job.get("task_kwargs") or {}).get("target", "")
        store = EngagementStore(job["db_path"])
        blackboard = Blackboard(store, engagement_name=job["engagement_name"])
        scan_id = f"fleet-probe-{os.getpid()}-{target}"
        written = blackboard.record_findings(scan_id, [{
            "id": f"probe-{target}", "target": target, "vuln_type": "probe",
            "title": f"probe finding for {target}", "severity": "info",
            "confidence": 1.0,
        }])
        return {"findings": written, "target": target, "worker_pid": os.getpid()}
    except Exception as e:  # noqa: BLE001
        return {"__worker_error__": f"{type(e).__name__}: {e}"}


class DistributedScheduler:
    """A drop-in replacement for :class:`AgentScheduler` that fans scan tasks out
    across worker processes. Same ``run`` signature, so the coordinator uses it
    without knowing the difference.

    Non-scan tasks (hypothesis / review) run through an embedded in-process
    :class:`AgentScheduler`, so the single brain and its concurrency cap stay in
    one process. Scan tasks are dispatched to a :class:`ProcessPoolExecutor`."""

    def __init__(
        self,
        base_executor: Executor,
        *,
        db_path: str,
        engagement_name: str,
        authorized: bool,
        authorized_targets: Optional[dict[str, Any]],
        workers: Optional[int] = None,
        metrics: Optional[FleetMetrics] = None,
        job_runner: Any = _run_scan_job,
    ):
        self.db_path = db_path
        self.engagement_name = engagement_name
        self.authorized = authorized
        self.authorized_targets = authorized_targets
        self.workers = workers or fleet_workers()
        self.metrics = metrics or FleetMetrics()
        # The pool target. Production always runs the real scan (``_run_scan_job``);
        # a test swaps in the deterministic offline probe to validate the plumbing.
        self._job_runner = job_runner
        # Non-scan kinds keep running exactly as they do single-process.
        self._inproc = AgentScheduler(
            base_executor, authorized=authorized, metrics=self.metrics,
        )

    async def run(
        self,
        tasks: list[AgentTask],
        *,
        time_budget_s: Optional[float] = None,
        done_keys: Optional[set[tuple[str, str, str]]] = None,
    ) -> list[TaskOutcome]:
        if not tasks:
            return []
        done = set(done_keys or set())
        scan_tasks: list[AgentTask] = []
        other_tasks: list[AgentTask] = []
        early: list[TaskOutcome] = []

        for t in tasks:
            if t.kind != KIND_SCAN:
                other_tasks.append(t)
                continue
            # Apply the same structural gates the async scheduler applies, up front,
            # so a refused/duplicate scan is never shipped to a worker process.
            refusal = refuse_reason(t, self.authorized)
            if refusal is not None:
                logger.info("fleet task refused (%s): %s -> %s", refusal, t.kind, t.target)
                early.append(TaskOutcome(task=t, skipped=True, skip_reason=refusal))
                continue
            key = t.dedupe_key()
            if key in done:
                early.append(TaskOutcome(task=t, skipped=True, skip_reason="already executed"))
                continue
            done.add(key)
            scan_tasks.append(t)

        # Non-scan tasks: delegate wholesale to the in-process scheduler (it does
        # its own refuse/dedupe/budget, sharing the same metrics object).
        other_outcomes: list[TaskOutcome] = []
        if other_tasks:
            other_outcomes = await self._inproc.run(
                other_tasks, time_budget_s=time_budget_s, done_keys=done_keys,
            )

        scan_outcomes = await self._run_scans(scan_tasks, time_budget_s=time_budget_s)
        return early + scan_outcomes + other_outcomes

    async def _run_scans(
        self, tasks: list[AgentTask], *, time_budget_s: Optional[float],
    ) -> list[TaskOutcome]:
        if not tasks:
            return []
        loop = asyncio.get_running_loop()
        runner = _live_runner(self._job_runner)
        # Serialise each job to a plain dict at the boundary so only built-in types
        # cross to the worker (reload-immune; see _ScanJob).
        jobs = [(t, asdict(self._job_for(t))) for t in tasks]
        outcomes: list[TaskOutcome] = []
        max_workers = max(1, min(self.workers, len(jobs)))
        logger.info(
            "fleet distributed: dispatching %d scan(s) across %d worker process(es)",
            len(jobs), max_workers,
        )
        try:
            with ProcessPoolExecutor(max_workers=max_workers) as pool:
                futures = [
                    (t, loop.run_in_executor(pool, runner, job))
                    for (t, job) in jobs
                ]
                results = await asyncio.gather(
                    *(f for (_t, f) in futures), return_exceptions=True,
                )
        except BrokenProcessPool as e:
            # The whole pool died (OOM-killer, a segfault in a native probe). Do
            # not lose the batch: run these scans in-process, which is slower but
            # always correct, and record the degradation honestly.
            logger.warning("fleet worker pool broke (%s); running scans in-process", e)
            return await self._inproc.run(tasks)

        # Any task whose worker died or failed to return is RETRIED in-process, so
        # a flaky/killed worker (resource pressure, a transient spawn failure)
        # never silently drops a scan — the distributed path is as reliable as the
        # single-process one, just faster when the workers are healthy.
        retry_tasks: list[AgentTask] = []
        for (t, _f), res in zip(futures, results):
            outcome = self._outcome_from_result(t, res)
            if not outcome.ok:
                logger.warning(
                    "fleet worker task failed (%s); retrying in-process: %s",
                    outcome.error, t.target,
                )
                retry_tasks.append(t)
                continue
            self.metrics.ran(ok=True)
            # Mirror the in-process executor's finding accounting so distributed
            # and single-process runs report identical metrics. Only a scan that
            # actually ran reports a "findings" count (a refused/out-of-scope scan
            # returns without one), so we gate on the key exactly as the executor
            # gates its own metrics.verified call.
            if isinstance(outcome.result, dict) and "findings" in outcome.result:
                self.metrics.verified(int(outcome.result.get("findings") or 0))
            outcomes.append(outcome)

        if retry_tasks:
            # The in-process scheduler runs the real executor and records its own
            # ran/verified metrics, so reliability and accounting both hold.
            outcomes.extend(await self._inproc.run(retry_tasks))
        return outcomes

    def _job_for(self, task: AgentTask) -> _ScanJob:
        return _ScanJob(
            db_path=str(self.db_path),
            engagement_name=self.engagement_name,
            authorized=self.authorized,
            authorized_targets=self.authorized_targets,
            task_kwargs={
                "kind": task.kind, "role": task.role, "target": task.target,
                "mode": task.mode, "rationale": task.rationale,
                "estimated_value": task.estimated_value,
                "requires_auth": task.requires_auth, "params": task.params,
            },
        )

    @staticmethod
    def _outcome_from_result(task: AgentTask, res: Any) -> TaskOutcome:
        if isinstance(res, BaseException):
            return TaskOutcome(task=task, ok=False, error=f"{type(res).__name__}: {res}")
        if isinstance(res, dict) and "__worker_error__" in res:
            return TaskOutcome(task=task, ok=False, error=str(res["__worker_error__"]))
        return TaskOutcome(task=task, ok=True, result=res if isinstance(res, dict) else {})
