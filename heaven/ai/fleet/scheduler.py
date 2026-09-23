"""HEAVEN — Agent Fleet scheduler.

Runs a batch of :class:`AgentTask`s through a bounded worker pool. The scheduler
is deliberately dumb about *what* a task does: the caller injects an ``executor``
coroutine that turns a task into real scanner activity (the propose→verify path
lives there, in later phases). The scheduler's job is the three things a large
fleet must get right regardless of task content:

  1. **Bound concurrency.** A large logical fleet must not become an unbounded
     burst of work. Tasks run behind a semaphore (``HEAVEN_FLEET_CONCURRENCY``),
     the same discipline the orchestrator uses per segment. The FleetBrain caps
     LLM concurrency separately, so scanner work and reasoning work are each
     bounded on their own axis.
  2. **Isolate failures.** One task raising must never abort the batch — it is
     captured as a failed :class:`TaskOutcome`, mirroring the FP-review pattern.
  3. **Enforce authorization + budget structurally.** Exploit / post-exploitation
     tasks are refused unless the run is authorized, and no new task is launched
     once the wall-clock budget is spent, so the sum of fleet work stays bounded.

Nothing here persists findings; that is the executor's and the blackboard's job.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, Protocol, runtime_checkable

from heaven.ai.fleet.metrics import FleetMetrics
from heaven.ai.fleet.roles import AUTH_REQUIRED_KINDS, AgentTask
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.scheduler")

# An executor turns one task into a raw result dict (e.g. an orchestrator scan
# summary or a verify-hypotheses result). It should not raise for ordinary
# failures — but if it does, the scheduler captures it.
Executor = Callable[[AgentTask], Awaitable[dict]]


def _fleet_concurrency() -> int:
    """Max tasks executed in parallel. Distinct from brain concurrency: this
    bounds scanner work, which is itself further bounded by the orchestrator's
    per-segment semaphores when a task runs a scan."""
    try:
        return max(1, min(64, int(os.environ.get("HEAVEN_FLEET_CONCURRENCY", "8"))))
    except (TypeError, ValueError):
        return 8


def refuse_reason(task: AgentTask, authorized: bool) -> Optional[str]:
    """The structural authorization gate, shared by the in-process scheduler and
    the distributed worker pool so both refuse exactly the same tasks.

    Returns a human-readable reason when ``task`` must not run (an exploit /
    post-exploitation kind, or a scan a mode-lead flagged ``requires_auth``, on an
    un-authorized run), else ``None``. Kept as one function so the two schedulers
    can never drift on what "authorized" means."""
    if task.kind in AUTH_REQUIRED_KINDS or task.requires_auth:
        if not authorized:
            return "authorization required (exploit/post-ex gated)"
    return None


@dataclass
class TaskOutcome:
    task: AgentTask
    ok: bool = False
    result: dict = field(default_factory=dict)
    error: str = ""
    duration_s: float = 0.0
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "task": self.task.to_dict(),
            "ok": self.ok, "error": self.error,
            "duration_s": round(self.duration_s, 2),
            "skipped": self.skipped, "skip_reason": self.skip_reason,
        }


@runtime_checkable
class Scheduler(Protocol):
    """What the coordinator needs from a scheduler: run a batch of tasks and give
    back one outcome each. Both the in-process :class:`AgentScheduler` and the
    opt-in :class:`~heaven.ai.fleet.distributed.DistributedScheduler` satisfy this,
    so the coordinator can be handed either without knowing which."""

    async def run(
        self,
        tasks: list[AgentTask],
        *,
        time_budget_s: Optional[float] = None,
        done_keys: Optional[set[tuple[str, str, str]]] = None,
    ) -> list["TaskOutcome"]:
        ...


class AgentScheduler:
    """Bounded, failure-isolated batch runner for fleet tasks."""

    def __init__(
        self,
        executor: Executor,
        *,
        authorized: bool = False,
        concurrency: Optional[int] = None,
        metrics: Optional[FleetMetrics] = None,
    ):
        self.executor = executor
        self.authorized = authorized
        self.concurrency = concurrency or _fleet_concurrency()
        self.metrics = metrics or FleetMetrics()

    def _refuse(self, task: AgentTask) -> Optional[str]:
        """Return a skip reason if this task must not run, else ``None``."""
        return refuse_reason(task, self.authorized)

    async def run(
        self,
        tasks: list[AgentTask],
        *,
        time_budget_s: Optional[float] = None,
        done_keys: Optional[set[tuple[str, str, str]]] = None,
    ) -> list[TaskOutcome]:
        """Execute ``tasks`` with bounded concurrency. ``done_keys`` lets a caller
        skip tasks already executed in prior iterations. ``time_budget_s`` caps the
        wall-clock: tasks not yet started when it is exhausted are skipped."""
        if not tasks:
            return []
        sem = asyncio.Semaphore(self.concurrency)
        deadline = (time.monotonic() + time_budget_s) if time_budget_s else None
        seen = set(done_keys or set())

        async def _one(task: AgentTask) -> TaskOutcome:
            # Structural gates first — cheap, and they never touch the network.
            refusal = self._refuse(task)
            if refusal is not None:
                logger.info("fleet task refused (%s): %s → %s", refusal, task.kind, task.target)
                return TaskOutcome(task=task, skipped=True, skip_reason=refusal)
            key = task.dedupe_key()
            if key in seen:
                return TaskOutcome(task=task, skipped=True, skip_reason="already executed")
            seen.add(key)
            if deadline is not None and time.monotonic() >= deadline:
                return TaskOutcome(task=task, skipped=True, skip_reason="budget exhausted")

            async with sem:
                if deadline is not None and time.monotonic() >= deadline:
                    return TaskOutcome(task=task, skipped=True, skip_reason="budget exhausted")
                t0 = time.monotonic()
                try:
                    result = await self.executor(task)
                    outcome = TaskOutcome(task=task, ok=True, result=result or {},
                                          duration_s=time.monotonic() - t0)
                except Exception as e:  # noqa: BLE001 — one task never aborts the batch
                    logger.warning("fleet task failed (%s → %s): %s", task.kind, task.target, e)
                    outcome = TaskOutcome(task=task, ok=False, error=f"{type(e).__name__}: {e}",
                                          duration_s=time.monotonic() - t0)
            self.metrics.ran(ok=outcome.ok)
            return outcome

        results = await asyncio.gather(*[_one(t) for t in tasks])
        return list(results)
