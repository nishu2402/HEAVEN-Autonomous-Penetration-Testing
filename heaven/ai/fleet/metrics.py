"""HEAVEN — Agent Fleet metrics.

A tiny, dependency-free counter set the scheduler and roles update as a run
proceeds. It exists so the fleet can PROVE its worth honestly: how many tasks
each role proposed, how many produced a verified finding, how many the oracle
rejected, and how much brain (LLM) work was actually spent. Phase 7's benchmark
reads these to compare the fleet against the deterministic baseline.

Single event loop → plain integer increments are safe; no locking needed.
Nothing here ever raises: a metrics failure must never break a scan.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class FleetMetrics:
    tasks_proposed: int = 0
    tasks_run: int = 0
    tasks_failed: int = 0
    findings_verified: int = 0   # tasks whose oracle confirmed at least one finding
    findings_rejected: int = 0   # tasks whose oracle confirmed nothing (hypothesis pruned)
    brain_calls: int = 0
    brain_errors: int = 0
    brain_tokens: int = 0        # best-effort; providers that report usage add here
    by_role: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_mode: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def proposed(self, role: str, mode: str, n: int = 1) -> None:
        self.tasks_proposed += n
        if role:
            self.by_role[role] += n
        if mode:
            self.by_mode[mode] += n

    def ran(self, *, ok: bool) -> None:
        self.tasks_run += 1
        if not ok:
            self.tasks_failed += 1

    def verified(self, n_findings: int) -> None:
        if n_findings > 0:
            self.findings_verified += 1
        else:
            self.findings_rejected += 1

    def brain(self, *, ok: bool, tokens: int = 0) -> None:
        self.brain_calls += 1
        if not ok:
            self.brain_errors += 1
        if tokens > 0:
            self.brain_tokens += tokens

    def to_dict(self) -> dict:
        return {
            "tasks_proposed": self.tasks_proposed,
            "tasks_run": self.tasks_run,
            "tasks_failed": self.tasks_failed,
            "findings_verified": self.findings_verified,
            "findings_rejected": self.findings_rejected,
            "brain_calls": self.brain_calls,
            "brain_errors": self.brain_errors,
            "brain_tokens": self.brain_tokens,
            "by_role": dict(self.by_role),
            "by_mode": dict(self.by_mode),
        }
