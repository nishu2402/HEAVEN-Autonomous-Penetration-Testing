"""HEAVEN — Agent Fleet coordinator (observe → plan → act, over the blackboard).

The coordinator is the one long-lived agent. Every other role is stateless and
cheap; the coordinator holds the loop and the budget. Each iteration it:

  1. **Observe** — snapshot the blackboard (confirmed findings + scope + the
     surface discovered so far) into a read-only :class:`FleetState`.
  2. **Plan** — ask every role that serves the active mode to PROPOSE tasks. Roles
     never talk to each other; they only read the shared state, so planning is
     deterministic, cheap, and auditable.
  3. **Prioritise** — order proposals by their planner prior, biased (when the
     cross-engagement knowledge graph has evidence) toward techniques that have
     worked on similar targets before.
  4. **Act** — run the batch through the bounded :class:`AgentScheduler`, whose
     executor is the propose→verify honesty gate. Only oracle-confirmed output is
     persisted.
  5. **Score / terminate** — stop on objective-met, budget, iteration cap, or when
     a whole planning cycle yields no new work (the surface is covered).

Before finalising, the adversarial reviewers (FP critic + coverage gap) are
guaranteed a pass, and the confirmed findings are run through the combined-risk
correlation engine — so the run ends with an attack-path view, not just a list.

Nothing here is required to have an LLM: with a deterministic brain the roles use
their rule-based paths and the whole loop still runs end to end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from heaven.ai.fleet.blackboard import Blackboard, host_of
from heaven.ai.fleet.brain import FleetBrain
from heaven.ai.fleet.executor import FleetExecutor
from heaven.ai.fleet.metrics import FleetMetrics
from heaven.ai.fleet.registry import all_roles, roles_for_mode
from heaven.ai.fleet.roles import (
    KIND_NOOP,
    KIND_REVIEW,
    AgentRole,
    AgentTask,
    FleetState,
)
from heaven.ai.fleet.scheduler import AgentScheduler, Scheduler
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.coordinator")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _objective_met(findings: list[dict], objective: str) -> bool:
    """Whether any finding satisfies the free-text objective (same matcher the
    autonomous loop uses, kept local so the fleet has no import cycle)."""
    if not objective:
        return False
    keys = [k.strip().lower() for k in objective.split() if len(k) > 3]
    if not keys:
        return False
    for f in findings:
        blob = (str(f.get("vuln_type", "")) + " " + str(f.get("title", ""))).lower()
        if all(k in blob for k in keys):
            return True
    return False


@dataclass
class FleetRunSummary:
    """Serialisable record of one fleet run — the audit trail and the report seed."""

    started_at: float = 0.0
    ended_at: float = 0.0
    active_mode: str = "full"
    objective: str = ""
    objective_met: bool = False
    stop_reason: str = ""
    iterations_run: int = 0
    authorized: bool = False

    total_findings: int = 0
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    hosts_engaged: list[str] = field(default_factory=list)
    top_findings: list[dict[str, Any]] = field(default_factory=list)

    brain: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    combined_risk: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    iterations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return round((self.ended_at or time.time()) - self.started_at, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_mode": self.active_mode,
            "objective": self.objective,
            "objective_met": self.objective_met,
            "stop_reason": self.stop_reason,
            "iterations_run": self.iterations_run,
            "authorized": self.authorized,
            "duration_s": self.duration_s,
            "total_findings": self.total_findings,
            "severity_breakdown": self.severity_breakdown,
            "hosts_engaged": self.hosts_engaged,
            "top_findings": self.top_findings,
            "brain": self.brain,
            "metrics": self.metrics,
            "combined_risk": self.combined_risk,
            "coverage": self.coverage,
            "iterations": self.iterations,
        }


class FleetCoordinator:
    """Drives the fleet loop. Construct one per run.

    ``roles`` defaults to the full roster (five primitives + one lead per backend
    mode); a caller may inject a subset for a focused run or a test. ``scheduler``
    and ``executor`` are injectable for hermetic testing; by default the executor
    is the real propose→verify gate over ``blackboard``.
    """

    def __init__(
        self,
        blackboard: Blackboard,
        base_config: Any,
        *,
        brain: Optional[FleetBrain] = None,
        metrics: Optional[FleetMetrics] = None,
        authorized: bool = False,
        authorized_targets: Optional[dict[str, Any]] = None,
        roles: Optional[list[AgentRole]] = None,
        executor: Optional[FleetExecutor] = None,
        scheduler: Optional[Scheduler] = None,
    ):
        self.blackboard = blackboard
        self.base_config = base_config
        self.metrics = metrics or FleetMetrics()
        self.brain = brain or FleetBrain(metrics=self.metrics)
        self.authorized = authorized
        self.roles = roles if roles is not None else all_roles()
        self.executor = executor or FleetExecutor(
            blackboard, base_config, brain=self.brain,
            metrics=self.metrics, authorized=authorized,
            authorized_targets=authorized_targets,
        )
        self.scheduler = scheduler or AgentScheduler(
            self.executor.execute, authorized=authorized, metrics=self.metrics,
        )

    async def run(
        self,
        *,
        seed_targets: dict[str, list[str]],
        objective: str = "",
        active_mode: str = "full",
        max_iterations: int = 6,
        time_budget_s: Optional[float] = 1800.0,
        on_iteration: Optional[Callable[[dict], None]] = None,
    ) -> FleetRunSummary:
        summary = FleetRunSummary(
            started_at=time.time(), active_mode=active_mode,
            objective=objective, authorized=self.authorized,
        )
        started = time.monotonic()
        history: list[AgentTask] = []
        roles = roles_for_mode(active_mode, self.roles)
        logger.info(
            "fleet run: mode=%s roles=%d authorized=%s budget=%ss",
            active_mode, len(roles), self.authorized, time_budget_s,
        )

        stop_reason = "max_iterations_reached"
        iter_n = 0
        while iter_n < max_iterations:
            elapsed = time.monotonic() - started
            remaining = (time_budget_s - elapsed) if time_budget_s else None
            if remaining is not None and remaining <= 0:
                stop_reason = "time_budget_exhausted"
                break

            state = self._snapshot(seed_targets, objective, iter_n, active_mode, history)
            if objective and _objective_met(state.findings, objective):
                summary.objective_met = True
                stop_reason = "objective_met"
                break

            proposals = await self._plan(state, roles)
            done = state.done_keys()
            actionable = [
                t for t in proposals
                if t.kind != KIND_NOOP and t.dedupe_key() not in done
            ]
            if not actionable:
                stop_reason = "converged: attack surface covered"
                break

            actionable = self._prioritise(actionable, state)
            findings_before = len(state.findings)

            outcomes = await self.scheduler.run(
                actionable, time_budget_s=remaining, done_keys=done,
            )
            for o in outcomes:
                if not o.skipped:
                    history.append(o.task)

            after = self._snapshot(seed_targets, objective, iter_n, active_mode, history)
            findings_after = len(after.findings)
            trace = {
                "n": iter_n,
                "proposed": len(actionable),
                "ran": sum(1 for o in outcomes if not o.skipped),
                "skipped": sum(1 for o in outcomes if o.skipped),
                "new_findings": max(0, findings_after - findings_before),
                "by_role": _count_by_role(actionable),
            }
            summary.iterations.append(trace)
            iter_n += 1
            if on_iteration is not None:
                try:
                    on_iteration(trace)
                except Exception:  # noqa: BLE001 — a flaky consumer never breaks a run
                    logger.debug("on_iteration callback raised; ignoring", exc_info=True)

        summary.iterations_run = iter_n
        summary.stop_reason = stop_reason

        # Guarantee the adversarial reviewers get a pass before we finalise, even
        # if the loop stopped early. Advisory only — they never add a finding.
        await self._final_review(seed_targets, objective, active_mode, history)

        self._finalise(summary, history)
        summary.ended_at = time.time()
        logger.info(
            "fleet run finished: %d iter(s), %d findings, stop=%s",
            summary.iterations_run, summary.total_findings, summary.stop_reason,
        )
        return summary

    # ── loop stages ────────────────────────────────────────────────────────
    def _snapshot(self, seed_targets, objective, iter_n, active_mode, history) -> FleetState:
        return self.blackboard.snapshot(
            seed_targets=seed_targets, objective=objective, iteration=iter_n,
            active_mode=active_mode, history=history, authorized=self.authorized,
        )

    async def _plan(self, state: FleetState, roles: list[AgentRole]) -> list[AgentTask]:
        proposals: list[AgentTask] = []
        for role in roles:
            try:
                tasks = await role.propose(state, self.brain)
            except Exception as e:  # noqa: BLE001 — a role never aborts planning
                logger.debug("role %s propose failed: %s", getattr(role, "name", "?"), e,
                             exc_info=True)
                continue
            for t in tasks or []:
                self.metrics.proposed(t.role or getattr(role, "name", ""), t.mode, 1)
            proposals.extend(tasks or [])
        return proposals

    def _prioritise(self, tasks: list[AgentTask], state: FleetState) -> list[AgentTask]:
        """Highest planner prior first, gently boosted by knowledge-graph priors
        when they exist. Deterministic and cheap; memory is an optimisation, never
        a requirement, and its absence changes nothing but order."""
        priors = self._technique_priors(state)

        def _score(t: AgentTask) -> float:
            boost = 0.0
            tech = str((t.params or {}).get("technique_id") or "")
            if tech and tech in priors:
                boost = 0.15 * priors[tech]
            return float(t.estimated_value) + boost

        return sorted(tasks, key=_score, reverse=True)

    def _technique_priors(self, state: FleetState) -> dict[str, float]:
        """Best-effort {technique_id: posterior_success_rate}. Empty on any error
        or when the knowledge graph has no evidence yet."""
        try:
            from heaven.ai.knowledge_graph import TargetProfile
            # A coarse profile from what the blackboard knows. Sparse by design:
            # the priors only sharpen ordering, never gate a task, so a thin
            # profile simply yields generic (often empty) priors.
            profile = TargetProfile(web_tech=_web_tech_hint(state.findings))
        except Exception:  # noqa: BLE001
            return {}
        priors: dict[str, float] = {}
        for row in self.blackboard.technique_priors(profile, top_n=10):
            tech = str(row.get("technique") or "")
            if tech:
                priors[tech] = float(row.get("posterior_success_rate") or 0.0)
        return priors

    async def _final_review(self, seed_targets, objective, active_mode, history) -> None:
        """Run any not-yet-executed FP-critic / coverage-gap review tasks once, so
        every run ends with an adversarial pass. Deduped against history."""
        state = self._snapshot(seed_targets, objective, 0, active_mode, history)
        if not state.has_findings():
            return
        from heaven.ai.fleet.registry import CriticRole, GapRole
        review_tasks: list[AgentTask] = []
        for role in (CriticRole(), GapRole()):
            try:
                review_tasks.extend(await role.propose(state, self.brain) or [])
            except Exception:  # noqa: BLE001
                logger.debug("final review propose failed", exc_info=True)
        done = state.done_keys()
        pending = [t for t in review_tasks
                   if t.kind == KIND_REVIEW and t.dedupe_key() not in done]
        if pending:
            await self.scheduler.run(pending, done_keys=done)

    # ── finalise ───────────────────────────────────────────────────────────
    def _finalise(self, summary: FleetRunSummary, history: list[AgentTask]) -> None:
        findings = self.blackboard.findings()
        summary.total_findings = len(findings)
        sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        hosts: set[str] = set()
        for f in findings:
            s = str(f.get("severity", "info") or "info").lower()
            if s in sev:
                sev[s] += 1
            h = host_of(str(f.get("target") or ""))
            if h:
                hosts.add(h)
        summary.severity_breakdown = sev
        summary.hosts_engaged = sorted(hosts)
        summary.top_findings = _top_findings(findings)
        summary.metrics = self.metrics.to_dict()
        try:
            summary.brain = self.brain.describe()
        except Exception:  # noqa: BLE001
            summary.brain = {}
        summary.combined_risk = self._combined_risk(findings)
        summary.coverage = self._coverage_from_history(history)

    @staticmethod
    def _combined_risk(findings: list[dict]) -> dict[str, Any]:
        """Attack-path / combined-risk view over the confirmed findings. Trimmed to
        the headline numbers plus the top paths (the full detail lives in the store
        and the report)."""
        if not findings:
            return {}
        try:
            from heaven.vulnscan.correlation import correlate_findings
            full = correlate_findings(findings)
        except Exception:  # noqa: BLE001
            logger.debug("combined-risk correlation failed", exc_info=True)
            return {}
        return {
            "total_combinations": full.get("total_combinations", 0),
            "critical_combinations": full.get("critical_combinations", 0),
            "confirmed_combinations": full.get("confirmed_combinations", 0),
            "total_attack_paths": full.get("total_attack_paths", 0),
            "highest_priority": full.get("highest_priority", 0.0),
            "attack_paths": (full.get("attack_paths") or [])[:5],
        }

    def _coverage_from_history(self, history: list[AgentTask]) -> dict[str, Any]:
        """Modes the fleet actually exercised, so the report can state coverage
        honestly (which modes ran, on how many targets)."""
        by_mode: dict[str, int] = {}
        for t in history:
            if t.mode:
                by_mode[t.mode] = by_mode.get(t.mode, 0) + 1
        return {"modes_exercised": by_mode, "modes_count": len(by_mode)}


# ── module helpers ─────────────────────────────────────────────────────────
def _build_scheduler(
    executor: FleetExecutor,
    engagement_store: Any,
    *,
    engagement_name: str,
    authorized: bool,
    authorized_targets: dict[str, Any],
    metrics: FleetMetrics,
) -> Optional[Scheduler]:
    """Pick the scheduler for this run.

    Returns a :class:`~heaven.ai.fleet.distributed.DistributedScheduler` when the
    operator opted into scale-out (``HEAVEN_FLEET_WORKERS>1``) AND the engagement
    store is a real on-disk store whose ``.db`` the workers can share; otherwise
    ``None``, so the coordinator falls back to its default in-process scheduler.
    Kept out of the hot path: import the distributed module lazily so a normal
    single-process run never pays for it."""
    from heaven.ai.fleet.distributed import distributed_enabled

    db_path = getattr(engagement_store, "db_path", None)
    if not distributed_enabled() or db_path is None:
        return None
    from heaven.ai.fleet.distributed import DistributedScheduler

    logger.info("fleet scale-out enabled: sharing engagement DB across workers")
    return DistributedScheduler(
        executor.execute, db_path=str(db_path), engagement_name=engagement_name,
        authorized=authorized, authorized_targets=authorized_targets, metrics=metrics,
    )


def _authorized_targets(
    seed_targets: dict[str, list[str]], blackboard: Blackboard
) -> dict[str, list[str]]:
    """Build the scope-guard input for the executor backstop: the operator's seeds
    plus the engagement's in-scope entries, keeping deliberately domain-wide entries
    (kind='domain' / wildcard) in the ``domains`` bucket so their subtrees stay in
    scope while a lone-host engagement authorises exactly its hosts."""
    ips: list[str] = [str(h) for h in (seed_targets.get("ips") or [])]
    urls: list[str] = [str(u) for u in (seed_targets.get("urls") or [])]
    domains: list[str] = list(blackboard.scope_domains())
    for s in blackboard.scope():
        s = str(s)
        if "://" in s:
            urls.append(s)
        elif s.startswith("*.") or s.startswith("."):
            domains.append(s)
        else:
            ips.append(s)
    return {"ips": ips, "urls": urls, "domains": domains}


def _web_tech_hint(findings: list[dict]) -> str:
    """Best-effort comma-joined web-stack labels from findings, for the knowledge
    graph's target fingerprint. Empty when nothing web-ish was seen."""
    stack: set[str] = set()
    for f in findings:
        for key in ("product", "technology", "web_tech"):
            v = f.get(key) if isinstance(f, dict) else None
            if v:
                stack.add(str(v).lower())
    return ",".join(sorted(stack))


def _count_by_role(tasks: list[AgentTask]) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in tasks:
        if t.role:
            out[t.role] = out.get(t.role, 0) + 1
    return out


def _top_findings(findings: list[dict], limit: int = 10) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "info")).lower(), 9),
                       -float(f.get("confidence", 0) or 0)),
    )
    out: list[dict[str, Any]] = []
    for f in ordered[:limit]:
        out.append({
            "title": str(f.get("title", ""))[:80],
            "severity": f.get("severity", "info"),
            "target": str(f.get("target", ""))[:60],
            "cve_id": f.get("cve_id", ""),
            "confidence": round(float(f.get("confidence", 0) or 0), 2),
        })
    return out


async def run_fleet(
    seed_targets: dict[str, list[str]],
    engagement_store: Any,
    base_config: Any,
    *,
    objective: str = "",
    active_mode: str = "full",
    max_iterations: int = 6,
    time_budget_s: float = 1800.0,
    authorized: bool = False,
    engagement_name: str = "",
    on_iteration: Optional[Callable[[dict], None]] = None,
) -> FleetRunSummary:
    """One-call entrypoint the CLI / API use to run the fleet.

    Mirrors :func:`heaven.ai.autonomous_loop.run_autonomous` so the fleet is a
    drop-in default-on engine over the same engagement store. Read-only unless
    ``authorized`` is set (which enables the exploit lead / active hypothesis
    verification); everything else runs at full strength with no keys."""
    blackboard = Blackboard(engagement_store, engagement_name=engagement_name)
    metrics = FleetMetrics()
    brain = FleetBrain(metrics=metrics)
    # The authorised scope the executor's backstop enforces: the seeds plus the
    # engagement's own in-scope entries (honouring deliberately domain-wide ones).
    authorized_targets = _authorized_targets(seed_targets, blackboard)
    executor = FleetExecutor(
        blackboard, base_config, brain=brain, metrics=metrics,
        authorized=authorized, authorized_targets=authorized_targets,
    )
    # Scale-out is opt-in: with HEAVEN_FLEET_WORKERS>1 and a real on-disk store,
    # scan tasks fan out across worker processes that share this engagement DB;
    # otherwise the coordinator builds the default in-process scheduler. The
    # distributed path only engages when there is a real ``.db`` to share, so a
    # stateless/dry run (or a test store) always stays single-process.
    scheduler = _build_scheduler(
        executor, engagement_store, engagement_name=engagement_name,
        authorized=authorized, authorized_targets=authorized_targets, metrics=metrics,
    )
    coordinator = FleetCoordinator(
        blackboard, base_config, brain=brain, metrics=metrics, authorized=authorized,
        authorized_targets=authorized_targets, executor=executor, scheduler=scheduler,
    )
    return await coordinator.run(
        seed_targets=seed_targets, objective=objective, active_mode=active_mode,
        max_iterations=max_iterations, time_budget_s=time_budget_s,
        on_iteration=on_iteration,
    )
