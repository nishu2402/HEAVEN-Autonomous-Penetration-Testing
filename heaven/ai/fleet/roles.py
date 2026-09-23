"""HEAVEN — Agent Fleet core types (roles, tasks, shared state).

The fleet is a set of *roles*. A role observes the shared :class:`FleetState`
(read from the engagement blackboard) and PROPOSES :class:`AgentTask` units of
work. It never produces a finding itself: a task is dispatched to a real
deterministic oracle in ``heaven.vulnscan`` / the orchestrator, and only that
oracle's confirmed output becomes a finding. This module holds nothing but the
plain data contracts every role and the scheduler share, so it has no heavy
imports and is safe to load anywhere.

Design invariants encoded here (see the approved plan):
  * A role emits ``AgentTask``s, never findings — the honesty gate lives in the
    executor, not in the role.
  * ``AgentTask.requires_auth`` flags exploit / post-exploitation work so the
    scheduler can refuse it unless the operator passed ``--i-have-authorization``.
  * Every field is a plain type so a task/state round-trips to JSON for the API
    stream and the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Task kinds the scheduler's executor knows how to run. Kept as bare strings
# (not an Enum) so the API/WS stream and the audit log serialize them directly.
KIND_SCAN = "scan"                # run a per-mode scan of one target
KIND_HYPOTHESIS = "hypothesis"    # propose vuln hypotheses, then verify with an oracle
KIND_EXPLOIT_PROOF = "exploit_proof"  # read-only exploitation proof (authorized)
KIND_POSTEX = "postex"            # post-exploitation / lateral reuse (authorized)
KIND_REVIEW = "review"            # advisory pass (FP critic, gap analysis)
KIND_NOOP = "noop"                # nothing to do (explained, never silent)

# Kinds that touch a target beyond read-only observation. The scheduler refuses
# these unless the run is explicitly authorized.
AUTH_REQUIRED_KINDS = frozenset({KIND_EXPLOIT_PROOF, KIND_POSTEX})


@dataclass
class AgentTask:
    """One unit of work a role proposes. The executor turns it into real scanner
    activity; the task itself carries no results and no finding."""

    kind: str                              # one of the KIND_* constants above
    role: str = ""                         # name of the role that proposed it
    target: str = ""                       # URL / host / engagement-scoped id
    mode: str = ""                         # a ScanMode value ("web", "network", ...) or ""
    rationale: str = ""                    # why this task, for the audit log / UI
    estimated_value: float = 0.5           # 0..1 planner prior on usefulness
    requires_auth: bool = False            # exploit/post-ex → gated by authorization
    params: dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> tuple[str, str, str]:
        """Identity used to avoid re-running the same action across iterations."""
        return (self.kind, self.target, self.mode)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "role": self.role, "target": self.target,
            "mode": self.mode, "rationale": self.rationale,
            "estimated_value": round(float(self.estimated_value), 3),
            "requires_auth": self.requires_auth, "params": self.params,
        }


def noop(role: str, rationale: str) -> AgentTask:
    """A clean, explained 'nothing to do' — never a silent stop."""
    return AgentTask(kind=KIND_NOOP, role=role, rationale=rationale, estimated_value=0.0)


@dataclass
class FleetState:
    """Read-only snapshot a role sees each iteration, produced by the Blackboard.

    ``findings`` are compact dicts (not ORM rows) so a role can reason over them
    cheaply and they serialize straight into an LLM prompt when a brain is used.
    """

    findings: list[dict[str, Any]] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)        # in-scope target strings
    scope_domains: list[str] = field(default_factory=list)  # scoped subdomain-wide (kind=domain/wildcard)
    seed_targets: dict[str, list[str]] = field(default_factory=dict)  # {"ips":[], "urls":[]}
    objective: str = ""
    iteration: int = 0
    active_mode: str = "full"
    history: list[AgentTask] = field(default_factory=list)  # tasks already executed
    authorized: bool = False

    # ── convenience views roles use constantly ──
    def finding_ids(self) -> set[str]:
        return {str(f.get("id")) for f in self.findings if f.get("id")}

    def done_keys(self) -> set[tuple[str, str, str]]:
        return {t.dedupe_key() for t in self.history}

    def has_findings(self) -> bool:
        return bool(self.findings)


@runtime_checkable
class AgentRole(Protocol):
    """The contract every fleet role implements.

    A role is cheap to construct and stateless between calls: all state lives on
    the blackboard and arrives via ``state``. ``propose`` returns zero or more
    tasks; an empty list means "I have nothing to add right now", which is
    different from a NOOP task (an explicit, whole-fleet 'we are done' signal a
    coordinator emits).
    """

    #: Human-readable role name, used in metrics and the audit log.
    name: str
    #: ScanMode values this role serves; empty set means "every mode".
    modes: frozenset[str]

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        """Look at the shared state and propose next tasks. Must never raise for
        an ordinary empty/degraded state; return ``[]`` instead. ``brain`` is a
        :class:`heaven.ai.fleet.brain.FleetBrain` (may be deterministic-only)."""
        ...


def serves_mode(role: AgentRole, mode: str) -> bool:
    """Whether ``role`` runs under the active scan mode. Empty ``modes`` = all;
    ``full`` runs every role — the same semantics as the orchestrator's
    ``add_task(modes=...)`` gate, so agent coverage tracks scanner coverage."""
    if mode == "full":
        return True
    if not role.modes:
        return True
    return mode in role.modes
