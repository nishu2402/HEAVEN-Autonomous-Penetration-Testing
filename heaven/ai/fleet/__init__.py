"""HEAVEN — Agent Fleet.

A role-based multi-agent engine that wraps HEAVEN's existing per-mode scanners.
Roles PROPOSE work; deterministic oracles VERIFY it; only confirmed results become
findings. The whole fleet runs at full strength with no LLM and no keys (a brain,
when present, is pure enrichment).

The fleet is on by default (``fleet_enabled()``), reached through the ``heaven
fleet`` command, the Fleet page, and autonomous. It is a superset of the classic
pipeline, so classic ``heaven scan`` stays byte-for-byte the same and a process can
revert the default with ``HEAVEN_AGENT_FLEET=0``. It ships: the role/task
contracts, the blackboard seam, the intelligence-ladder
brain, the bounded scheduler, the metrics harness, the role registry (five agent
primitives + one lead per backend :class:`~heaven.config.ScanMode`), the
propose→verify executor (the honesty gate), and the observe→plan→act coordinator.
"""

from __future__ import annotations

import os

from heaven.ai.fleet.blackboard import Blackboard, host_of
from heaven.ai.fleet.brain import (
    TIER_CLOUD,
    TIER_DETERMINISTIC,
    TIER_LOCAL,
    FleetBrain,
)
from heaven.ai.fleet.metrics import FleetMetrics
from heaven.ai.fleet.roles import (
    AUTH_REQUIRED_KINDS,
    KIND_EXPLOIT_PROOF,
    KIND_HYPOTHESIS,
    KIND_NOOP,
    KIND_POSTEX,
    KIND_REVIEW,
    KIND_SCAN,
    AgentRole,
    AgentTask,
    FleetState,
    noop,
    serves_mode,
)
from heaven.ai.fleet.coordinator import FleetCoordinator, FleetRunSummary, run_fleet
from heaven.ai.fleet.distributed import (
    DistributedScheduler,
    distributed_enabled,
    fleet_workers,
)
from heaven.ai.fleet.executor import FleetExecutor, scan_targets_for
from heaven.ai.fleet.registry import (
    AUTH_REQUIRED_MODES,
    BACKEND_MODES,
    CriticRole,
    GapRole,
    HypothesisRole,
    ModeLeadRole,
    ReconRole,
    StrategistRole,
    all_roles,
    base_roles,
    default_roles,
    mode_lead_roles,
    roles_for_mode,
)
from heaven.ai.fleet.scheduler import AgentScheduler, TaskOutcome

__all__ = [
    "fleet_enabled",
    "Blackboard", "host_of",
    "FleetBrain", "TIER_DETERMINISTIC", "TIER_LOCAL", "TIER_CLOUD",
    "FleetMetrics",
    "AgentRole", "AgentTask", "FleetState", "noop", "serves_mode",
    "KIND_SCAN", "KIND_HYPOTHESIS", "KIND_EXPLOIT_PROOF", "KIND_POSTEX",
    "KIND_REVIEW", "KIND_NOOP", "AUTH_REQUIRED_KINDS",
    "AgentScheduler", "TaskOutcome",
    "DistributedScheduler", "distributed_enabled", "fleet_workers",
    "FleetExecutor", "scan_targets_for",
    "FleetCoordinator", "FleetRunSummary", "run_fleet",
    "base_roles", "default_roles", "mode_lead_roles", "all_roles", "roles_for_mode",
    "BACKEND_MODES", "AUTH_REQUIRED_MODES",
    "ReconRole", "StrategistRole", "HypothesisRole", "CriticRole", "GapRole",
    "ModeLeadRole",
]


def fleet_enabled() -> bool:
    """Whether the Agent Fleet engine is the default engine for this process.

    On by default. The fleet is a **superset** of the classic pipeline: for every
    scan task it runs the same deterministic verify oracles that power
    ``heaven scan`` and then fans out onto the surface it discovers, so it can only
    ever add coverage, never drop a finding (recall parity is proven on the labs).
    Revert to the pre-fleet default for a process with a single flag,
    ``HEAVEN_AGENT_FLEET=0`` (also ``false`` / ``no`` / ``off``).

    Classic ``heaven scan`` stays byte-for-byte the same either way: this flag
    governs the default-on state the fleet reports and the engine reached through
    ``heaven fleet`` / the Fleet page / autonomous, not the core scan command."""
    val = (os.environ.get("HEAVEN_AGENT_FLEET", "") or "").strip().lower()
    if val in ("0", "false", "no", "off"):
        return False
    # Unset (the default) or any affirmative value keeps the fleet on.
    return True
