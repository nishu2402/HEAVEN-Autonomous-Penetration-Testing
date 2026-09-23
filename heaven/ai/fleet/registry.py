"""HEAVEN — Agent Fleet role registry (Phase 1).

Adopts HEAVEN's existing agent primitives as first-class fleet roles behind the
:class:`~heaven.ai.fleet.roles.AgentRole` contract, with no capability change:
each role delegates to the same module that already does the work, and every role
degrades to its deterministic path (or to proposing nothing) when no brain is
available. A role never emits a finding — it proposes an :class:`AgentTask` that a
real oracle later verifies.

Roles here:
  * ``ReconRole``      — deterministic fan-out: scan every un-reconned seed
                         (mirrors the rule-based playbook's recon phase).
  * ``StrategistRole`` — wraps :class:`AttackChainPlanner`; proposes the top chain's
                         first step as a scan. Works deterministically (grounded
                         chains) and is enriched by an LLM when one is present.
  * ``HypothesisRole`` — wraps :class:`VulnHypothesisAgent`; proposes vuln-class
                         hypotheses to verify. Pure enrichment: no brain → nothing
                         (the deterministic web/api scanners already cover the
                         surface), so it never lowers precision.
  * ``CriticRole``     — schedules the borderline-finding FP second opinion
                         (:func:`review_borderline_findings`), advisory only.
  * ``GapRole``        — schedules the self-grading coverage assessment
                         (:func:`grade_engagement`), which has a deterministic path.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from heaven.ai.fleet.blackboard import host_of
from heaven.ai.fleet.roles import (
    KIND_HYPOTHESIS,
    KIND_REVIEW,
    KIND_SCAN,
    AgentRole,
    AgentTask,
    FleetState,
    serves_mode,
)
from heaven.feedback import ScopeGuard
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.registry")


@asynccontextmanager
async def _noguard() -> AsyncIterator[None]:
    yield


def _guard(brain: Any):
    """Hold an LLM slot only when a brain will actually be used, so purely
    deterministic role work is never throttled by the LLM concurrency cap."""
    return brain.slot() if getattr(brain, "available", False) else _noguard()


def _scan_mode(state: FleetState, is_url: bool) -> str:
    """Keep an emitted scan's mode in lockstep with the active scan mode: a
    focused run scans in that mode; FULL picks web for URLs, full for hosts."""
    if state.active_mode and state.active_mode != "full":
        return state.active_mode
    return "web" if is_url else "full"


def _scanned_targets(state: FleetState) -> set[str]:
    return {t for (k, t, _m) in state.done_keys() if k == KIND_SCAN and t}


def _web_endpoints(state: FleetState) -> list[str]:
    """Distinct http(s) surfaces from findings + scope, for hypothesis probing."""
    urls: set[str] = set()
    for f in state.findings:
        t = str(f.get("target") or "")
        if t.startswith("http"):
            urls.add(t)
    for t in state.scope:
        if str(t).startswith("http"):
            urls.add(str(t))
    for u in state.seed_targets.get("urls", []) or []:
        if u:
            urls.add(u)
    return sorted(urls)


# ═══════════════════════════════════════════════════════════════════════════
# ROLES
# ═══════════════════════════════════════════════════════════════════════════


class ReconRole:
    name = "recon"
    modes: frozenset[str] = frozenset()  # every mode

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        scanned = _scanned_targets(state)
        tasks: list[AgentTask] = []
        for host in state.seed_targets.get("ips", []) or []:
            if host and host not in scanned:
                tasks.append(AgentTask(
                    kind=KIND_SCAN, role=self.name, target=host,
                    mode=_scan_mode(state, is_url=False),
                    rationale="recon: full network + service scan of seed host",
                    estimated_value=0.9,
                ))
        for url in state.seed_targets.get("urls", []) or []:
            if url and url not in scanned:
                tasks.append(AgentTask(
                    kind=KIND_SCAN, role=self.name, target=url,
                    mode=_scan_mode(state, is_url=True),
                    rationale="recon: web application scan of seed URL",
                    estimated_value=0.9,
                ))
        return tasks


class StrategistRole:
    name = "strategist"
    modes: frozenset[str] = frozenset()

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        if not state.findings:
            return []
        try:
            from heaven.ai.attack_chain_planner import AttackChainPlanner
        except Exception:  # noqa: BLE001
            return []
        planner = AttackChainPlanner(gateway=getattr(brain, "gateway", None))
        try:
            async with _guard(brain):
                plan = await planner.plan(
                    findings=state.findings[:50],
                    objective_hint=state.objective or "discover and prove the highest-impact vulnerability",
                )
        except Exception as e:  # noqa: BLE001 — planning must never abort the fleet
            logger.debug("strategist plan failed: %s", e, exc_info=True)
            return []
        plans = getattr(plan, "plans", None) or []
        if not plans:
            return []
        top = plans[0]
        steps = getattr(top, "steps", None) or []
        if not steps:
            return []
        step = steps[0]
        target = getattr(step, "target_host", "") or ""
        if not target or target in _scanned_targets(state):
            return []
        if not scope_guard(state).allows(host_of(target) or target):
            # The planner referenced a host outside authorised scope (e.g. one it
            # read from a finding on a redirect). Never scan it.
            return []
        is_url = target.startswith("http")
        technique = getattr(step, "technique_id", "")
        return [AgentTask(
            kind=KIND_SCAN, role=self.name, target=target,
            mode=_scan_mode(state, is_url),
            rationale=f"strategist step 1/{len(steps)} via {technique}: "
                      f"{getattr(step, 'description', '')}"[:200],
            estimated_value=float(getattr(top, "estimated_success", 0.6) or 0.6),
            params={"technique_id": technique, "plan_name": getattr(top, "name", "")},
        )]


class HypothesisRole:
    name = "hypothesis"
    modes: frozenset[str] = frozenset({"web", "api"})

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        # Pure enrichment: with no brain there is nothing honest to add here (the
        # deterministic web/api detectors already ran), so we add nothing.
        if not getattr(brain, "available", False):
            return []
        try:
            from heaven.ai.vuln_hypothesis import VulnHypothesisAgent
        except Exception:  # noqa: BLE001
            return []
        agent = VulnHypothesisAgent(gateway=getattr(brain, "gateway", None))
        if not agent.available:
            return []
        endpoints = _web_endpoints(state)
        if not endpoints:
            return []
        profile: dict[str, Any] = {"tech_stack": [], "waf_detected": None}
        endpoint_dicts: list[dict] = [{"url": u} for u in endpoints]
        try:
            async with _guard(brain):
                out = await agent.propose(profile, endpoint_dicts, max_hypotheses=8)
        except Exception as e:  # noqa: BLE001
            logger.debug("hypothesis propose failed: %s", e, exc_info=True)
            return []
        hyps = getattr(out, "hypotheses", None) or []
        by_url: dict[str, list[dict]] = {}
        for h in hyps:
            url = getattr(h, "target_url", "") or ""
            if not url:
                continue
            by_url.setdefault(url, []).append({
                "vuln_class": getattr(h, "vuln_class", ""),
                "target_url": url,
                "param": getattr(h, "param", ""),
                "rationale": getattr(h, "rationale", ""),
                "prior": float(getattr(h, "prior", 0.5) or 0.5),
            })
        mode = state.active_mode if state.active_mode in ("web", "api") else "web"
        tasks: list[AgentTask] = []
        for url, group in by_url.items():
            tasks.append(AgentTask(
                kind=KIND_HYPOTHESIS, role=self.name, target=url, mode=mode,
                rationale=f"{len(group)} hypothesis(es) to verify with real detectors",
                estimated_value=max(g["prior"] for g in group),
                params={"hypotheses": group},
            ))
        return tasks


class CriticRole:
    name = "critic"
    modes: frozenset[str] = frozenset()

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        # The deterministic FP rules are authoritative and already ran; this is an
        # optional LLM second opinion on the borderline band only.
        if not getattr(brain, "available", False) or not state.findings:
            return []
        borderline = [
            f for f in state.findings
            if 0.4 <= float(f.get("confidence", 0) or 0) <= 0.7
        ]
        if not borderline:
            return []
        return [AgentTask(
            kind=KIND_REVIEW, role=self.name,
            rationale=f"second-opinion review of {len(borderline)} borderline finding(s)",
            estimated_value=0.4, params={"review": "fp"},
        )]


class GapRole:
    name = "gap"
    modes: frozenset[str] = frozenset()

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        # Self-grading has a deterministic rule-based path, so this runs with or
        # without a brain — but only once, and only after there is work to grade.
        if not state.has_findings():
            return []
        already = any(
            t.kind == KIND_REVIEW and (t.params or {}).get("review") == "coverage"
            for t in state.history
        )
        if already:
            return []
        return [AgentTask(
            kind=KIND_REVIEW, role=self.name,
            rationale="self-grade coverage: identify what was not tested",
            estimated_value=0.3, params={"review": "coverage"},
        )]


# ═══════════════════════════════════════════════════════════════════════════
# MODE LEADS — one per backend ScanMode, so agent coverage == scanner coverage
# ═══════════════════════════════════════════════════════════════════════════

# Every backend ScanMode except FULL (FULL is the meta-mode a single full scan
# already covers). Kept as bare strings that MUST equal ScanMode values; a test
# asserts this set is exactly ``set(ScanMode) - {FULL}`` so a new mode can never
# be added to the scanner without a matching agent lead.
BACKEND_MODES: tuple[str, ...] = (
    "network", "web", "api", "cloud", "container", "iot", "ot", "ad", "email",
    "ci", "devsecops", "exploit", "wireless", "dos", "sniff", "malware",
)

# Modes whose scan is more than read-only observation. The lead flags its tasks
# ``requires_auth`` so the scheduler refuses them unless the run is authorized —
# the same gate ``heaven scan --mode exploit`` enforces.
AUTH_REQUIRED_MODES: frozenset[str] = frozenset({"exploit"})

# What kind of target each mode's oracle can actually assess. Keeps the fan-out
# honest: a web scan needs a URL, a network/AD/IoT scan needs a host, and the
# code-analysis modes need a repository (not a network target), so they no-op on
# a pure host/URL engagement rather than pretending to scan.
_MODE_TARGETS: dict[str, tuple[bool, bool]] = {
    # mode: (accepts_urls, accepts_hosts)
    "web": (True, False),
    "api": (True, False),
    "network": (False, True),
    "ad": (False, True),
    "iot": (False, True),
    "ot": (False, True),
    "container": (False, True),
    "sniff": (False, True),
    "email": (False, True),
    "cloud": (False, True),
    "wireless": (False, True),
    "malware": (True, True),
    "dos": (True, True),
    "exploit": (True, True),
    # devsecops / ci are code-analysis modes: no network target type applies, so
    # they accept neither and stay dormant unless a repo seed is present.
    "devsecops": (False, False),
    "ci": (False, False),
}


def _fanout_cap() -> int:
    """Max targets one mode-lead fans out to per iteration. Bounds the breadth on
    a very large engagement so 'surface-proportional' never becomes unbounded."""
    try:
        return max(1, min(500, int(os.environ.get("HEAVEN_FLEET_FANOUT_CAP", "25"))))
    except (TypeError, ValueError):
        return 25


def _done_by_target(state: FleetState) -> dict[str, set[str]]:
    """target → set of modes it has already been scanned in (incl. ``full``)."""
    out: dict[str, set[str]] = {}
    for (kind, target, mode) in state.done_keys():
        if kind == KIND_SCAN and target:
            out.setdefault(target, set()).add(mode)
    return out


def scope_guard(state: FleetState) -> ScopeGuard:
    """A containment-only scope gate built from the operator's authorised inputs —
    the seed targets plus the engagement's in-scope entries. It can only ever
    *contain*: a finding-derived host must pass this before the fleet will scan it,
    so a run deepens coverage onto in-scope surface it discovers (a live host in a
    seeded CIDR, a subdomain of a deliberately named domain) but never silently
    expands to a host nobody authorised — a parent domain, or third-party infra
    reached via a redirect or a certificate SAN."""
    ips: list[str] = []
    urls: list[str] = []
    domains: list[str] = [str(d) for d in state.scope_domains]
    for h in state.seed_targets.get("ips", []) or []:
        ips.append(str(h))
    for u in state.seed_targets.get("urls", []) or []:
        urls.append(str(u))
    for s in state.scope:
        s = str(s)
        if "://" in s:
            urls.append(s)
        elif s.startswith("*.") or s.startswith("."):
            domains.append(s)
        else:
            ips.append(s)
    return ScopeGuard({"ips": ips, "urls": urls, "domains": domains})


def _surface_targets(state: FleetState, *, want_urls: bool, want_hosts: bool) -> list[str]:
    """Candidate targets for a mode, drawn from scope + seeds + the hosts/URLs the
    scans have already surfaced (findings). Seed and scope targets are authorised by
    definition; a finding-derived host/URL is included only when it falls inside the
    operator's authorised scope (:func:`scope_guard`). In-scope discovered surface is
    how a real engagement grows past its seeds toward ~dozens of agents — but a host
    the operator never authorised is never auto-scanned, whatever a finding says."""
    guard = scope_guard(state)
    urls: set[str] = set()
    hosts: set[str] = set()

    def _add(t: str, *, authorised: bool) -> None:
        t = (t or "").strip()
        if not t:
            return
        host = host_of(t) or t
        if not authorised and not guard.allows(host):
            return  # discovered surface outside authorised scope — never auto-scan it
        if t.startswith("http"):
            urls.add(t)
        else:
            hosts.add(host)

    for t in state.scope:
        _add(str(t), authorised=True)
    for t in state.seed_targets.get("ips", []) or []:
        _add(str(t), authorised=True)
    for u in state.seed_targets.get("urls", []) or []:
        _add(str(u), authorised=True)
    for f in state.findings:
        _add(str(f.get("target") or ""), authorised=False)

    out: list[str] = []
    if want_urls:
        out.extend(sorted(urls))
    if want_hosts:
        out.extend(sorted(hosts))
    return out


class ModeLeadRole:
    """One lead per backend ScanMode. It fans the fleet out across the attack
    surface *in its own mode*, so coverage of that mode tracks the scanner's own
    per-mode pipeline. It emits ``KIND_SCAN`` tasks the executor runs through the
    real orchestrator; it never produces a finding.

    Dedup is by construction: a target already scanned in this mode (or already
    covered by a ``full`` scan of the same target) is skipped, so a mode-lead only
    ever deepens coverage onto surface the seed pass did not reach."""

    def __init__(self, mode: str):
        self.mode = mode
        self.name = f"{mode}-lead"
        self.modes: frozenset[str] = frozenset({mode})
        self._accepts_urls, self._accepts_hosts = _MODE_TARGETS.get(mode, (False, False))
        self._requires_auth = mode in AUTH_REQUIRED_MODES

    async def propose(self, state: FleetState, brain: Any) -> list[AgentTask]:
        if not (self._accepts_urls or self._accepts_hosts):
            return []  # code-analysis mode: no network target type to fan out to
        if self._requires_auth and not state.authorized:
            # A read-only run can never run this mode; stand down rather than emit
            # tasks the scheduler would only refuse every iteration. The scheduler's
            # refusal stays the authoritative backstop for anything that slips past.
            return []
        candidates = _surface_targets(
            state, want_urls=self._accepts_urls, want_hosts=self._accepts_hosts)
        if not candidates:
            return []
        done = _done_by_target(state)
        cap = _fanout_cap()
        tasks: list[AgentTask] = []
        for target in candidates:
            covered = done.get(target, set())
            if self.mode in covered or "full" in covered:
                continue  # already scanned in this mode, or by a full scan
            tasks.append(AgentTask(
                kind=KIND_SCAN, role=self.name, target=target, mode=self.mode,
                rationale=f"{self.mode} lead: assess {target} in {self.mode} mode",
                estimated_value=0.5,
                requires_auth=self._requires_auth,
            ))
            if len(tasks) >= cap:
                break
        return tasks


def base_roles() -> list[AgentRole]:
    """The five agent primitives adopted as roles (recon/strategy/hypothesis/
    FP-critic/gap). These run under every mode-appropriate gate."""
    return [ReconRole(), StrategistRole(), HypothesisRole(), CriticRole(), GapRole()]


def mode_lead_roles() -> list[AgentRole]:
    """One lead per backend ScanMode, so the fleet's mode coverage is exactly the
    scanner's mode set — a mode cannot exist without an agent that drives it."""
    return [ModeLeadRole(m) for m in BACKEND_MODES]


def default_roles() -> list[AgentRole]:
    """Backwards-compatible alias for :func:`base_roles` (the five primitives)."""
    return base_roles()


def all_roles() -> list[AgentRole]:
    """The full fleet roster: the five primitives plus one lead per backend mode."""
    return base_roles() + mode_lead_roles()


def roles_for_mode(mode: str, roles: list[AgentRole] | None = None) -> list[AgentRole]:
    """Roles that serve the active scan mode, using the same gate as the
    orchestrator's ``add_task(modes=...)`` so agent coverage tracks scanner
    coverage. Defaults to the full roster (primitives + mode leads); ``full``
    returns every role, a focused mode returns the primitives plus that mode's
    lead."""
    return [r for r in (roles if roles is not None else all_roles()) if serves_mode(r, mode)]
