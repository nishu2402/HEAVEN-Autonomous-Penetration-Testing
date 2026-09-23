"""HEAVEN — Agent Fleet executor (the propose→verify honesty gate).

This is where a role's :class:`AgentTask` becomes real scanner activity. It is the
one place the fleet is allowed to produce a finding, and it does so ONLY by running
a deterministic oracle that already exists in HEAVEN and persisting exactly what
that oracle confirmed. A role never reaches the store; the executor does, and only
with oracle output. That is the structural honesty guarantee: a poisoned banner or
an LLM hallucination can, at most, cause a *scan* to run — it can never mint a
finding, because the finding still has to survive a real detector.

Task kinds handled:
  * ``KIND_SCAN``       — run the orchestrator pipeline for one target in one
    :class:`~heaven.config.ScanMode`. The findings are the deterministic pipeline's
    own output (recon → detectors → validation → FP-suppression → scoring), byte
    for byte the same as ``heaven scan`` would produce for that target/mode.
  * ``KIND_HYPOTHESIS`` — take LLM-proposed vuln hypotheses and run each through
    :func:`heaven.ai.vuln_hypothesis.verify_hypotheses`, which probes with a REAL
    detector and returns only confirmed findings (the hypothesis is attached as
    evidence, never as a result). Gated by the run's authorization.
  * ``KIND_REVIEW``     — advisory passes that never add a finding: the FP critic
    (:func:`heaven.ai.fp_review.review_borderline_findings`) re-scores borderline
    findings in place, and the coverage grader
    (:func:`heaven.ai.coverage_grader.grade_engagement`) reports what was not tested.
  * ``KIND_NOOP``       — nothing to do (explained, never silent).

Every write goes through :meth:`Blackboard.record_findings`, the single
finding-write path, so persistence stays auditable in one place.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from heaven.ai.fleet.blackboard import Blackboard, host_of
from heaven.ai.fleet.brain import FleetBrain
from heaven.ai.fleet.metrics import FleetMetrics
from heaven.ai.fleet.roles import (
    KIND_HYPOTHESIS,
    KIND_NOOP,
    KIND_REVIEW,
    KIND_SCAN,
    AgentTask,
)
from heaven.feedback import ScopeGuard
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.executor")

# The FP-review band the fleet critic re-scores. Mirrors fp_review's own default
# so the fleet's second opinion covers exactly the deterministic "uncertain" band.
_BORDERLINE = (0.4, 0.7)


def scan_targets_for(target: str, *, ports: str = "1-1024",
                     stealth: str = "normal") -> dict[str, Any]:
    """Build the orchestrator ``targets`` dict for a single fleet scan target.

    Mirrors the shape the autonomous loop and ``heaven scan`` pass, so a fleet
    scan is indistinguishable from a normal scan of the same target — the fleet
    only *chooses* the target and mode; the pipeline does the rest."""
    is_url = target.startswith("http")
    return {
        "ips": [] if is_url else [target],
        "urls": [target] if is_url else [],
        "ports": ports,
        "stealth_level": stealth,
        "ad_domain": "", "ad_dc": "",
        "enable_iot": False, "enable_api_scan": False,
        "enable_container": False, "enable_mitre": True,
        # Read-only by default: the fleet never auto-proves or auto-chains post-ex
        # from a plain scan task. The Exploit mode-lead + verify path own that, and
        # only when the run is authorized (enforced by the scheduler).
        "auto_prove": False,
        "autonomous": False,
    }


class FleetExecutor:
    """Turns tasks into verified findings. One per fleet run.

    ``authorized`` is the run-level authorization (``--i-have-authorization``); the
    scheduler already refuses auth-gated *kinds* before they reach here, and the
    executor additionally passes it into the hypothesis verifier so active probing
    stays gated even for allowed kinds.
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
    ):
        self.blackboard = blackboard
        self.base_config = base_config
        self.brain = brain
        self.metrics = metrics or FleetMetrics()
        self.authorized = authorized
        # Structural scope backstop: even if a role proposes an out-of-scope target
        # (a planner reading a redirect host, an LLM hallucinating a URL), the
        # executor refuses to scan or probe a host the operator never authorised.
        # ``None`` means no backstop is configured (a bare/test executor); the
        # coordinator always configures one for a real run.
        self._scope_guard: Optional[ScopeGuard] = (
            ScopeGuard(authorized_targets) if authorized_targets else None
        )

    def _in_scope(self, target: str) -> bool:
        """True when ``target`` is authorised, or when no backstop is configured."""
        if self._scope_guard is None:
            return True
        return self._scope_guard.allows(host_of(target) or target)

    @property
    def store(self) -> Any:
        return self.blackboard.store

    async def execute(self, task: AgentTask) -> dict[str, Any]:
        """Dispatch one task to its oracle. Returns a compact result dict. Never
        raises for ordinary failures — the scheduler captures exceptions, but each
        branch also degrades to an explained empty result."""
        if task.kind == KIND_SCAN:
            return await self._run_scan(task)
        if task.kind == KIND_HYPOTHESIS:
            return await self._verify_hypotheses(task)
        if task.kind == KIND_REVIEW:
            return await self._run_review(task)
        if task.kind == KIND_NOOP:
            return {"noop": True, "rationale": task.rationale}
        return {"error": f"unknown task kind: {task.kind}"}

    # ── KIND_SCAN ──────────────────────────────────────────────────────────
    async def _run_scan(self, task: AgentTask) -> dict[str, Any]:
        from heaven.config import ScanMode
        from heaven.orchestrator import build_full_scan

        target = task.target
        if not target:
            return {"skipped": True, "reason": "scan task has no target"}
        if not self._in_scope(target):
            logger.info("fleet scan refused (out of scope): %s", target)
            return {"skipped": True, "reason": "target out of authorised scope",
                    "target": target}
        mode = task.mode or "full"
        try:
            self.base_config.scan_mode = ScanMode(mode)
        except ValueError:
            mode = "full"
            self.base_config.scan_mode = ScanMode.FULL

        targets = scan_targets_for(target)
        store = self.store
        orch = build_full_scan(
            targets, self.base_config, checkpoint_store=store,
            scan_mode=ScanMode(mode),
        )
        if store is not None:
            try:
                store.record_scan_start(
                    orch.scan_id, name=f"fleet:{task.role or 'scan'}:{mode}",
                    mode=mode,
                    config={"targets": targets, "fleet_task": task.to_dict()},
                )
            except Exception:  # noqa: BLE001 — lifecycle bookkeeping is best-effort
                logger.debug("record_scan_start failed", exc_info=True)

        t0 = time.monotonic()
        summary = await orch.run()
        # The orchestrator publishes one deduped list under both keys; take one.
        findings = summary.get("vulnerabilities") or summary.get("findings") or []
        written = self.blackboard.record_findings(orch.scan_id, findings)
        if store is not None:
            try:
                store.record_scan_complete(orch.scan_id, summary)
            except Exception:  # noqa: BLE001
                logger.debug("record_scan_complete failed", exc_info=True)
        self.metrics.verified(len(findings))
        logger.info(
            "fleet scan %s (%s) → %d finding(s) in %.1fs",
            target, mode, len(findings), time.monotonic() - t0,
        )
        return {
            "scan_id": orch.scan_id, "target": target, "mode": mode,
            "findings": len(findings), "persisted": written,
            "critical": summary.get("critical", 0), "high": summary.get("high", 0),
            "medium": summary.get("medium", 0), "low": summary.get("low", 0),
            "info": summary.get("info", 0),
        }

    # ── KIND_HYPOTHESIS ────────────────────────────────────────────────────
    async def _verify_hypotheses(self, task: AgentTask) -> dict[str, Any]:
        from heaven.ai.vuln_hypothesis import verify_hypotheses

        hyps = (task.params or {}).get("hypotheses") or []
        if not hyps:
            return {"skipped": True, "reason": "no hypotheses on task"}
        # Scope backstop: never probe a URL the operator did not authorise, even if
        # a hypothesis (LLM-proposed) points at one — e.g. a host reached via a
        # redirect in a finding. Filter before any detector touches the network.
        in_scope = [h for h in hyps if self._in_scope(str(h.get("target_url") or task.target or ""))]
        dropped = len(hyps) - len(in_scope)
        if not in_scope:
            return {"skipped": True, "reason": "all hypotheses out of authorised scope",
                    "out_of_scope": dropped}
        # verify_hypotheses probes with real detectors; it self-gates on
        # ``authorized`` and returns only oracle-confirmed findings.
        res = await verify_hypotheses(in_scope, authorized=self.authorized)
        findings = res.get("findings", []) or []
        store = self.store
        scan_id = f"fleet-hypothesis-{task.target or 'web'}"
        if store is not None and findings:
            try:
                store.record_scan_start(
                    scan_id, name=f"fleet:hypothesis:{task.target}", mode=task.mode or "web",
                    config={"fleet_task": task.to_dict()},
                )
            except Exception:  # noqa: BLE001
                logger.debug("record_scan_start (hypothesis) failed", exc_info=True)
        written = self.blackboard.record_findings(scan_id, findings)
        self.metrics.verified(len(findings))
        return {
            "target": task.target, "verified": res.get("verified", len(findings)),
            "rejected": res.get("rejected", 0),
            "probed_targets": res.get("probed_targets", 0),
            "persisted": written, "skipped": res.get("skipped"),
        }

    # ── KIND_REVIEW ────────────────────────────────────────────────────────
    async def _run_review(self, task: AgentTask) -> dict[str, Any]:
        review = (task.params or {}).get("review", "")
        if review == "fp":
            return await self._review_false_positives()
        if review == "coverage":
            return await self._grade_coverage()
        return {"skipped": True, "reason": f"unknown review: {review}"}

    async def _review_false_positives(self) -> dict[str, Any]:
        """Second-opinion the borderline band and persist only the deltas.

        The classic pipeline already runs this per scan; the fleet critic is a
        cross-target sweep after every scan has landed. It only ever touches the
        uncertain band and re-persists a finding solely when the reviewer changed
        it, so it can neither invent nor silently rewrite confident findings."""
        from heaven.ai.fp_review import review_borderline_findings

        store = self.store
        if store is None:
            return {"skipped": True, "reason": "no store"}
        try:
            rows = store.list_findings(limit=10000)
        except Exception:  # noqa: BLE001
            logger.debug("critic list_findings failed", exc_info=True)
            return {"skipped": True, "reason": "list failed"}
        # Full dicts so a re-persist carries the whole finding, not a compact view.
        dicts = [self._finding_full_dict(f) for f in rows]
        borderline = [d for d in dicts
                      if _BORDERLINE[0] <= float(d.get("confidence", 0) or 0) <= _BORDERLINE[1]]
        if not borderline:
            return {"reviewed": 0, "adjusted": 0}
        before = {d["id"]: (d.get("confidence"), d.get("status")) for d in borderline}
        await review_borderline_findings(borderline)
        adjusted = 0
        for d in borderline:
            fid = d.get("id")
            if not fid:
                continue
            if (d.get("confidence"), d.get("status")) != before.get(fid):
                try:
                    store.upsert_finding(d.get("scan_id") or "fleet-critic", d)
                    adjusted += 1
                except Exception:  # noqa: BLE001
                    logger.debug("critic re-persist failed", exc_info=True)
        return {"reviewed": len(borderline), "adjusted": adjusted}

    async def _grade_coverage(self) -> dict[str, Any]:
        """Self-grade what was and was not tested. Advisory: emits no finding."""
        from heaven.ai.coverage_grader import grade_engagement

        store = self.store
        if store is None:
            return {"skipped": True, "reason": "no store"}
        use_llm = bool(self.brain and self.brain.available)
        try:
            report = await grade_engagement(store, use_llm=use_llm)
        except Exception:  # noqa: BLE001
            logger.debug("coverage grade failed", exc_info=True)
            return {"skipped": True, "reason": "grade failed"}
        return {
            "grade": getattr(report, "grade", None),
            "scope_coverage_pct": round(float(getattr(report, "scope_coverage_pct", 0.0) or 0.0), 1),
            "owasp_coverage_pct": round(float(getattr(report, "owasp_coverage_pct", 0.0) or 0.0), 1),
            "untested_targets": list(getattr(report, "untested_scope_targets", []) or [])[:20],
            "recommendations": list(getattr(report, "recommendations", []) or [])[:10],
        }

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _finding_full_dict(f: Any) -> dict[str, Any]:
        """A round-trippable finding dict for re-persist (keeps every field the
        store needs), tolerant of both ORM rows and dicts."""
        if isinstance(f, dict):
            return dict(f)
        out: dict[str, Any] = {}
        for k in ("id", "scan_id", "target", "vuln_type", "title", "severity",
                  "confidence", "confidence_bucket", "cve_id", "risk_score",
                  "status", "evidence", "source"):
            v = getattr(f, k, None)
            if v is not None:
                out[k] = v
        return out
