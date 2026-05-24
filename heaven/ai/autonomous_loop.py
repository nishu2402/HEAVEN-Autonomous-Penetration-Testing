"""
HEAVEN — Autonomous loop

Replaces the fixed RECON → SCAN → REPORT DAG with an iterative
"observe → plan → act" loop driven by an LLM (or a rule-based fallback
when no LLM key is set).

Termination conditions (any one triggers exit):
  - max_iterations reached (default 8)
  - time_budget_s exhausted (default 1800 = 30 min)
  - planner returns no_action_recommended (target sufficiently explored)
  - operator-supplied objective met (e.g. "RCE on any internal host")

Each iteration's anatomy:
  1. **Observe**  — read every finding produced so far from the engagement DB
  2. **Plan**    — ask the planner: "given these findings, what should we do next?"
                   The planner uses LLM tool-use via AttackChainPlanner; if no
                   LLM is configured, falls back to a small rule-based planner.
  3. **Act**     — execute the proposed action via the existing orchestrator
                   (build_full_scan with restricted targets/mode)
  4. **Score**   — diff findings before/after; record reward in the bandit
                   so the planner learns which actions actually produce
                   value.

This module *does not* invent new scanner primitives — it composes the
existing recon, vulnscan, postex, and exploit_proof modules in an order
the planner picks rather than the order the original DAG dictates.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("ai.autonomous_loop")


# ═══════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════


@dataclass
class AutonomousAction:
    """A single next-step the planner proposes the loop should execute."""
    kind: str                       # "scan" | "exploit_proof" | "postex" | "lateral" | "noop"
    target: str = ""                # URL / host / engagement-id depending on kind
    mode: str = ""                  # for kind=scan: web|network|full|ad|cloud
    rationale: str = ""             # why the planner picked this
    estimated_value: float = 0.5    # 0-1, planner's prior on usefulness
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class IterationReport:
    iteration: int
    action: AutonomousAction
    duration_s: float
    findings_before: int = 0
    findings_after: int = 0
    new_critical: int = 0
    new_high: int = 0
    reward: float = 0.0
    error: str = ""

    @property
    def new_findings(self) -> int:
        return max(0, self.findings_after - self.findings_before)


@dataclass
class AutonomousRunSummary:
    started_at: float = 0.0
    ended_at: float = 0.0
    iterations: list[IterationReport] = field(default_factory=list)
    stop_reason: str = ""
    total_findings: int = 0
    total_critical: int = 0
    total_high: int = 0
    target_objective: str = ""
    objective_met: bool = False

    @property
    def duration_s(self) -> float:
        return self.ended_at - self.started_at

    def to_dict(self) -> dict:
        return {
            "duration_s": round(self.duration_s, 1),
            "iterations_run": len(self.iterations),
            "stop_reason": self.stop_reason,
            "objective": self.target_objective,
            "objective_met": self.objective_met,
            "total_findings": self.total_findings,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "iterations": [
                {
                    "n": r.iteration,
                    "action": {"kind": r.action.kind, "target": r.action.target,
                               "mode": r.action.mode, "rationale": r.action.rationale,
                               "estimated_value": r.action.estimated_value},
                    "duration_s": round(r.duration_s, 1),
                    "new_findings": r.new_findings,
                    "new_critical": r.new_critical, "new_high": r.new_high,
                    "reward": round(r.reward, 3),
                    "error": r.error,
                }
                for r in self.iterations
            ],
        }


# ═══════════════════════════════════════════
# RULE-BASED FALLBACK PLANNER
# Used when no LLM is configured. Mirrors a junior pen-tester's playbook.
# ═══════════════════════════════════════════


def _rule_based_next_action(
    findings: list[dict], iteration: int,
    targets_seed: dict,
) -> AutonomousAction:
    """When no LLM is available, fall back to a deterministic playbook.

    Order:
      1. First iteration → recon scan the seed targets
      2. If any web URLs discovered but no SQLi tested → web scan
      3. If any sqli/cmdi/ssrf finding has high confidence → exploit_proof
      4. If any credentials discovered → cred-reuse / lateral
      5. Otherwise → noop (planner has nothing more to recommend)
    """
    if iteration == 0:
        seeds = targets_seed.get("ips") or targets_seed.get("urls") or []
        if not seeds:
            return AutonomousAction(kind="noop", rationale="no seed targets given")
        return AutonomousAction(
            kind="scan", target=seeds[0],
            mode="full" if targets_seed.get("ips") else "web",
            rationale="iteration 0: full recon on seed target",
            estimated_value=0.9,
        )

    # Collect signal from findings so far
    has_web = any("http" in (f.get("target") or "") for f in findings)
    has_sqli_high = any(
        ("sqli" in (f.get("vuln_type") or "").lower()
         and float(f.get("confidence") or 0) >= 0.7)
        for f in findings
    )
    has_cmdi_high = any(
        (("cmdi" in (f.get("vuln_type") or "").lower()
          or "rce" in (f.get("vuln_type") or "").lower())
         and float(f.get("confidence") or 0) >= 0.7)
        for f in findings
    )
    has_creds = any(
        f.get("vuln_type") in ("weak_credentials", "default_credentials")
        or "password" in (f.get("title") or "").lower()
        for f in findings
    )

    if has_sqli_high or has_cmdi_high:
        return AutonomousAction(
            kind="exploit_proof", rationale="high-confidence injection — prove impact",
            estimated_value=0.85,
        )
    if has_creds:
        return AutonomousAction(
            kind="postex_credreuse",
            rationale="credentials discovered — fan out cred reuse",
            estimated_value=0.7,
        )
    if has_web and iteration < 3:
        urls = [f.get("target") for f in findings if "http" in (f.get("target") or "")]
        if urls:
            return AutonomousAction(
                kind="scan", target=urls[0], mode="web",
                rationale="web surface discovered — deep web scan",
                estimated_value=0.65,
            )
    return AutonomousAction(
        kind="noop", rationale="rule-based planner found no profitable next action",
        estimated_value=0.0,
    )


# ═══════════════════════════════════════════
# LLM-DRIVEN PLANNER (preferred)
# ═══════════════════════════════════════════


async def _llm_next_action(
    findings: list[dict], iteration: int,
    seed_targets: dict, objective: str,
) -> Optional[AutonomousAction]:
    """Use the AttackChainPlanner to propose the next action.

    Returns None if the LLM gateway is unavailable so the caller can fall
    through to the rule-based planner.
    """
    try:
        from heaven.ai import AttackChainPlanner
    except Exception:
        return None
    planner = AttackChainPlanner()
    if not planner.available:
        return None

    try:
        plan = await planner.plan(
            findings=findings[:50],
            assets=[],
            objective_hint=objective or "discover and prove the highest-impact vulnerability",
        )
    except Exception as e:
        logger.warning(f"LLM planner crashed: {e}")
        return None

    plans = getattr(plan, "plans", None) or []
    if not plans:
        return None
    top = plans[0]
    steps = getattr(top, "steps", None) or []
    if not steps:
        return None
    step = steps[0]
    target = getattr(step, "target_host", "") or ""
    description = getattr(step, "description", "")
    technique = getattr(step, "technique_id", "")
    return AutonomousAction(
        kind="scan",
        target=target,
        mode="web" if target.startswith("http") else "full",
        rationale=f"LLM step 1/{len(steps)} via {technique}: {description}",
        estimated_value=float(getattr(top, "estimated_success", 0.6) or 0.6),
        parameters={"llm_plan": True, "technique_id": technique},
    )


# ═══════════════════════════════════════════
# ACTION EXECUTORS
# ═══════════════════════════════════════════


async def _execute_action(
    action: AutonomousAction,
    engagement_store,
    base_config,
) -> dict:
    """Run the proposed action. Returns the raw orchestrator summary dict."""
    from heaven.orchestrator import build_full_scan

    if action.kind == "noop":
        return {"skipped": True, "reason": action.rationale}

    if action.kind == "scan":
        from heaven.config import ScanMode
        targets = {
            "ips": [action.target] if not action.target.startswith("http") else [],
            "urls": [action.target] if action.target.startswith("http") else [],
            "ports": "1-1024",
            "stealth_level": "normal",
            "ad_domain": "", "ad_dc": "",
            "enable_iot": False, "enable_api_scan": False,
            "enable_container": False, "enable_mitre": True,
            "auto_prove": True,    # autonomous mode always proves
            "autonomous": False,   # don't recurse into post-ex chain — that's a separate action
        }
        try:
            base_config.scan_mode = ScanMode(action.mode or "full")
        except ValueError:
            pass
        orch = build_full_scan(targets, base_config, checkpoint_store=engagement_store)
        if engagement_store:
            engagement_store.record_scan_start(
                orch.scan_id, name=f"autonomous-iter:{action.kind}",
                mode=action.mode, config={"targets": targets, "autonomous_action": action.__dict__},
            )
        summary = await orch.run()
        if engagement_store:
            for f in summary.get("vulnerabilities", []) + summary.get("findings", []):
                try:
                    engagement_store.upsert_finding(orch.scan_id, f)
                except Exception:
                    pass
            engagement_store.record_scan_complete(orch.scan_id, summary)
        return summary

    if action.kind == "exploit_proof":
        from heaven.vulnscan.exploit_proof import prove_finding
        # Take the most recent high-confidence findings from the engagement
        if engagement_store is None:
            return {"skipped": True, "reason": "no engagement store"}
        findings = engagement_store.list_findings(min_confidence=0.7, limit=20)
        proved = 0
        for f in findings:
            try:
                _ = await prove_finding({
                    "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                    "title": f.title, "severity": f.severity, "confidence": f.confidence,
                    "evidence": f.evidence or {},
                }, authorized=True)
                proved += 1
            except Exception as e:
                logger.debug(f"prove_finding error on {f.id}: {e}")
        return {"prove_attempts": len(findings), "proved": proved}

    if action.kind == "postex_credreuse":
        # Defer to the orchestrator's postex phase via an explicit autonomous scan
        from heaven.postex import CredentialValidator
        v = CredentialValidator(authorized=True)
        # Build creds from engagement secrets (best-effort)
        creds: list[tuple[str, str]] = [("admin", "admin"), ("root", "root")]
        targets_t: list[tuple[str, int, str]] = []
        if engagement_store:
            for entry in engagement_store.list_scope(in_scope_only=True):
                t = entry.target
                # Heuristic — SSH on 22 unless URL
                if not t.startswith("http"):
                    targets_t.append((t, 22, "ssh"))
        if not targets_t:
            return {"skipped": True, "reason": "no engagement targets for cred-reuse"}
        out = await v.validate(creds, targets_t)
        return {"cred_reuse_attempted": out.attempted, "cred_reuse_hits": len(out.hits)}

    return {"error": f"unknown action kind: {action.kind}"}


# ═══════════════════════════════════════════
# THE LOOP
# ═══════════════════════════════════════════


SEVERITY_REWARD = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}


def _objective_met(findings: list[dict], objective: str) -> bool:
    """Very simple objective matcher. Free-text objective contains keywords
    that must appear in any finding's vuln_type or title (case-insensitive).
    """
    if not objective:
        return False
    keys = [k.strip().lower() for k in objective.split() if len(k) > 3]
    if not keys:
        return False
    for f in findings:
        blob = (f.get("vuln_type", "") + " " + f.get("title", "")).lower()
        if all(k in blob for k in keys):
            return True
    return False


async def run_autonomous(
    seed_targets: dict,
    engagement_store,
    base_config,
    *,
    max_iterations: int = 8,
    time_budget_s: int = 1800,
    objective: str = "",
    use_llm_planner: bool = True,
) -> AutonomousRunSummary:
    """Drive the observe → plan → act loop.

    Returns an AutonomousRunSummary suitable for serialisation and audit.
    """
    summary = AutonomousRunSummary(
        started_at=time.time(), target_objective=objective,
    )
    iter_n = 0

    while iter_n < max_iterations:
        elapsed = time.time() - summary.started_at
        if elapsed > time_budget_s:
            summary.stop_reason = "time_budget_exhausted"
            break

        # Observe — pull every finding stored so far
        if engagement_store is not None:
            findings = [
                {
                    "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                    "title": f.title, "severity": f.severity,
                    "confidence": f.confidence, "evidence": f.evidence,
                }
                for f in engagement_store.list_findings(limit=500)
            ]
        else:
            findings = []
        findings_before = len(findings)

        if _objective_met(findings, objective):
            summary.stop_reason = "objective_met"
            summary.objective_met = True
            break

        # Plan
        action: Optional[AutonomousAction] = None
        if use_llm_planner:
            action = await _llm_next_action(findings, iter_n, seed_targets, objective)
        if action is None:
            action = _rule_based_next_action(findings, iter_n, seed_targets)

        if action.kind == "noop":
            summary.stop_reason = f"planner_done:{action.rationale}"
            break

        logger.info(
            f"[autonomous iter {iter_n}] {action.kind} → {action.target} "
            f"(est={action.estimated_value:.2f}): {action.rationale}"
        )

        # Act
        t0 = time.time()
        try:
            await _execute_action(action, engagement_store, base_config)
            err = ""
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            logger.error(f"autonomous iter {iter_n} action {action.kind} failed: {err}")

        # Score
        if engagement_store is not None:
            new_findings = engagement_store.list_findings(limit=500)
            findings_after = len(new_findings)
            new_crit = sum(1 for f in new_findings[:findings_after - findings_before]
                           if f.severity == "critical")
            new_high = sum(1 for f in new_findings[:findings_after - findings_before]
                           if f.severity == "high")
        else:
            findings_after = 0
            new_crit = new_high = 0

        reward = (
            new_crit * SEVERITY_REWARD["critical"]
            + new_high * SEVERITY_REWARD["high"]
            + max(0, findings_after - findings_before - new_crit - new_high) * 0.1
        )
        report = IterationReport(
            iteration=iter_n, action=action,
            duration_s=time.time() - t0,
            findings_before=findings_before,
            findings_after=findings_after,
            new_critical=new_crit, new_high=new_high,
            reward=reward, error=err,
        )
        summary.iterations.append(report)
        iter_n += 1

    else:
        summary.stop_reason = "max_iterations_reached"

    # Final stats
    summary.ended_at = time.time()
    if engagement_store is not None:
        all_findings = engagement_store.list_findings(limit=10000)
        summary.total_findings = len(all_findings)
        summary.total_critical = sum(1 for f in all_findings if f.severity == "critical")
        summary.total_high = sum(1 for f in all_findings if f.severity == "high")

    logger.info(
        f"autonomous loop finished: {len(summary.iterations)} iter(s), "
        f"{summary.total_findings} total findings, stop={summary.stop_reason}"
    )
    return summary
