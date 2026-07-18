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
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from heaven.utils.logger import get_logger

logger = get_logger("ai.autonomous_loop")


# Vuln-type fragments that are worth an active exploitation-proof pass. Kept
# broad (substring match) so real scanner vuln_types — ``sql_injection``,
# ``command_injection``, ``ssrf_confirmed`` … — all trigger the proof phase.
_EXPLOITABLE_FRAGMENTS = (
    "sql", "sqli", "injection", "cmdi", "command_inj", "rce", "remote_code",
    "ssrf", "xxe", "lfi", "rfi", "path_traversal", "ssti", "deserial",
    "file_upload", "auth_bypass",
)

# Vuln-types / title fragments that mean we recovered or can guess credentials.
_CRED_VULN_TYPES = frozenset({
    "weak_credentials", "default_credentials", "exposed_credentials",
    "hardcoded_credentials", "credential_exposure",
})


def _root_url(target: str) -> str:
    """``scheme://host[:port]`` for a URL target, or the bare host for a
    non-URL. Used to dedupe "already web-scanned" surfaces so the loop follows
    *new* hosts instead of re-scanning every path of one it already covered."""
    target = (target or "").strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        p = urlparse(target)
        return f"{p.scheme}://{p.netloc}" if p.netloc else target
    return target


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

    def to_dict(self) -> dict:
        """One iteration in the same shape the UI table + WS stream consume."""
        return {
            "n": self.iteration,
            "action": {"kind": self.action.kind, "target": self.action.target,
                       "mode": self.action.mode, "rationale": self.action.rationale,
                       "estimated_value": self.action.estimated_value},
            "duration_s": round(self.duration_s, 1),
            "new_findings": self.new_findings,
            "new_critical": self.new_critical, "new_high": self.new_high,
            "reward": round(self.reward, 3),
            "error": self.error,
        }


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
    # ── Professional executive layer (filled by _finalize_report) ──
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    top_findings: list[dict] = field(default_factory=list)
    hosts_engaged: list[str] = field(default_factory=list)
    actions_taken: dict[str, int] = field(default_factory=dict)
    executive_summary: str = ""
    recommendations: list[str] = field(default_factory=list)

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
            "severity_breakdown": self.severity_breakdown,
            "top_findings": self.top_findings,
            "hosts_engaged": self.hosts_engaged,
            "actions_taken": self.actions_taken,
            "executive_summary": self.executive_summary,
            "recommendations": self.recommendations,
            "iterations": [r.to_dict() for r in self.iterations],
        }


# ═══════════════════════════════════════════
# RULE-BASED FALLBACK PLANNER
# Used when no LLM is configured. Mirrors a junior pen-tester's playbook.
# ═══════════════════════════════════════════


def _rule_based_next_action(
    findings: list[dict], iteration: int,
    targets_seed: dict,
    history: list[AutonomousAction],
) -> AutonomousAction:
    """Deterministic playbook used when no LLM is configured.

    Unlike a single-shot "recon then give up", this mirrors how a methodical
    tester works a target end-to-end, and — crucially — never repeats an action
    it has already run (``history`` is the ordered log of executed actions), so
    it keeps making forward progress across iterations instead of stalling:

      1. **Recon** — full-scan every seed *host* and web-scan every seed *URL*
         (all of them, not just the first).
      2. **Follow the surface** — web-scan any *new* http(s) host that turned up
         in findings but hasn't been scanned yet (deduped by scheme://host).
      3. **Prove impact** — when an exploitable finding (SQLi/RCE/SSRF/XXE/LFI/…)
         reaches ≥0.6 confidence, run the exploitation-proof pass once.
      4. **Fan out** — when credentials are recovered, attempt read-only
         credential reuse once.
      5. Otherwise the playbook is exhausted → ``noop`` (a clean, explained stop,
         not a silent one).
    """
    done: set[tuple[str, str, str]] = {(a.kind, a.target, a.mode) for a in history}
    kinds_done: set[str] = {a.kind for a in history}
    scanned_roots: set[str] = {
        _root_url(t) for (k, t, _m) in done if k == "scan" and t
    }

    ip_seeds = [s for s in (targets_seed.get("ips") or []) if s]
    url_seeds = [s for s in (targets_seed.get("urls") or []) if s]
    if not (ip_seeds or url_seeds):
        return AutonomousAction(kind="noop", rationale="no seed targets given")

    # ── Phase 1: recon every seed exactly once ──
    for host in ip_seeds:
        if _root_url(host) not in scanned_roots:
            return AutonomousAction(
                kind="scan", target=host, mode="full",
                rationale="recon: full network + service scan of seed host",
                estimated_value=0.9,
            )
    for u in url_seeds:
        if _root_url(u) not in scanned_roots:
            return AutonomousAction(
                kind="scan", target=u, mode="web",
                rationale="recon: web application scan of seed URL",
                estimated_value=0.9,
            )

    # ── Phase 2: follow any NEW web surface discovered in findings ──
    discovered = sorted({
        _root_url(f.get("target") or "")
        for f in findings
        if (f.get("target") or "").startswith("http")
    })
    for root in discovered:
        if root and root not in scanned_roots:
            return AutonomousAction(
                kind="scan", target=root, mode="web",
                rationale="new web surface discovered in findings — deep web scan",
                estimated_value=0.65,
            )

    # ── Phase 3: prove exploitable, high-confidence findings ──
    exploitable = [
        f for f in findings
        if any(frag in (f.get("vuln_type") or "").lower() for frag in _EXPLOITABLE_FRAGMENTS)
        and float(f.get("confidence") or 0) >= 0.6
    ]
    if exploitable and "exploit_proof" not in kinds_done:
        return AutonomousAction(
            kind="exploit_proof",
            rationale=f"{len(exploitable)} exploitable high-confidence finding(s) "
                      f"— run read-only exploitation proof",
            estimated_value=0.85,
        )

    # ── Phase 4: credential reuse when creds were recovered ──
    has_creds = any(
        (f.get("vuln_type") or "") in _CRED_VULN_TYPES
        or "password" in (f.get("title") or "").lower()
        or "credential" in (f.get("title") or "").lower()
        for f in findings
    )
    if has_creds and "postex_credreuse" not in kinds_done:
        return AutonomousAction(
            kind="postex_credreuse",
            rationale="credentials discovered — attempt read-only credential reuse",
            estimated_value=0.7,
        )

    return AutonomousAction(
        kind="noop",
        rationale="playbook complete — recon, surface-follow, proof and cred-reuse "
                  "all exhausted for the discovered attack surface",
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
                    logger.debug("suppressed non-fatal exception", exc_info=True)
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
    on_iteration: Optional[Callable[[dict], None]] = None,
) -> AutonomousRunSummary:
    """Drive the observe → plan → act loop.

    Returns an AutonomousRunSummary suitable for serialisation and audit.

    ``on_iteration`` (optional) is invoked with each completed iteration's
    ``IterationReport.to_dict()`` as soon as it finishes — used by the API to
    stream live progress over a WebSocket. It must not raise; failures are
    swallowed so a flaky consumer can't break the run.
    """
    summary = AutonomousRunSummary(
        started_at=time.time(), target_objective=objective,
    )
    iter_n = 0
    history: list[AutonomousAction] = []   # ordered log of executed actions

    while iter_n < max_iterations:
        elapsed = time.time() - summary.started_at
        if elapsed > time_budget_s:
            summary.stop_reason = "time_budget_exhausted"
            break

        # Observe — pull every finding stored so far AND remember which IDs
        # we knew about, so we can diff after the action (engagement DB orders
        # by severity, not recency, so list[:N] would attribute the wrong
        # findings as "new").
        if engagement_store is not None:
            raw_before = engagement_store.list_findings(limit=10000)
            findings = [
                {
                    "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                    "title": f.title, "severity": f.severity,
                    "confidence": f.confidence, "evidence": f.evidence,
                }
                for f in raw_before
            ]
            findings_before_ids = {f.id for f in raw_before}
        else:
            findings = []
            findings_before_ids = set()
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
            action = _rule_based_next_action(findings, iter_n, seed_targets, history)

        if action.kind == "noop":
            summary.stop_reason = f"planner_done:{action.rationale}"
            break

        history.append(action)

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

        # Score — set-diff on finding IDs gives us the ACTUAL new findings,
        # not the top-N-by-severity that list_findings happens to return first.
        if engagement_store is not None:
            raw_after = engagement_store.list_findings(limit=10000)
            findings_after = len(raw_after)
            actually_new = [f for f in raw_after if f.id not in findings_before_ids]
            new_crit = sum(1 for f in actually_new if f.severity == "critical")
            new_high = sum(1 for f in actually_new if f.severity == "high")
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

        if on_iteration is not None:
            try:
                on_iteration(report.to_dict())
            except Exception:
                logger.debug("on_iteration callback raised; ignoring", exc_info=True)

    else:
        summary.stop_reason = "max_iterations_reached"

    # Final stats + the professional executive layer.
    summary.ended_at = time.time()
    _finalize_report(summary, engagement_store, history)

    logger.info(
        f"autonomous loop finished: {len(summary.iterations)} iter(s), "
        f"{summary.total_findings} total findings, stop={summary.stop_reason}"
    )
    return summary


# ═══════════════════════════════════════════
# EXECUTIVE REPORT
# Turns a raw run into a professional, self-explaining summary so the output
# reads like a report even on a lean rule-based (no-LLM) run.
# ═══════════════════════════════════════════


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _host_of(target: str) -> str:
    """Bare host for a URL/host target — used to count distinct hosts engaged."""
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith("http://") or t.startswith("https://"):
        return urlparse(t).hostname or t
    return t.split("/")[0].split(":")[0]


def _finalize_report(
    summary: AutonomousRunSummary,
    engagement_store,
    history: list[AutonomousAction],
) -> None:
    """Populate the executive layer of the summary from the engagement store.

    Best-effort: any failure leaves the (already-serialisable) base summary
    intact rather than breaking the run.
    """
    summary.actions_taken = _count_actions(history)

    findings: list = []
    if engagement_store is not None:
        try:
            findings = engagement_store.list_findings(limit=10000)
        except Exception:  # noqa: BLE001 — a report must never break a completed run
            logger.debug("list_findings failed during finalize", exc_info=True)
            findings = []

    breakdown = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    hosts: set[str] = set()
    for f in findings:
        sev = (getattr(f, "severity", "") or "info").lower()
        breakdown[sev] = breakdown.get(sev, 0) + 1
        h = _host_of(getattr(f, "target", "") or "")
        if h:
            hosts.add(h)

    summary.total_findings = len(findings)
    summary.total_critical = breakdown.get("critical", 0)
    summary.total_high = breakdown.get("high", 0)
    summary.severity_breakdown = breakdown
    summary.hosts_engaged = sorted(hosts)

    # Top findings — already severity-then-confidence sorted by list_findings.
    summary.top_findings = [
        {
            "title": getattr(f, "title", "") or getattr(f, "vuln_type", "") or "finding",
            "severity": (getattr(f, "severity", "") or "info").lower(),
            "target": getattr(f, "target", "") or "",
            "vuln_type": getattr(f, "vuln_type", "") or "",
            "confidence": round(float(getattr(f, "confidence", 0) or 0), 2),
            "cve_id": getattr(f, "cve_id", "") or "",
        }
        for f in findings[:8]
    ]

    summary.executive_summary = _executive_summary(summary)
    summary.recommendations = _recommendations(summary)


def _count_actions(history: list[AutonomousAction]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in history:
        counts[a.kind] = counts.get(a.kind, 0) + 1
    return counts


def _executive_summary(s: AutonomousRunSummary) -> str:
    """A short, factual narrative — no fabrication, only what the run produced."""
    n_hosts = len(s.hosts_engaged)
    host_word = "host" if n_hosts == 1 else "hosts"
    iters = len(s.iterations)
    iter_word = "iteration" if iters == 1 else "iterations"

    if s.total_findings == 0:
        body = (
            f"The autonomous loop ran {iters} {iter_word} across {n_hosts} {host_word} "
            f"and surfaced no confirmed findings. The attack surface reached appears "
            f"hardened against the checks exercised, or the seed targets exposed little "
            f"to probe."
        )
    else:
        c, h = s.total_critical, s.total_high
        sev_bits = []
        if c:
            sev_bits.append(f"{c} critical")
        if h:
            sev_bits.append(f"{h} high")
        med = s.severity_breakdown.get("medium", 0)
        low = s.severity_breakdown.get("low", 0)
        if med:
            sev_bits.append(f"{med} medium")
        if low:
            sev_bits.append(f"{low} low")
        sev_str = ", ".join(sev_bits) if sev_bits else "informational-only"
        headline = (
            "immediate remediation is warranted"
            if c else "prompt remediation is advised"
            if h else "the exposure is limited but worth addressing"
        )
        body = (
            f"Across {iters} planned {iter_word} the loop engaged {n_hosts} {host_word} "
            f"and confirmed {s.total_findings} finding(s) ({sev_str}). "
            f"Given the severity profile, {headline}."
        )
    if s.objective_met and s.target_objective:
        body += f" The stated objective — \"{s.target_objective}\" — was met."
    return body


def _recommendations(s: AutonomousRunSummary) -> list[str]:
    """Actionable next steps derived from what the run actually found."""
    recs: list[str] = []
    if s.total_critical:
        recs.append(
            f"Triage and remediate the {s.total_critical} critical finding(s) first — "
            f"these are directly exploitable and should block release."
        )
    if s.total_high:
        recs.append(
            f"Schedule fixes for the {s.total_high} high-severity finding(s) within the "
            f"current sprint and re-scan to confirm closure."
        )
    med = s.severity_breakdown.get("medium", 0)
    if med:
        recs.append(f"Address the {med} medium finding(s) as part of routine hardening.")
    if s.total_findings == 0:
        recs.append(
            "No findings surfaced. Broaden the seed scope (add discovered subdomains / "
            "internal hosts) or run with an LLM planner key set for deeper hypothesis-driven "
            "testing."
        )
    else:
        recs.append(
            "Export the full report (heaven report export) and re-run after fixes to "
            "produce a delta and evidence of remediation."
        )
    if not s.actions_taken.get("exploit_proof") and (s.total_critical or s.total_high):
        recs.append(
            "Run an exploitation-proof pass on the high-impact findings to attach "
            "reproducible evidence before reporting to stakeholders."
        )
    return recs
