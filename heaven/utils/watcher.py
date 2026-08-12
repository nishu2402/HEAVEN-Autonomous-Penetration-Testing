"""
HEAVEN — Continuous-monitoring watch loop

The old `heaven schedule` ran scans on cron and treated every result the
same — so a re-scan that turned up nothing new still triggered a Slack
ping. That's alert fatigue. The watch loop fixes it by:

  1. Running a scan on a configurable interval (+ optional jitter)
  2. Computing the diff against the previous scan in the same engagement
  3. Emitting alerts ONLY when the diff contains new / regressed findings
     (or when the operator opts in to a heartbeat ping)
  4. Optionally auto-creating tickets for new criticals + regressed crit/high
  5. Persisting iteration state to the engagement DB so a restart resumes
     from where it left off

Designed for operator's-laptop use OR for a long-lived `heaven serve`
process — the loop is pure asyncio, no threads, no signal-handling magic
beyond honouring KeyboardInterrupt cleanly.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from heaven.utils.logger import get_logger

logger = get_logger("utils.watcher")


# ═══════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════


@dataclass
class WatchConfig:
    targets: dict[str, Any]                 # passed to build_full_scan
    engagement_name: str                    # must already exist
    interval_s: int = 3600                  # seconds between scan starts
    jitter_pct: float = 0.1                 # ±10% randomisation by default
    max_iterations: int = 0                 # 0 = run forever
    alert_on_heartbeat: bool = False        # ping even when nothing changed
    auto_create_tickets: bool = False       # create Jira/Linear on new crit + regression
    seed: Optional[int] = None              # propagated to scan for reproducible runs

    def next_sleep(self) -> float:
        """Returns interval_s with bounded random jitter applied."""
        if self.jitter_pct <= 0:
            return float(self.interval_s)
        delta = self.interval_s * self.jitter_pct
        return max(1.0, self.interval_s + random.uniform(-delta, delta))  # nosec B311


@dataclass
class WatchIteration:
    n: int
    started_at: float
    finished_at: float = 0.0
    scan_id: str = ""
    findings_total: int = 0
    new: int = 0
    regressed: int = 0
    resolved: int = 0
    alert_dispatched: bool = False
    tickets_created: int = 0
    error: str = ""
    baseline: bool = False              # first iteration — establishes the baseline
    # Compact list of the notable changes this iteration (new + regressed),
    # so the API/UI can show WHAT changed, not just how many.
    changes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.regressed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scan_id": self.scan_id,
            "findings_total": self.findings_total,
            "new": self.new,
            "regressed": self.regressed,
            "resolved": self.resolved,
            "changed": self.changed,
            "alert_dispatched": self.alert_dispatched,
            "tickets_created": self.tickets_created,
            "baseline": self.baseline,
            "changes": self.changes,
            "error": self.error,
        }


@dataclass
class WatchSummary:
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    iterations: list[WatchIteration] = field(default_factory=list)
    stop_reason: str = ""

    @property
    def total_iterations(self) -> int:
        return len(self.iterations)

    @property
    def total_alerts(self) -> int:
        return sum(1 for i in self.iterations if i.alert_dispatched)

    @property
    def total_tickets(self) -> int:
        return sum(i.tickets_created for i in self.iterations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_s": round((self.ended_at or time.time()) - self.started_at, 1),
            "iterations": self.total_iterations,
            "alerts_dispatched": self.total_alerts,
            "tickets_created": self.total_tickets,
            "stop_reason": self.stop_reason,
            "changes_detected": sum(1 for i in self.iterations if i.changed),
            "last_iteration": (
                self.iterations[-1].to_dict() if self.iterations else None
            ),
        }


# ═══════════════════════════════════════════
# THE LOOP
# ═══════════════════════════════════════════


async def run_watch(
    config: WatchConfig,
    base_heaven_config,
    *,
    on_iteration: Optional[Callable[[WatchIteration], None]] = None,
) -> WatchSummary:
    """Continuous watch loop. Returns when max_iterations is hit or
    KeyboardInterrupt is raised in the caller.
    """
    from heaven.cli._helpers import _engagement_db_path
    from heaven.engagement import EngagementStore
    from heaven.orchestrator import build_full_scan

    summary = WatchSummary()
    db_path = _engagement_db_path(config.engagement_name)
    if not db_path.exists():
        summary.stop_reason = f"engagement DB not found: {db_path}"
        summary.ended_at = time.time()
        return summary

    store = EngagementStore(db_path)
    last_scan_id: Optional[str] = None

    iter_n = 0
    try:
        while True:
            if config.max_iterations and iter_n >= config.max_iterations:
                summary.stop_reason = "max_iterations_reached"
                break

            iteration = WatchIteration(n=iter_n, started_at=time.time())

            # Run a scan
            try:
                if config.seed is not None:
                    from heaven.utils.seeding import set_seed
                    set_seed(config.seed + iter_n)  # vary per-iteration deterministically

                orch = build_full_scan(
                    config.targets, base_heaven_config, checkpoint_store=store,
                )
                store.record_scan_start(
                    orch.scan_id, name=f"watch-{iter_n}",
                    mode=base_heaven_config.scan_mode.value,
                    config={"targets": config.targets, "watch_iteration": iter_n,
                            "seed": (config.seed + iter_n) if config.seed is not None else None},
                )
                scan_summary = await orch.run()
                for f in (scan_summary.get("vulnerabilities", [])
                          + scan_summary.get("findings", [])):
                    try:
                        store.upsert_finding(orch.scan_id, f)
                    except Exception:
                        logger.debug("suppressed non-fatal exception", exc_info=True)

                iteration.scan_id = orch.scan_id
                iteration.findings_total = store.count_findings()
                iteration.baseline = last_scan_id is None

                # Diff against the previous iteration's scan. Computed BEFORE
                # record_scan_complete so it can be folded into the persisted
                # summary (which is how the web UI / a resumed run reads what
                # changed — otherwise the whole "auto-diff" is invisible after
                # the fact). compute_diff anchors on the current scan's
                # started_at (already recorded), so completing it later is fine.
                watch_meta: dict[str, Any] = {
                    "iteration": iter_n, "baseline": iteration.baseline,
                    "new": 0, "regressed": 0, "resolved": 0,
                }
                if last_scan_id:
                    try:
                        from heaven.devsecops.diff_finder import compute_diff
                        diff = compute_diff(store, last_scan_id, orch.scan_id)
                        iteration.new = len(diff.new)
                        iteration.regressed = len(diff.regressed)
                        iteration.resolved = len(diff.resolved)
                        iteration.changes = _summarize_changes(diff)
                        watch_meta.update(
                            new=iteration.new, regressed=iteration.regressed,
                            resolved=iteration.resolved,
                            critical_new=diff.critical_new,
                            regressed_critical_or_high=diff.regressed_critical_or_high,
                        )

                        # Alert on CHANGE (new / regressed) — or on every cycle
                        # if the operator opted into a heartbeat.
                        if iteration.new or iteration.regressed:
                            iteration.alert_dispatched = await _dispatch_alerts(
                                diff, iteration, config, heartbeat=False,
                            )
                        elif config.alert_on_heartbeat:
                            iteration.alert_dispatched = await _dispatch_alerts(
                                diff, iteration, config, heartbeat=True,
                            )
                        if config.auto_create_tickets and (iteration.new or iteration.regressed):
                            iteration.tickets_created = await _auto_ticket(
                                diff, store,
                            )
                    except Exception as e:
                        iteration.error = f"diff: {type(e).__name__}: {e}"
                        logger.warning(f"watch iter {iter_n} diff failed: {e}")
                else:
                    # First iteration — no baseline yet. Optionally heartbeat.
                    if config.alert_on_heartbeat:
                        iteration.alert_dispatched = await _heartbeat(config)

                watch_meta["alert_dispatched"] = iteration.alert_dispatched
                watch_meta["tickets_created"] = iteration.tickets_created
                # Fold the diff into the persisted scan summary so the UI + a
                # resumed run can show exactly what changed this iteration.
                store.record_scan_complete(
                    orch.scan_id, {**scan_summary, "watch": watch_meta},
                )

                last_scan_id = orch.scan_id
            except Exception as e:
                iteration.error = f"{type(e).__name__}: {e}"
                logger.error(f"watch iter {iter_n} failed: {e}")

            iteration.finished_at = time.time()
            summary.iterations.append(iteration)
            if on_iteration:
                try:
                    on_iteration(iteration)
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)

            logger.info(
                f"[watch iter {iter_n}] scan={iteration.scan_id[:8] if iteration.scan_id else '—'} "
                f"new={iteration.new} regressed={iteration.regressed} "
                f"resolved={iteration.resolved} "
                f"alert={'✓' if iteration.alert_dispatched else '·'} "
                f"tix={iteration.tickets_created}"
            )

            iter_n += 1
            if config.max_iterations and iter_n >= config.max_iterations:
                summary.stop_reason = "max_iterations_reached"
                break

            sleep_s = config.next_sleep()
            logger.info(f"[watch] sleeping {sleep_s:.0f}s until next iteration")
            await asyncio.sleep(sleep_s)

    except (KeyboardInterrupt, asyncio.CancelledError):
        summary.stop_reason = "operator_interrupt"
    finally:
        summary.ended_at = time.time()
    return summary


# ═══════════════════════════════════════════
# ALERTING + TICKETING HOOKS
# ═══════════════════════════════════════════


def _summarize_changes(diff, cap: int = 12) -> list[dict[str, Any]]:
    """Compact, JSON-safe list of what changed (new + regressed) this iter."""
    out: list[dict[str, Any]] = []
    for r in diff.new[:cap]:
        out.append({
            "kind": "new", "severity": r.severity, "vuln_type": r.vuln_type,
            "target": r.target, "title": r.title or r.vuln_type,
        })
    for r in diff.regressed[: max(0, cap - len(out))]:
        out.append({
            "kind": "regressed", "severity": r.severity, "vuln_type": r.vuln_type,
            "target": r.target, "title": r.title or r.vuln_type,
        })
    return out


async def _dispatch_alerts(
    diff, iteration: WatchIteration, config: "WatchConfig",
    *, heartbeat: bool = False,
) -> bool:
    """Fire whichever alerters are configured (webhook + SIEM).

    ``heartbeat=True`` means this cycle had NO change but the operator asked
    for a per-run ping, so the message is a heartbeat rather than a change
    alert. Watch alerts go out for *any* change — including medium/low — via
    ``send_watch_alert_async`` (the scan-complete ``send_alert_async`` stays
    silent unless critical/high, which is the wrong contract for watch mode).
    """
    from heaven.devsecops.alerting import SIEMNotifier, WebhookAlerter
    ok = False
    summary = {
        "scan_id": iteration.scan_id,
        "engagement": config.engagement_name,
        "watch_iteration": iteration.n,
        "new": iteration.new,
        "regressed": iteration.regressed,
        "resolved": iteration.resolved,
        "critical_new": diff.critical_new,
        "regressed_critical_or_high": diff.regressed_critical_or_high,
        "total_assets": iteration.findings_total,
        # WebhookAlerter watch-message format
        "critical": diff.critical_new,
        "high": sum(1 for r in diff.new if r.severity == "high"),
    }
    try:
        webhook = WebhookAlerter()
        if webhook.webhook_url:
            ok = await webhook.send_watch_alert_async(summary) or ok
    except Exception as e:
        logger.warning(f"webhook alert failed: {e}")
    try:
        siem = SIEMNotifier()
        if siem.configured_backends:
            # Emit a structured event for SOC
            await siem.emit(
                "watch.heartbeat" if heartbeat else "watch.change", summary,
            )
            ok = True
    except Exception as e:
        logger.warning(f"SIEM emit failed: {e}")
    return ok


async def _heartbeat(config: "WatchConfig") -> bool:
    """First-iteration ping when --heartbeat is set (there is no baseline to
    diff against yet, so this announces that monitoring has started)."""
    from heaven.devsecops.alerting import SIEMNotifier, WebhookAlerter
    payload = {
        "engagement": config.engagement_name,
        "watch_iteration": 0, "new": 0, "regressed": 0, "resolved": 0,
        "total_assets": 0, "first_run": True,
    }
    ok = False
    w = WebhookAlerter()
    if w.webhook_url:
        try:
            ok = await w.send_watch_alert_async(payload) or ok
        except Exception as e:
            logger.warning(f"heartbeat failed: {e}")
    try:
        siem = SIEMNotifier()
        if siem.configured_backends:
            await siem.emit("watch.start", payload)
            ok = True
    except Exception as e:
        logger.warning(f"SIEM heartbeat emit failed: {e}")
    return ok


async def _auto_ticket(diff, store) -> int:
    """Create tickets for new criticals + every regression."""
    from heaven.devsecops.alerting import TicketingDispatcher
    d = TicketingDispatcher()
    if not d.has_any:
        return 0
    rows = [r for r in diff.new if r.severity == "critical"] + list(diff.regressed)
    created = 0
    for r in rows[:25]:  # safety cap per iteration
        finding = store.get_finding(r.id)
        if not finding:
            continue
        result = await d.dispatch({
            "id": finding.id, "target": finding.target,
            "vuln_type": finding.vuln_type, "title": finding.title,
            "severity": finding.severity, "confidence": finding.confidence,
            "cve_id": finding.cve_id,
        })
        if any(v.get("ok") for v in result.values()):
            created += 1
    return created
