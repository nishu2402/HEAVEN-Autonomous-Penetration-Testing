"""HEAVEN — a scan must never hang, and its web/vuln timeouts must fit the scope.

Regression tests for the two bugs found on a live full-range + UDP scan of a slow
remote host (www.certifiedhacker.com): the scan froze at a fixed percentage for
over an hour, and the web tasks tripped fixed timeouts that were too short for the
scope.

1. ``_execute_phase`` bounds every phase. A task whose *cancellation itself*
   stalls (the real failure mode — aiohttp/TLS teardown against an unresponsive
   target) can no longer freeze the pipeline: the phase hits its deadline,
   force-finalises the stuck task as FAILED, releases its dependents, and returns.
2. ``_effective_timeout`` scales web/vuln task timeouts by the stealth + scope
   factor, and leaves the self-scaling network task alone.
"""

from __future__ import annotations

import asyncio
import time

from heaven.orchestrator import ScanOrchestrator, ScanPhase, TaskState


def _fast_deadline(orch: ScanOrchestrator) -> None:
    """Shrink the phase-deadline constants so the test runs in well under a second
    instead of the production 180s+ floor."""
    orch._phase_deadline_factor = 1.0
    orch._phase_deadline_margin = 0.4


async def _stubborn():
    """A task that ignores the first cancellation, mimicking an aiohttp/TLS
    teardown that stalls against a dead host and defeats ``wait_for``."""
    try:
        await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await asyncio.sleep(3600)
        raise


async def test_hung_task_cannot_freeze_the_phase():
    orch = ScanOrchestrator()
    _fast_deadline(orch)

    tid = orch.add_task("Stubborn Web Task", _stubborn,
                        phase=ScanPhase.VULN_SCAN, concurrency_group="web",
                        timeout=0.2)
    assert tid is not None

    t0 = time.monotonic()
    results = await asyncio.wait_for(
        orch._execute_phase(ScanPhase.VULN_SCAN), timeout=10.0)
    elapsed = time.monotonic() - t0

    # The phase came back promptly (deadline ~= 0.2*1.0 + 0.4 = 0.6s), NOT hung.
    assert elapsed < 5.0, f"phase took {elapsed:.1f}s — it hung"
    # The stuck task is recorded as FAILED with a clear reason, and its done-event
    # is set so nothing waiting on it stalls.
    assert orch.tasks[tid].state == TaskState.FAILED
    assert "deadline" in (orch.results[tid].error or "").lower()
    assert orch._task_done_events[tid].is_set()
    assert any(r.task_id == tid for r in results)
    # Progress accounting stays whole so the bar can still reach 100.
    assert orch.progress.completed_weight > 0

    # Let the abandoned task's cancellation settle so the loop teardown is clean.
    await asyncio.sleep(0.2)


async def test_dependent_of_hung_task_is_not_stranded():
    orch = ScanOrchestrator()
    _fast_deadline(orch)

    ran = {"dep": False}

    async def _dependent():
        ran["dep"] = True
        return {"ok": True}

    hung = orch.add_task("Hung", _stubborn, phase=ScanPhase.VULN_SCAN,
                         concurrency_group="web", timeout=0.2)
    dep = orch.add_task("Dependent", _dependent, phase=ScanPhase.VALIDATION,
                        depends_on=[hung], timeout=5)

    await asyncio.wait_for(orch._execute_phase(ScanPhase.VULN_SCAN), timeout=10.0)
    # The dependency wait for VALIDATION resolves instead of blocking forever.
    await asyncio.wait_for(orch._execute_phase(ScanPhase.VALIDATION), timeout=10.0)

    assert orch.tasks[hung].state == TaskState.FAILED
    # Dependent is skipped because its dependency failed — and crucially the phase
    # returned rather than hanging on a never-terminating dependency.
    assert orch.tasks[dep].state in (TaskState.SKIPPED, TaskState.COMPLETED)

    await asyncio.sleep(0.2)


def test_effective_timeout_scales_web_not_network():
    orch = ScanOrchestrator()
    orch._web_timeout_scale = 2.0

    async def _noop(**kw):
        return {}

    web = orch.add_task("Web Fuzz", _noop, phase=ScanPhase.VULN_SCAN,
                        concurrency_group="web", timeout=600)
    vuln = orch.add_task("Vuln (default group)", _noop,
                         phase=ScanPhase.VULN_SCAN, timeout=300)
    net = orch.add_task("Network Reconnaissance", _noop,
                        phase=ScanPhase.RECON, concurrency_group="network",
                        timeout=3600)
    orch.net_task_id = net
    recon = orch.add_task("Web Crawl", _noop, phase=ScanPhase.RECON,
                          concurrency_group="web", timeout=600)

    assert orch._effective_timeout(orch.tasks[web]) == 1200      # web group scaled
    assert orch._effective_timeout(orch.tasks[vuln]) == 600      # VULN_SCAN scaled
    assert orch._effective_timeout(orch.tasks[net]) == 3600      # network untouched
    assert orch._effective_timeout(orch.tasks[recon]) == 1200    # web group scaled

    # No scaling configured -> timeouts are unchanged.
    orch._web_timeout_scale = 1.0
    assert orch._effective_timeout(orch.tasks[web]) == 600
