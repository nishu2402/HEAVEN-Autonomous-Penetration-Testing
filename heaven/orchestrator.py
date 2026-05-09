"""
HEAVEN — Core Async Orchestrator
Manages the complete scan lifecycle with dependency-aware task scheduling,
concurrency control, and real-time progress reporting.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

from heaven.config import HeavenConfig, get_config
from heaven.ml.ai_brain import BayesianPrioritiser
from heaven.utils.logger import get_logger

logger = get_logger("orchestrator")


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ScanPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    AD_RECON = "ad_recon"
    IOT_SCAN = "iot_scan"
    VULN_SCAN = "vuln_scan"
    API_SCAN = "api_scan"
    CONTAINER_SCAN = "container_scan"
    VALIDATION = "validation"
    ML_SCORING = "ml_scoring"
    MITRE_MAPPING = "mitre_mapping"
    REPORTING = "reporting"
    DONE = "done"


@dataclass
class TaskResult:
    """Result of a single orchestrator task."""
    task_id: str
    name: str
    state: TaskState
    duration_ms: float = 0.0
    data: Any = None
    error: Optional[str] = None
    items_processed: int = 0


@dataclass
class ScanProgress:
    """Real-time scan progress tracking."""
    scan_id: str
    phase: ScanPhase = ScanPhase.INIT
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    current_task: str = ""
    start_time: float = field(default_factory=time.time)
    findings_count: int = 0
    assets_discovered: int = 0
    vulns_found: int = 0

    @property
    def progress_pct(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase.value,
            "progress": round(self.progress_pct, 1),
            "completed": self.completed_tasks,
            "total": self.total_tasks,
            "failed": self.failed_tasks,
            "current_task": self.current_task,
            "elapsed_s": round(self.elapsed_seconds, 1),
            "findings": self.findings_count,
            "assets": self.assets_discovered,
            "vulns": self.vulns_found,
        }


@dataclass
class OrchestratorTask:
    """A task node in the execution graph."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    phase: ScanPhase = ScanPhase.RECON
    coro_factory: Optional[Callable[..., Coroutine]] = None
    kwargs: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    state: TaskState = TaskState.PENDING
    result: Optional[TaskResult] = None
    concurrency_group: str = "default"
    timeout: float = 300.0  # 5 min default


class ScanOrchestrator:
    """
    Central async orchestrator for HEAVEN scan lifecycle.

    Features:
    - Dependency-aware task graph execution
    - Per-segment concurrency pools (network=500, web=100, cloud=50)
    - Real-time progress via callback/websocket
    - Graceful cancellation and timeout handling
    - Phase-based execution: RECON → VULN_SCAN → VALIDATION → ML_SCORING → REPORTING
    """

    def __init__(self, config: Optional[HeavenConfig] = None,
                 checkpoint_store=None, resume_scan_id: Optional[str] = None):
        self.config = config or get_config()
        # Use the resumed scan_id if provided so checkpoints line up
        self.scan_id = resume_scan_id or str(uuid.uuid4())
        self.tasks: dict[str, OrchestratorTask] = {}
        self.results: dict[str, TaskResult] = {}
        self.progress = ScanProgress(scan_id=self.scan_id)
        self._cancelled = False
        self._progress_callbacks: list[Callable[[ScanProgress], Any]] = []
        # Per-task asyncio.Event so dep waiters can be unblocked on completion
        # without busy-polling.
        self._task_done_events: dict[str, asyncio.Event] = {}

        # Checkpoint store — if set, each task's terminal state is persisted.
        # On resume, completed tasks are skipped.
        self._prioritiser = BayesianPrioritiser()
        self.priority_targets: list[str] = []
        self.net_task_id: Optional[str] = None
        self._injected_service_keys: set[str] = set()

        self._checkpoint_store = checkpoint_store
        self._resumed_checkpoints: dict[str, dict] = {}
        if checkpoint_store and resume_scan_id:
            try:
                self._resumed_checkpoints = checkpoint_store.load_checkpoints(resume_scan_id)
                if self._resumed_checkpoints:
                    logger.info(
                        f"Resuming scan {resume_scan_id}: "
                        f"{len(self._resumed_checkpoints)} prior task(s) on disk"
                    )
            except Exception as e:
                logger.warning(f"Could not load checkpoints for resume: {e}")

        # Concurrency semaphores per segment
        self._semaphores = {
            "network": asyncio.Semaphore(self.config.scanner.net_concurrency),
            "web": asyncio.Semaphore(self.config.scanner.web_concurrency),
            "cloud": asyncio.Semaphore(self.config.scanner.cloud_concurrency),
            "default": asyncio.Semaphore(200),
            "ml": asyncio.Semaphore(10),
        }

    def add_task(
        self,
        name: str,
        coro_factory: Callable[..., Coroutine],
        phase: ScanPhase = ScanPhase.RECON,
        depends_on: Optional[list[str]] = None,
        concurrency_group: str = "default",
        timeout: float = 300.0,
        **kwargs,
    ) -> str:
        """Register a task in the execution graph. Returns task ID."""
        task = OrchestratorTask(
            name=name,
            phase=phase,
            coro_factory=coro_factory,
            kwargs=kwargs,
            depends_on=depends_on or [],
            concurrency_group=concurrency_group,
            timeout=timeout,
        )
        self.tasks[task.id] = task
        self._task_done_events[task.id] = asyncio.Event()
        self.progress.total_tasks += 1
        logger.debug(f"Task registered: {name} (id={task.id}, phase={phase.value})")
        return task.id

    def on_progress(self, callback: Callable[[ScanProgress], Any]) -> None:
        """Register a progress callback (called on each task completion)."""
        self._progress_callbacks.append(callback)

    def cancel(self) -> None:
        """Request graceful cancellation of the scan."""
        self._cancelled = True
        logger.warning("Scan cancellation requested")

    async def _run_task(self, task: OrchestratorTask) -> TaskResult:
        """Execute a single task with concurrency control and timeout."""
        sem = self._semaphores.get(task.concurrency_group, self._semaphores["default"])

        # Resume short-circuit: if this task previously completed, replay it
        prior = self._resumed_checkpoints.get(task.id) if self._resumed_checkpoints else None
        if prior and prior.get("state") == "completed":
            logger.info(f"⏵ {task.name} skipped (resumed from checkpoint)")
            result = TaskResult(
                task_id=task.id, name=task.name,
                state=TaskState.COMPLETED, duration_ms=0.0,
                data=prior.get("result"),
            )
            task.state = TaskState.COMPLETED
            task.result = result
            self.results[task.id] = result
            evt = self._task_done_events.get(task.id)
            if evt:
                evt.set()
            return result

        async with sem:
            if self._cancelled:
                result = TaskResult(
                    task_id=task.id, name=task.name,
                    state=TaskState.CANCELLED,
                )
                task.state = TaskState.CANCELLED
                task.result = result
                self.results[task.id] = result
                evt = self._task_done_events.get(task.id)
                if evt:
                    evt.set()
                self._maybe_checkpoint(task, result)
                return result

            task.state = TaskState.RUNNING
            self.progress.current_task = task.name
            start = time.time()

            MAX_RETRIES = 2
            retry_count = 0
            last_error = None
            result_data = None
            timed_out = False

            while retry_count <= MAX_RETRIES:
                try:
                    result_data = await asyncio.wait_for(
                        task.coro_factory(**task.kwargs),
                        timeout=task.timeout,
                    )
                    last_error = None
                    break
                except asyncio.TimeoutError:
                    last_error = f"Timeout after {task.timeout}s"
                    timed_out = True
                    break  # Don't retry timeouts
                except Exception as e:
                    last_error = str(e)
                    if retry_count < MAX_RETRIES:
                        wait = 5 * (2 ** retry_count)
                        logger.warning(f"↻ Retrying {task.name} in {wait}s (attempt {retry_count+1}/{MAX_RETRIES})")
                        await asyncio.sleep(wait)
                    retry_count += 1

            duration = (time.time() - start) * 1000

            if last_error is None:
                result = TaskResult(
                    task_id=task.id,
                    name=task.name,
                    state=TaskState.COMPLETED,
                    duration_ms=duration,
                    data=result_data,
                )
                task.state = TaskState.COMPLETED
                logger.info(f"✓ {task.name} completed in {duration:.0f}ms")
            else:
                result = TaskResult(
                    task_id=task.id, name=task.name,
                    state=TaskState.FAILED, duration_ms=duration,
                    error=last_error,
                )
                task.state = TaskState.FAILED
                if timed_out:
                    logger.error(f"✗ {task.name} timed out after {task.timeout}s")
                else:
                    logger.error(f"✗ {task.name} failed after {retry_count} attempt(s): {last_error}")

            task.result = result
            self.results[task.id] = result
            # Wake any tasks waiting on us as a dependency
            evt = self._task_done_events.get(task.id)
            if evt:
                evt.set()
            # Persist for resume
            self._maybe_checkpoint(task, result)
            return result

    def _maybe_checkpoint(self, task: "OrchestratorTask", result: "TaskResult") -> None:
        """Persist task state to checkpoint store if one is configured."""
        if not self._checkpoint_store:
            return
        try:
            # Only persist serializable result data — raw objects might not encode
            persistable = result.data
            if persistable is not None and not isinstance(persistable, (dict, list, str, int, float, bool)):
                persistable = None
            self._checkpoint_store.checkpoint_task(
                self.scan_id, task.id, task.name, task.state.value,
                result={"data": persistable, "duration_ms": result.duration_ms,
                        "error": result.error},
            )
        except Exception as e:
            logger.debug(f"Checkpoint write failed (non-fatal): {e}")

    async def _wait_for_dependencies(self, task: OrchestratorTask) -> bool:
        """Wait for all dependencies to complete. Returns False if any failed."""
        for dep_id in task.depends_on:
            dep_task = self.tasks.get(dep_id)
            if dep_task is None:
                logger.warning(f"Unknown dependency {dep_id} for task {task.name}")
                continue

            done_event = self._task_done_events.get(dep_id)
            if done_event is None:
                # Should never happen, but be defensive
                logger.warning(f"No done-event for dep {dep_id}; falling back to poll")
                while dep_task.state in (TaskState.PENDING, TaskState.RUNNING):
                    if self._cancelled:
                        return False
                    await asyncio.sleep(0.1)
            else:
                # Race the cancellation flag against the dep's done event
                while not done_event.is_set():
                    if self._cancelled:
                        return False
                    try:
                        await asyncio.wait_for(done_event.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue

            if dep_task.state == TaskState.FAILED:
                logger.warning(f"Dependency {dep_task.name} failed; skipping {task.name}")
                return False

        return True

    def _inject_service_tasks(self, net_data: dict) -> None:
        """Inject follow-on tasks based on services discovered during RECON."""
        hosts = net_data.get("hosts", [])
        for host in hosts:
            ip = host.get("ip", "")
            for port_info in host.get("open_ports", []):
                port = port_info.get("port", 0)
                service = (port_info.get("service") or "").lower()
                task_key = f"dynamic_{ip}_{port}"
                if task_key in self._injected_service_keys:
                    continue
                self._injected_service_keys.add(task_key)

                if "ssh" in service or port == 22:
                    async def _ssh_check(ip=ip, port=port, **kw):
                        try:
                            from heaven.vulnscan.advanced_attacks import CredentialSprayer
                            import aiohttp
                            async with aiohttp.ClientSession() as session:
                                sprayer = CredentialSprayer()
                                return await sprayer.spray(session, f"ssh://{ip}:{port}")
                        except Exception:
                            return {}
                    self.add_task(f"SSH Credential Check {ip}:{port}", _ssh_check,
                                  phase=ScanPhase.VULN_SCAN, timeout=120)

                elif port in (445, 139) or "smb" in service or "microsoft-ds" in service:
                    async def _smb_enum(ip=ip, **kw):
                        try:
                            from heaven.recon.ad_scanner import scan_active_directory
                            return await scan_active_directory(dc_host=ip)
                        except Exception:
                            return {}
                    self.add_task(f"SMB Enumeration {ip}", _smb_enum,
                                  phase=ScanPhase.AD_RECON, timeout=180)

                elif port == 3389 or "rdp" in service or "ms-wbt-server" in service:
                    async def _rdp_check(ip=ip, port=port, **kw):
                        try:
                            from heaven.vulnscan.advanced_attacks import test_default_credentials
                            import aiohttp
                            async with aiohttp.ClientSession() as session:
                                return await test_default_credentials(session, f"http://{ip}:{port}")
                        except Exception:
                            return {}
                    self.add_task(f"RDP Default Credentials {ip}", _rdp_check,
                                  phase=ScanPhase.VULN_SCAN, timeout=120)

                elif port in (3306, 5432, 1433, 27017, 6379) or any(
                    db in service for db in ("mysql", "postgres", "mssql", "mongodb", "redis")
                ):
                    async def _db_check(ip=ip, port=port, service=service, **kw):
                        return {
                            "finding": {
                                "target": f"{ip}:{port}",
                                "vuln_type": "exposed_database",
                                "title": f"Exposed {service.upper()} port {port}",
                                "severity": "high",
                                "confidence": 0.8,
                            }
                        }
                    self.add_task(f"Exposed DB {ip}:{port}", _db_check,
                                  phase=ScanPhase.VULN_SCAN, timeout=30)

        injected = [t for t in self.tasks.values() if t.id.startswith("dynamic_") or
                    any(x in t.name for x in ("SSH", "SMB", "RDP", "Exposed DB"))]
        if injected:
            logger.info(f"Dynamic injection: {len(injected)} service-specific tasks added")

    async def _execute_phase(self, phase: ScanPhase) -> list[TaskResult]:
        """Execute all tasks for a given phase with dependency resolution."""
        phase_tasks = [t for t in self.tasks.values() if t.phase == phase and t.state == TaskState.PENDING]

        if not phase_tasks:
            return []

        self.progress.phase = phase
        logger.info(f"═══ Phase: {phase.value.upper()} ({len(phase_tasks)} tasks) ═══")

        async def run_with_deps(task: OrchestratorTask) -> TaskResult:
            deps_ok = await self._wait_for_dependencies(task)
            if not deps_ok:
                task.state = TaskState.SKIPPED
                result = TaskResult(task_id=task.id, name=task.name, state=TaskState.SKIPPED)
                task.result = result
                self.results[task.id] = result
                self.progress.completed_tasks += 1
                # Wake anyone waiting on us
                evt = self._task_done_events.get(task.id)
                if evt:
                    evt.set()
                return result

            result = await self._run_task(task)

            if result.state == TaskState.COMPLETED:
                self.progress.completed_tasks += 1
            elif result.state == TaskState.FAILED:
                self.progress.failed_tasks += 1
                self.progress.completed_tasks += 1

            # Notify progress callbacks
            for cb in self._progress_callbacks:
                try:
                    ret = cb(self.progress)
                    if asyncio.iscoroutine(ret):
                        await ret
                except Exception as e:
                    logger.debug(f"Progress callback error: {e}")

            return result

        # Run all phase tasks concurrently (semaphores control actual parallelism)
        results = await asyncio.gather(
            *[run_with_deps(t) for t in phase_tasks],
            return_exceptions=True,
        )

        # Handle any exceptions from gather
        processed = []
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Unexpected task error: {r}")
            elif isinstance(r, TaskResult):
                processed.append(r)

        return processed

    async def run(self) -> dict[str, Any]:
        """
        Execute the full scan pipeline in phase order.

        Returns a summary dict with all results.
        """
        logger.info(f"╔══ HEAVEN Scan {self.scan_id[:8]} starting ══╗")
        self.progress.start_time = time.time()

        phase_order = [
            ScanPhase.INIT,
            ScanPhase.RECON,
            ScanPhase.AD_RECON,
            ScanPhase.IOT_SCAN,
            ScanPhase.VULN_SCAN,
            ScanPhase.API_SCAN,
            ScanPhase.CONTAINER_SCAN,
            ScanPhase.VALIDATION,
            ScanPhase.ML_SCORING,
            ScanPhase.MITRE_MAPPING,
            ScanPhase.REPORTING,
        ]

        all_results: list[TaskResult] = []

        for phase in phase_order:
            if self._cancelled:
                logger.warning("Scan cancelled — stopping pipeline")
                break

            phase_results = await self._execute_phase(phase)
            all_results.extend(phase_results)

            if phase == ScanPhase.RECON and self.net_task_id:
                net_result = self.results.get(self.net_task_id)
                if net_result and net_result.data:
                    self._prioritiser.initialise_beliefs(net_result.data)
                    top = self._prioritiser.get_next_targets(n=20)
                    logger.info(f"Prioritised targets: {[t.host for t in top[:5]]}")
                    self.priority_targets = [t.host for t in top]
                    # Dynamic task injection based on discovered services
                    self._inject_service_tasks(net_result.data)
                else:
                    self.priority_targets = []

        self.progress.phase = ScanPhase.DONE
        elapsed = self.progress.elapsed_seconds

        all_vulns, all_assets = [], []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for tid, res in self.results.items():
            if res.state != TaskState.COMPLETED or not res.data:
                continue
            data = res.data if isinstance(res.data, dict) else {}
            for f in (data.get("vulnerabilities", []) + data.get("findings", [])
                      + data.get("candidates", []) + data.get("validated_findings", [])):
                all_vulns.append(f)
                sev = (f.get("severity") or "info").lower()
                if sev in sev_counts:
                    sev_counts[sev] += 1
            all_assets.extend(data.get("hosts", []))
            all_assets.extend(data.get("endpoints", []))

        summary = {
            "scan_id": self.scan_id,
            "status": "cancelled" if self._cancelled else "completed",
            "elapsed_seconds": round(elapsed, 2),
            "total_tasks": self.progress.total_tasks,
            "completed": self.progress.completed_tasks,
            "failed": self.progress.failed_tasks,
            "vulnerabilities": all_vulns,
            "findings": all_vulns,
            "assets": all_assets,
            **sev_counts,
            "results": {r.task_id: r.state.value for r in all_results},
        }

        status = "CANCELLED" if self._cancelled else "COMPLETED"
        logger.info(
            f"╚══ Scan {status} in {elapsed:.1f}s "
            f"({self.progress.completed_tasks}/{self.progress.total_tasks} tasks, "
            f"{self.progress.failed_tasks} failed) ══╝"
        )

        return summary


def build_full_scan(targets: dict, config: Optional[HeavenConfig] = None,
                    checkpoint_store=None,
                    resume_scan_id: Optional[str] = None) -> ScanOrchestrator:
    """
    Build the HEAVEN full scan pipeline.

    If ``checkpoint_store`` is provided (an EngagementStore), each task's
    terminal state is persisted, and passing ``resume_scan_id`` makes the
    orchestrator skip tasks that previously completed.
    """
    from heaven.recon.network_scanner import scan_network
    from heaven.recon.web_crawler import crawl_targets
    from heaven.recon.cloud_enum import enumerate_cloud
    from heaven.recon.git_secrets import scan_repositories
    from heaven.recon.honeypot_detector import check_honeypots

    orch = ScanOrchestrator(config, checkpoint_store=checkpoint_store,
                             resume_scan_id=resume_scan_id)
    stealth = targets.get("stealth_level", "normal")

    # ═══ Phase: RECON (parallel multi-vector) ═══
    net_id = orch.add_task(
        "Network Reconnaissance", scan_network,
        phase=ScanPhase.RECON, concurrency_group="network",
        targets=targets.get("ips", []),
        port_range=targets.get("ports", "1-65535"),
        stealth_level=stealth,
    )
    orch.net_task_id = net_id

    web_id = orch.add_task(
        "Web Application Crawling", crawl_targets,
        phase=ScanPhase.RECON, concurrency_group="web",
        urls=targets.get("urls", []),
    )

    cloud_id = orch.add_task(
        "Cloud Asset Enumeration", enumerate_cloud,
        phase=ScanPhase.RECON, concurrency_group="cloud",
        providers=targets.get("cloud_providers", []),
    )

    git_id = orch.add_task(
        "Git Secret Scanning", scan_repositories,
        phase=ScanPhase.RECON,
        repos=targets.get("repositories", []),
    )

    hp_id = orch.add_task(
        "Honeypot Detection", check_honeypots,
        phase=ScanPhase.RECON, depends_on=[net_id],
        scan_id=orch.scan_id,
    )

    # ═══ Phase: DEEP RECON (subdomain enum, JS secrets, endpoint fuzzing) ═══
    async def _deep_recon(**kw):
        try:
            from heaven.recon.deep_recon import (
                enumerate_subdomains, extract_js_secrets, fuzz_endpoints,
            )
            import aiohttp
            results = {"subdomains": [], "js_secrets": [], "endpoints": []}
            async with aiohttp.ClientSession() as session:
                for url in targets.get("urls", []):
                    from urllib.parse import urlparse
                    domain = urlparse(url).hostname or ""
                    if domain:
                        subs = await enumerate_subdomains(domain, session, concurrency=50)
                        results["subdomains"].extend([s.value for s in subs])
                    secrets = await extract_js_secrets(session, url)
                    results["js_secrets"].extend([s.value for s in secrets if s.asset_type == "secret"])
                    results["endpoints"].extend([s.value for s in secrets if s.asset_type == "endpoint"])
                    eps = await fuzz_endpoints(session, url)
                    results["endpoints"].extend([e.value for e in eps])
            return results
        except ImportError:
            return {}

    deep_id = orch.add_task(
        "Deep Reconnaissance", _deep_recon,
        phase=ScanPhase.RECON, depends_on=[web_id],
        timeout=600,
    )

    # ═══ Phase: SHODAN PASSIVE RECON ═══
    async def _shodan_recon(**kw):
        try:
            from heaven.recon.shodan_recon import ShodanRecon
            recon = ShodanRecon()
            results = {"hosts": [], "domains": []}
            for ip in targets.get("ips", []):
                info = await recon.lookup_host(ip)
                if info:
                    results["hosts"].append(info)
            for url in targets.get("urls", []):
                from urllib.parse import urlparse
                domain = urlparse(url).hostname or ""
                if domain:
                    info = await recon.lookup_domain(domain)
                    if info:
                        results["domains"].append(info)
            return results
        except ImportError:
            return {}

    orch.add_task(
        "Shodan Passive Intelligence", _shodan_recon,
        phase=ScanPhase.RECON,
        timeout=120,
    )

    # ═══ Phase: ADAPTIVE PROFILING (WAF fingerprint, tech stack) ═══
    async def _adaptive_profile(**kw):
        try:
            from heaven.recon.adaptive_intel import AdaptiveIntelligence
            import aiohttp
            intel = AdaptiveIntelligence()
            profiles = []
            async with aiohttp.ClientSession() as session:
                for url in targets.get("urls", []):
                    p = await intel.profile_target(session, url)
                    profiles.append({
                        "url": url, "waf": p.waf.name if p.waf else None,
                        "tech": p.technologies, "server": p.server,
                        "recommended_attacks": p.recommended_attacks,
                    })
            return {"profiles": profiles}
        except ImportError:
            return {}

    adapt_id = orch.add_task(
        "Adaptive Target Profiling", _adaptive_profile,
        phase=ScanPhase.RECON, depends_on=[web_id],
    )

    # ═══ Phase: VULN_SCAN ═══
    async def _lookup_vulnerabilities(**kw):
        try:
            from heaven.vulnscan.nvd_client import lookup_vulnerabilities
            # Collect discovered services and technologies
            cpes = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                # From network scan
                for host in data.get("hosts", []):
                    for p in host.get("open_ports", []):
                        if p.get("cpe"):
                            cpes.append(p["cpe"])
                # From adaptive profile
                for p in data.get("profiles", []):
                    for tech in p.get("tech", []):
                        cpes.append(f"cpe:2.3:a:{tech.lower()}:{tech.lower()}:*:*:*:*:*:*:*")
            return await lookup_vulnerabilities(scan_id=orch.scan_id, cpes=list(set(cpes)))
        except ImportError:
            return {}

    vuln_id = orch.add_task(
        "Vulnerability Mapping", _lookup_vulnerabilities,
        phase=ScanPhase.VULN_SCAN,
        depends_on=[net_id, web_id, cloud_id, hp_id],
    )

    # ═══ Phase: ZERO-DAY DISCOVERY ═══
    async def _zeroday_scan(**kw):
        try:
            from heaven.vulnscan.zeroday_engine import WebZeroDayScanner
            import aiohttp
            scanner = WebZeroDayScanner()
            candidates = []
            async with aiohttp.ClientSession() as session:
                for url in targets.get("urls", []):
                    found = await scanner.scan_endpoint(session, url, ["id", "q", "page", "file", "url"])
                    candidates.extend([{
                        "target": c.target, "category": c.category,
                        "severity": c.severity, "description": c.description,
                        "confidence": c.confidence, "cwe": c.cwe_id,
                    } for c in found])
            return {"candidates": candidates, "total": len(candidates)}
        except ImportError:
            return {}

    zday_id = orch.add_task(
        "Zero-Day Discovery", _zeroday_scan,
        phase=ScanPhase.VULN_SCAN, depends_on=[adapt_id],
        timeout=600,
    )

    # ═══ Phase: ADVANCED ATTACKS ═══
    async def _advanced_attacks(**kw):
        try:
            from heaven.vulnscan.advanced_attacks import run_advanced_tests
            import aiohttp
            findings = []
            # Build scan_data from completed recon results so JWT + race tests fire
            scan_data: dict = {"jwt_tokens": [], "critical_endpoints": []}
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                scan_data["jwt_tokens"].extend(data.get("jwt_tokens", []))
                scan_data["critical_endpoints"].extend(data.get("endpoints", []))
                for ep in data.get("forms", []):
                    scan_data["critical_endpoints"].append(ep.get("action", ""))
            async with aiohttp.ClientSession() as session:
                for url in targets.get("urls", []):
                    found = await run_advanced_tests(session, url, scan_data=scan_data)
                    findings.extend([{
                        "target": f.target, "vuln_type": f.vuln_type,
                        "severity": f.severity, "title": f.title,
                        "confidence": f.confidence,
                    } for f in found])
            return {"findings": findings, "total": len(findings)}
        except ImportError:
            return {}

    adv_id = orch.add_task(
        "Advanced Exploitation Tests", _advanced_attacks,
        phase=ScanPhase.VULN_SCAN, depends_on=[adapt_id, deep_id],
        timeout=600,
    )

    # ═══ Phase: NUCLEI SCAN ═══
    async def _nuclei_scan(**kw):
        try:
            from heaven.vulnscan.nuclei_scanner import scan_nuclei
            urls = targets.get("urls", [])
            stealth = targets.get("stealth_level", "normal")
            # Also extract URLs from crawler if available
            for tid, res in orch.results.items():
                if res.state == TaskState.COMPLETED and res.data:
                    if isinstance(res.data, dict) and "endpoints" in res.data:
                        for ep in res.data["endpoints"]:
                            if ep.get("url") and ep["url"] not in urls:
                                urls.append(ep["url"])
            return await scan_nuclei(urls, stealth_level=stealth)
        except ImportError:
            return {}

    nuclei_id = orch.add_task(
        "Nuclei Scanner", _nuclei_scan,
        phase=ScanPhase.VULN_SCAN, depends_on=[adv_id],
        timeout=1800,
    )

    # ═══ Phase: VALIDATION ═══
    async def _validate_findings(**kw):
        try:
            from heaven.vulnscan.safe_validator import validate_findings
            # Collect findings
            findings = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                findings.extend(data.get("vulnerabilities", []))
                findings.extend(data.get("candidates", []))
                findings.extend(data.get("findings", []))
            return await validate_findings(scan_id=orch.scan_id, findings=findings)
        except ImportError:
            return {}

    val_id = orch.add_task(
        "PoC Validation", _validate_findings,
        phase=ScanPhase.VALIDATION,
        depends_on=[vuln_id, zday_id, adv_id, nuclei_id],
    )

    # ═══ Phase: SQLMAP (confirmed SQLi targets only) ═══
    async def _sqlmap_scan(**kw):
        try:
            from heaven.vulnscan.sqlmap_runner import run_sqlmap_on_findings
            sqli_targets = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                for f in (data.get("findings", []) + data.get("candidates", [])
                          + data.get("validated_findings", [])):
                    vt = (f.get("vuln_type") or f.get("type") or "").lower()
                    sev = (f.get("severity") or "").lower()
                    if "sqli" in vt and sev in ("critical", "high"):
                        sqli_targets.append(f)
            if not sqli_targets:
                return {"skipped": True, "reason": "no confirmed SQLi candidates"}
            return await run_sqlmap_on_findings(sqli_targets)
        except ImportError:
            return {}

    orch.add_task(
        "SQLMap Exploitation", _sqlmap_scan,
        phase=ScanPhase.VALIDATION, depends_on=[val_id],
        timeout=600,
    )

    # ═══ Phase: ATTACK CHAIN ANALYSIS ═══
    async def _attack_chains(**kw):
        try:
            from heaven.vulnscan.attack_chain import AttackChainEngine
            engine = AttackChainEngine()
            # Collect findings from completed scan tasks
            collected_vulns = []
            collected_secrets = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                collected_vulns.extend(data.get("vulnerabilities", []))
                collected_vulns.extend(data.get("findings", []))
                collected_vulns.extend(data.get("candidates", []))
                collected_secrets.extend(data.get("secrets", []))
                collected_secrets.extend(data.get("secrets_list", []))
            engine.ingest_findings({"vulnerabilities": collected_vulns, "secrets": collected_secrets})
            engine.discover_chains()
            return engine.summary()
        except ImportError:
            return {}

    chain_id = orch.add_task(
        "Attack Chain Discovery", _attack_chains,
        phase=ScanPhase.VALIDATION, depends_on=[val_id],
    )

    # ═══ Phase: AD RECON ═══
    async def _ad_scan(**kw):
        try:
            from heaven.recon.ad_scanner import scan_active_directory
            ad_cfg = (config or get_config()).ad
            return await scan_active_directory(
                domain=ad_cfg.domain or targets.get("ad_domain", ""),
                dc_host=ad_cfg.dc_host or targets.get("ad_dc", ""),
                username=ad_cfg.username, password=ad_cfg.password,
            )
        except ImportError:
            return {}

    orch.add_task(
        "Active Directory Scan", _ad_scan,
        phase=ScanPhase.AD_RECON, depends_on=[net_id],
        timeout=600,
    )

    # ═══ Phase: IOT SCAN ═══
    async def _iot_scan(**kw):
        try:
            from heaven.recon.iot_scanner import scan_iot_targets
            return await scan_iot_targets(targets=targets.get("iot_targets", targets.get("ips", [])))
        except ImportError:
            return {}

    orch.add_task(
        "IoT/SCADA/OT Scan", _iot_scan,
        phase=ScanPhase.IOT_SCAN, depends_on=[net_id],
        timeout=600,
    )

    # ═══ Phase: API SCAN ═══
    async def _api_scan(**kw):
        try:
            from heaven.vulnscan.api_scanner import scan_api_targets
            return await scan_api_targets(urls=targets.get("urls", []))
        except ImportError:
            return {}

    orch.add_task(
        "API Security Scan", _api_scan,
        phase=ScanPhase.API_SCAN, depends_on=[web_id, adapt_id],
        timeout=600,
    )

    # ═══ Phase: CONTAINER SCAN ═══
    async def _container_scan(**kw):
        try:
            from heaven.recon.container_scanner import scan_containers
            return await scan_containers(hosts=targets.get("container_hosts", targets.get("ips", [])))
        except ImportError:
            return {}

    orch.add_task(
        "Container/K8s Scan", _container_scan,
        phase=ScanPhase.CONTAINER_SCAN, depends_on=[net_id],
        timeout=600,
    )

    # ═══ Phase: EMAIL SCAN ═══
    async def _email_scan(**kw):
        try:
            from heaven.recon.email_scanner import scan_email_domains
            # Extract domains from URLs
            from urllib.parse import urlparse
            domains = set()
            for url in targets.get("urls", []):
                parsed = urlparse(url)
                if parsed.hostname:
                    parts = parsed.hostname.split(".")
                    if len(parts) >= 2:
                        domains.add(".".join(parts[-2:]))
            return await scan_email_domains(domains=list(domains))
        except ImportError:
            return {}

    orch.add_task(
        "Email Security Scan", _email_scan,
        phase=ScanPhase.RECON, depends_on=[web_id],
    )

    # ═══ Phase: ML SCORING ═══
    async def _score_vulnerabilities(**kw):
        try:
            from heaven.ml.risk_model import score_vulnerabilities
            findings = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                findings.extend(data.get("vulnerabilities", []))
                findings.extend(data.get("candidates", []))
                findings.extend(data.get("findings", []))
                findings.extend(data.get("validated_findings", []))
            return await score_vulnerabilities(scan_id=orch.scan_id, findings=findings)
        except ImportError:
            return {}

    ml_id = orch.add_task(
        "ML Risk Scoring", _score_vulnerabilities,
        phase=ScanPhase.ML_SCORING,
        depends_on=[val_id, chain_id],
        concurrency_group="ml",
    )

    # ═══ Phase: MITRE ATT&CK MAPPING + KILL CHAIN ═══
    async def _mitre_mapping(**kw):
        try:
            from heaven.mitre.attack_mapper import MITREAttackMapper
            from heaven.mitre.threat_intel import ThreatIntelEngine
            from heaven.mitre.kill_chain import KillChainAnalyzer
            mapper = MITREAttackMapper()
            intel = ThreatIntelEngine()
            kill_chain = KillChainAnalyzer()
            # Collect findings from all completed scan tasks
            findings = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                findings.extend(data.get("vulnerabilities", []))
                findings.extend(data.get("findings", []))
                findings.extend(data.get("candidates", []))
            mapper.map_all_findings(findings)
            intel.enrich_all_findings(findings)
            kill_chain.ingest(findings)
            return {
                "mitre": mapper.summary(),
                "threat_intel": intel.get_threat_landscape(),
                "kill_chain": kill_chain.report(),
                "kill_chain_path": kill_chain.attack_path_summary(),
            }
        except ImportError as e:
            logger.warning(f"MITRE mapping skipped: {e}")
            return {}

    mitre_id = orch.add_task(
        "MITRE ATT&CK Mapping", _mitre_mapping,
        phase=ScanPhase.MITRE_MAPPING, depends_on=[ml_id],
    )

    # ═══ Phase: PATCH GENERATION ═══
    async def _generate_patches(**kw):
        try:
            from heaven.vulnscan.patch_generator import PatchGenerator
            gen = PatchGenerator()
            # Collect vulnerability findings from completed tasks
            vulns = []
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                vulns.extend(data.get("vulnerabilities", []))
                vulns.extend(data.get("findings", []))
                vulns.extend(data.get("candidates", []))
            patches = gen.generate_all_patches(vulns)
            return {"patches": len(patches), "details": [{
                "vuln_id": p.vuln_id, "title": p.title, "severity": p.severity,
                "fix_type": p.fix_type, "language": p.language,
            } for p in patches]}
        except ImportError:
            return {}

    patch_id = orch.add_task(
        "Patch Generation", _generate_patches,
        phase=ScanPhase.REPORTING, depends_on=[ml_id],
    )

    # ═══ Phase: REPORTING ═══
    async def _generate_report(**kw):
        try:
            from heaven.devsecops.aggregator import generate_report
            # Collect EVERYTHING for the report
            scan_data = {"scan_id": orch.scan_id, "vulnerabilities": [], "assets": [], "secrets_list": []}
            for tid, res in orch.results.items():
                if res.state != TaskState.COMPLETED or not res.data:
                    continue
                data = res.data if isinstance(res.data, dict) else {}
                scan_data["vulnerabilities"].extend(data.get("vulnerabilities", []))
                scan_data["vulnerabilities"].extend(data.get("validated_findings", []))
                scan_data["assets"].extend(data.get("hosts", []))
                scan_data["assets"].extend(data.get("endpoints", []))
                scan_data["secrets_list"].extend(data.get("secrets", []))
                scan_data["secrets_list"].extend(data.get("js_secrets", []))
            return await generate_report(scan_id=orch.scan_id, scan_data=scan_data)
        except ImportError:
            return {}

    orch.add_task(
        "Report Generation", _generate_report,
        phase=ScanPhase.REPORTING,
        depends_on=[ml_id, git_id, patch_id, mitre_id],
    )

    return orch
