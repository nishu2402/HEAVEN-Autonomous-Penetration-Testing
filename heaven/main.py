"""
HEAVEN — CLI Entry Point
Command-line interface for running scans, managing config, and launching the API server.
Works with or without optional dependencies (click, rich, uvicorn, fastapi).
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import click
    HAS_CLICK = True
except ImportError:
    HAS_CLICK = False

from heaven import __banner__, __version__
from heaven.config import ScanMode, get_config, reload_config
from heaven.utils.logger import get_logger, print_banner, setup_logging, HAS_RICH

logger = get_logger("main")

# Target validation regex — single-escaped (these are normal Python strings, not raw)
_IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
_HOST_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")
_URL_REGEX = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)


def _print(msg: str) -> None:
    """Print with Rich console if available, else plain print."""
    if HAS_RICH:
        from heaven.utils.logger import console
        if console:
            console.print(msg)
            return
    plain = re.sub(r"\[/?[^\]]+\]", "", msg)
    print(plain)


def _validate_target_string(t: str) -> tuple[bool, str]:
    """Return (is_valid, kind) where kind is 'ip' | 'host' | 'invalid'."""
    if _IP_REGEX.match(t):
        return True, "ip"
    if _HOST_REGEX.match(t) and "." in t:
        return True, "host"
    return False, "invalid"


def _verify_authorization(targets: dict, ack_flag: bool) -> bool:
    """
    Scope/authorization gate. Tool refuses to scan unless operator explicitly
    acknowledges they have written authorization for every target.

    Override mechanisms (priority order):
      1. --i-have-authorization flag (explicit per-run ack)
      2. HEAVEN_AUTHORIZED_SCOPE env var (newline/comma-separated allowed targets)
      3. Interactive confirm (TTY only)
    """
    import os

    all_targets = (
        list(targets.get("ips", []))
        + list(targets.get("urls", []))
        + list(targets.get("repositories", []))
        + list(targets.get("cloud_providers", []))
    )
    if targets.get("ad_domain"):
        all_targets.append(targets["ad_domain"])

    if not all_targets:
        return True  # Nothing to scan, nothing to authorize

    if ack_flag:
        logger.warning("Authorization acknowledged via --i-have-authorization flag")
        return True

    scope_env = os.environ.get("HEAVEN_AUTHORIZED_SCOPE", "").strip()
    if scope_env:
        allowed = {s.strip() for s in re.split(r"[,\n]", scope_env) if s.strip()}
        unauthorized = [t for t in all_targets if t not in allowed]
        if not unauthorized:
            logger.info(f"All {len(all_targets)} targets present in HEAVEN_AUTHORIZED_SCOPE")
            return True
        _print(f"[bold red]Authorization failure:[/bold red] {len(unauthorized)} target(s) not in HEAVEN_AUTHORIZED_SCOPE")
        for t in unauthorized:
            _print(f"  - {t}")
        return False

    if sys.stdin.isatty():
        _print("\n[bold yellow]⚠ AUTHORIZATION REQUIRED[/bold yellow]")
        _print("HEAVEN performs active vulnerability testing. Scanning systems without")
        _print("written authorization is illegal in most jurisdictions (CFAA in the US,")
        _print("Computer Misuse Act in the UK, and equivalent laws elsewhere).")
        _print("\nTargets you are about to scan:")
        for t in all_targets:
            _print(f"  - {t}")
        try:
            ans = input("\nDo you have written authorization to test ALL listed targets? [y/N]: ").strip().lower()
        except EOFError:
            return False
        if ans in ("y", "yes"):
            logger.warning(f"Authorization acknowledged interactively for {len(all_targets)} targets")
            return True
        _print("[red]Authorization not confirmed. Aborting.[/red]")
        return False

    _print("[bold red]Authorization required.[/bold red]")
    _print("Use --i-have-authorization, set HEAVEN_AUTHORIZED_SCOPE env var, or run interactively.")
    return False


def check_module_health() -> dict:
    checks = {
        "network_scanner": "heaven.recon.network_scanner",
        "web_crawler": "heaven.recon.web_crawler",
        "risk_model": "heaven.ml.risk_model",
        "nuclei_scanner": "heaven.vulnscan.nuclei_scanner",
        "attack_mapper": "heaven.mitre.attack_mapper",
        "evasion_engine": "heaven.recon.evasion_engine",
        "ai_brain": "heaven.ml.ai_brain",
    }
    results = {}
    for name, module in checks.items():
        try:
            __import__(module)
            results[name] = "OK"
        except Exception as e:
            results[name] = f"DEGRADED: {e}"
    return results


if HAS_CLICK:

    @click.group()
    @click.version_option(version=__version__, prog_name="HEAVEN")
    @click.option("--debug", is_flag=True, help="Enable debug logging")
    @click.option("--config-file", type=click.Path(), help="Path to .env config file")
    def cli(debug: bool, config_file: Optional[str]) -> None:
        """HEAVEN — Automated Vulnerability Scanner & Risk Triage Platform"""
        if config_file:
            try:
                from dotenv import load_dotenv
                load_dotenv(config_file)
            except ImportError:
                logger.warning("python-dotenv not installed — .env file ignored")
            reload_config()

        cfg = get_config()
        if debug:
            cfg.debug = True
            cfg.log_level = "DEBUG"

        setup_logging(level=cfg.log_level)

        from heaven.utils.platform_detect import configure_event_loop
        configure_event_loop()

    @cli.command()
    @click.option("--target", "-t", multiple=True, help="Target IPs, hostnames, or CIDRs")
    @click.option("--url", "-u", multiple=True, help="Target URLs for web scanning")
    @click.option("--repo", "-r", multiple=True, help="Git repositories to scan")
    @click.option("--cloud", "-c", multiple=True, help="Cloud providers (aws, gcp, azure)")
    @click.option("--mode", "-m", type=click.Choice([m.value for m in ScanMode]), default="full")
    @click.option("--ports", "-p", default="1-1024", help="Port range for network scan")
    @click.option("--stealth", "-s", type=click.Choice(["aggressive", "normal", "stealth", "paranoid"]), default="normal")
    @click.option("--output", "-o", type=click.Choice(["json", "sarif", "html", "pdf", "markdown"]), default="json")
    @click.option("--output-file", type=click.Path(), help="Output file path")
    @click.option("--ad-domain", default="", help="Active Directory domain (e.g. corp.local)")
    @click.option("--ad-dc", default="", help="Active Directory Domain Controller IP/hostname")
    @click.option("--iot", is_flag=True, help="Enable IoT/SCADA/OT scanning")
    @click.option("--api-scan", is_flag=True, help="Enable advanced API security scanning")
    @click.option("--container", is_flag=True, help="Enable Container/Kubernetes scanning")
    @click.option("--mitre-map", is_flag=True, help="Enable MITRE ATT&CK mapping")
    @click.option("--engagement", help="Engagement name — persists findings into engagement DB")
    @click.option("--use-scope/--no-use-scope", default=True,
                  help="If --engagement set, restrict scan to in-scope targets only")
    @click.option("--i-have-authorization", is_flag=True,
                  help="Acknowledge written authorization to test all targets (required)")
    @click.option("--skip-dep-check", is_flag=True,
                  help="Skip nmap/nuclei system-dep check (use only for unit tests)")
    def scan(
        target: tuple[str, ...], url: tuple[str, ...],
        repo: tuple[str, ...], cloud: tuple[str, ...],
        mode: str, ports: str, stealth: str,
        output: str, output_file: Optional[str],
        ad_domain: str, ad_dc: str,
        iot: bool, api_scan: bool, container: bool, mitre_map: bool,
        engagement: Optional[str], use_scope: bool,
        i_have_authorization: bool, skip_dep_check: bool,
    ) -> None:
        """Launch a vulnerability scan against specified targets."""
        print_banner()

        targets = {
            "ips": list(target), "urls": list(url),
            "repositories": list(repo), "cloud_providers": list(cloud),
            "ports": ports, "stealth_level": stealth,
            "ad_domain": ad_domain, "ad_dc": ad_dc,
            "enable_iot": iot, "enable_api_scan": api_scan,
            "enable_container": container, "enable_mitre": mitre_map,
        }

        # Engagement scope check — second authorization gate
        engagement_store = None
        if engagement:
            from heaven.engagement import EngagementStore
            db_path = _engagement_db_path(engagement)
            if not db_path.exists():
                _print(f"[red]Engagement DB not found:[/red] {db_path}")
                _print(f"Run: [cyan]heaven engage init {engagement}[/cyan]")
                sys.exit(2)
            engagement_store = EngagementStore(db_path)

            if use_scope:
                # Filter targets to those explicitly in scope
                kept_ips, dropped_ips = [], []
                for t in targets["ips"]:
                    if engagement_store.is_in_scope(t):
                        kept_ips.append(t)
                    else:
                        dropped_ips.append(t)
                kept_urls, dropped_urls = [], []
                for u in targets["urls"]:
                    if engagement_store.is_in_scope(u):
                        kept_urls.append(u)
                    else:
                        dropped_urls.append(u)
                if dropped_ips or dropped_urls:
                    _print("[yellow]Targets dropped (not in engagement scope):[/yellow]")
                    for x in dropped_ips + dropped_urls:
                        _print(f"  - {x}")
                    _print("[dim]Add them with: [cyan]heaven scope add <target>[/cyan][/dim]")
                targets["ips"] = kept_ips
                targets["urls"] = kept_urls

        has_targets = any(targets[k] for k in ("ips", "urls", "repositories", "cloud_providers"))
        if not has_targets and mode != "ci" and not ad_domain:
            if sys.stdin.isatty() and HAS_RICH:
                from rich.prompt import Prompt
                _print("\n[bold cyan]⚡ HEAVEN Interactive Wizard[/bold cyan]")
                _print("[italic]No targets specified. Let's set up your scan.[/italic]\n")

                target_input = Prompt.ask("[bold]Enter target IP/host or URL[/bold] (e.g., 127.0.0.1 or https://example.com)")
                if target_input.startswith("http"):
                    targets["urls"].append(target_input)
                else:
                    targets["ips"].append(target_input)

                mode = Prompt.ask(
                    "[bold]Select Scan Mode[/bold]",
                    choices=["full", "network", "web", "cloud", "devsecops"],
                    default="full",
                )
                stealth = Prompt.ask(
                    "[bold]Select Stealth Level[/bold]",
                    choices=["aggressive", "normal", "stealth", "paranoid"],
                    default="normal",
                )
                targets["stealth_level"] = stealth
                _print("")
            else:
                _print("[red]Error:[/red] No targets specified or all dropped by scope filter.")
                sys.exit(1)

        # Target validation — real regex this time
        invalid = []
        for t in targets["ips"]:
            ok, _kind = _validate_target_string(t)
            if not ok:
                invalid.append(t)
        for u in targets["urls"]:
            if not _URL_REGEX.match(u):
                invalid.append(u)
        if invalid:
            _print("[bold red]Invalid target(s) (refusing to proceed):[/bold red]")
            for x in invalid:
                _print(f"  - {x}")
            _print("Use IPv4/CIDR (e.g. 10.0.0.0/24) or hostname for --target, full URL with scheme for --url.")
            sys.exit(2)

        # Authorization gate — REFUSE to scan without explicit ack
        if not _verify_authorization(targets, i_have_authorization):
            sys.exit(3)

        # Dependency validation — non-fatal warning
        if not skip_dep_check:
            import shutil
            missing_deps = [d for d in ("nmap", "nuclei") if not shutil.which(d)]
            if missing_deps:
                _print("\n[bold yellow]Warning:[/bold yellow] missing system tools: " + ", ".join(missing_deps))
                _print("Some scan modules will degrade gracefully. Install for full coverage:")
                _print("  Linux: apt install nmap && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
                _print("  macOS: brew install nmap nuclei")

        _print(f"[cyan]Scan mode:[/cyan] {mode.upper()}")
        _print(f"[cyan]Stealth:[/cyan] {stealth.upper()}")
        _print(f"[cyan]Targets:[/cyan] {sum(len(v) for v in targets.values() if isinstance(v, list))} specified")
        _print(f"[cyan]Port range:[/cyan] {ports}")
        if ad_domain:
            _print(f"[cyan]AD Domain:[/cyan] {ad_domain} (DC: {ad_dc or 'auto-discover'})")
        if iot:
            _print("[cyan]IoT/SCADA:[/cyan] Enabled")
        if api_scan:
            _print("[cyan]API Scan:[/cyan] Enabled")
        if container:
            _print("[cyan]Container:[/cyan] Enabled")
        if mitre_map:
            _print("[cyan]MITRE ATT&CK:[/cyan] Enabled")

        from heaven.orchestrator import build_full_scan
        config = get_config()
        config.scan_mode = ScanMode(mode)

        # Pass engagement store as checkpoint store so scan is resumable.
        orch = build_full_scan(targets, config,
                               checkpoint_store=engagement_store)

        # Pre-register the scan in the engagement DB so a crash-then-resume
        # can find the config to restart from.
        if engagement_store:
            engagement_store.record_scan_start(
                orch.scan_id, name=f"{mode} scan", mode=mode,
                config={"targets": targets},
            )

        try:
            from rich.live import Live
            from rich.layout import Layout
            from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
            from rich.table import Table
            from rich.text import Text
            import time as _time

            findings_log = []
            log_lines = []

            progress_bar = Progress(
                TextColumn("[cyan]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[green]{task.completed}/{task.total}"),
                TimeElapsedColumn(),
            )
            scan_task = progress_bar.add_task("Scanning...", total=100)

            def build_layout():
                table = Table(show_header=True, header_style="bold cyan",
                              box=None, padding=(0, 1))
                table.add_column("SEV", width=8)
                table.add_column("TYPE", width=20)
                table.add_column("TARGET", width=35)
                table.add_column("CONF", width=6)
                sev_colors = {"critical": "bold red", "high": "red",
                              "medium": "yellow", "low": "cyan", "info": "dim"}
                for f in findings_log[-15:]:
                    sev = f.get("severity", "info").lower()
                    table.add_row(
                        f"[{sev_colors.get(sev,'dim')}]{sev[:4].upper()}[/]",
                        str(f.get("vuln_type", ""))[:20],
                        str(f.get("target", ""))[:35],
                        f"{f.get('confidence', 0):.2f}",
                    )
                log_text = Text("\n".join(log_lines[-8:]), style="dim")
                layout = Layout()
                layout.split_column(
                    Layout(progress_bar, name="progress", size=3),
                    Layout(table, name="findings"),
                    Layout(log_text, name="log", size=10),
                )
                return layout

            def progress_callback(progress):
                pct = progress.progress_pct
                progress_bar.update(scan_task, completed=pct,
                                    description=f"[{progress.phase.value.upper()}]")
                log_lines.append(f"[{_time.strftime('%H:%M:%S')}] {progress.current_task}")

            with Live(build_layout(), refresh_per_second=4, screen=False) as live:
                orch.on_progress(lambda p: (progress_callback(p), live.update(build_layout())))
                try:
                    summary = asyncio.run(orch.run())
                except KeyboardInterrupt:
                    _print("[yellow]Scan aborted.[/yellow]")
                    sys.exit(0)

            # Post-scan findings table
            all_findings = summary.get("vulnerabilities", [])
            if all_findings:
                ft = Table(title="Findings", show_header=True, header_style="bold")
                ft.add_column("Severity", style="bold")
                ft.add_column("Type")
                ft.add_column("Target")
                ft.add_column("CVSS")
                ft.add_column("Priority")
                sev_style = {"critical": "bold red", "high": "red",
                             "medium": "yellow", "low": "cyan"}
                for f in sorted(all_findings,
                                key=lambda x: x.get("priority_score", 0), reverse=True):
                    sev = f.get("severity", "info").lower()
                    ft.add_row(
                        f"[{sev_style.get(sev,'dim')}]{sev.upper()}[/]",
                        str(f.get("vuln_type", ""))[:25],
                        str(f.get("target", ""))[:40],
                        str(round(f.get("predicted_cvss_score", 0), 1)),
                        str(round(f.get("priority_score", 0), 1)),
                    )
                if HAS_RICH:
                    from heaven.utils.logger import console
                    console.print(ft)

        except ImportError:
            # Fallback when Rich is not available
            def progress_callback(progress):
                _print(
                    f"  [{progress.phase.value}] {progress.progress_pct:.0f}% "
                    f"({progress.completed_tasks}/{progress.total_tasks}) — {progress.current_task}"
                )

            orch.on_progress(progress_callback)
            try:
                try:
                    summary = asyncio.run(orch.run())
                except RuntimeError:
                    loop = asyncio.get_event_loop()
                    summary = loop.run_until_complete(orch.run())
            except KeyboardInterrupt:
                _print("\n[bold yellow]⚠ Scan aborted by user (KeyboardInterrupt).[/bold yellow]")
                _print("Cleaning up active processes and exiting safely...")
                sys.exit(0)
            except Exception as e:
                _print(f"\n[bold red]Critical engine failure:[/bold red] {e}")
                if get_config().debug:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)

        _print(f"\n[green]Scan completed in {summary['elapsed_seconds']}s[/green]")
        _print(f"  Tasks: {summary['completed']}/{summary['total_tasks']} (failed: {summary['failed']})")

        # Persist into engagement DB if specified
        if engagement_store:
            scan_id = summary.get("scan_id", orch.scan_id)
            findings_in_summary = (
                summary.get("vulnerabilities", [])
                + summary.get("findings", [])
            )
            persisted = 0
            for f in findings_in_summary:
                try:
                    engagement_store.upsert_finding(scan_id, f)
                    persisted += 1
                except Exception as e:
                    logger.debug(f"Could not persist finding: {e}")
            engagement_store.record_scan_complete(scan_id, summary)
            _print(f"  [cyan]Persisted to engagement:[/cyan] {persisted} findings into "
                   f"{_engagement_db_path(engagement)}")
            _print(f"  [dim]List:   [/dim][cyan]heaven findings --engagement {engagement}[/cyan]")
            _print(f"  [dim]Export: [/dim][cyan]heaven export --engagement {engagement} -o report.md --format markdown[/cyan]")

        if output_file:
            try:
                if output == "pdf":
                    from heaven.devsecops.pdf_report import PDFReportGenerator
                    if PDFReportGenerator().generate(summary, output_file):
                        _print(f"  PDF report written to: {output_file}")
                    else:
                        _print("  [red]Failed to generate PDF report.[/red]")
                elif output == "sarif":
                    from heaven.devsecops.aggregator import export_sarif
                    sarif_data = export_sarif(summary)
                    Path(output_file).write_text(json.dumps(sarif_data, indent=2))
                    _print(f"  SARIF results written to: {output_file}")
                elif output == "markdown":
                    from heaven.devsecops.evidence import export_findings_markdown
                    findings_in_summary = (
                        summary.get("vulnerabilities", [])
                        + summary.get("findings", [])
                    )
                    Path(output_file).write_text(export_findings_markdown(findings_in_summary))
                    _print(f"  Markdown report written to: {output_file}")
                else:
                    Path(output_file).write_text(json.dumps(summary, indent=2, default=str))
                    _print(f"  Results written to: {output_file}")
            except Exception as e:
                _print(f"  [red]Failed to write output:[/red] {e}")

        if mode == "ci":
            criticals = summary.get("critical", 0)
            highs = summary.get("high", 0)
            if criticals > 0 or highs > 0:
                _print(f"\n[bold red]CI mode: failing build due to {criticals} critical and {highs} high vulnerabilities.[/bold red]")
                sys.exit(1)

    @cli.command()
    @click.argument("interval_minutes", type=int)
    @click.option("--target", "-t", multiple=True, required=True, help="Target IPs or URLs")
    @click.option("--mode", "-m", type=click.Choice([m.value for m in ScanMode]), default="full")
    @click.option("--i-have-authorization", is_flag=True, required=True,
                  help="Required for scheduled scans — confirms all targets are authorized")
    def schedule(interval_minutes: int, target: tuple[str, ...], mode: str,
                 i_have_authorization: bool) -> None:
        """Continuously monitor targets at a specified interval (minutes)."""
        print_banner()

        if not i_have_authorization:
            _print("[red]Scheduled scans require --i-have-authorization for every target.[/red]")
            sys.exit(3)

        if interval_minutes < 1:
            _print("[red]Interval must be >= 1 minute.[/red]")
            sys.exit(2)

        _print("[cyan]Initializing continuous monitoring[/cyan]")
        _print(f"Targets: {target}")
        _print(f"Interval: every {interval_minutes} minutes")

        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            import subprocess
            from datetime import datetime

            def run_scan_job():
                _print(f"\n[green]Scheduled scan triggered: {datetime.now().isoformat()}[/green]")
                cmd = ["heaven", "scan", "-m", mode, "--i-have-authorization"]
                for t in target:
                    if t.startswith("http"):
                        cmd.extend(["-u", t])
                    else:
                        cmd.extend(["-t", t])
                subprocess.run(cmd, check=False)

            run_scan_job()  # Run once immediately

            scheduler = AsyncIOScheduler()
            scheduler.add_job(run_scan_job, "interval", minutes=interval_minutes)
            scheduler.start()

            _print("[green]Scheduler started. Press Ctrl+C to exit.[/green]")
            loop = asyncio.get_event_loop()
            try:
                loop.run_forever()
            except (KeyboardInterrupt, SystemExit):
                pass
        except ImportError:
            _print("[red]Error: apscheduler required. Install with: pip install apscheduler[/red]")

    @cli.command()
    def info() -> None:
        """Display platform information and available tools."""
        print_banner()
        from heaven.utils.platform_detect import detect_platform, print_platform_info
        platform_info = detect_platform()
        print_platform_info(platform_info)

    @cli.command()
    @click.option("--host", default="127.0.0.1",
                  help="API server host (default: 127.0.0.1, use 0.0.0.0 only behind a TLS reverse proxy)")
    @click.option("--port", default=8443, type=int, help="API server port")
    def serve(host: str, port: int) -> None:
        """Start the HEAVEN API server and Command Centre."""
        print_banner()
        _print(f"[cyan]Starting HEAVEN API server on {host}:{port}[/cyan]")

        if host == "0.0.0.0":
            _print("[yellow]⚠  Binding to 0.0.0.0 — make sure you are behind a reverse proxy with TLS.[/yellow]")

        try:
            import uvicorn
            from heaven.api.server import create_app
            app = create_app()
            health = check_module_health()
            for mod, status in health.items():
                _print(f"  {'[green]OK[/green]' if status == 'OK' else '[yellow]' + status + '[/yellow]'} {mod}")
            uvicorn.run(app, host=host, port=port, log_level="info")
        except ImportError:
            _print("[red]Error: uvicorn and fastapi required. Install with: pip install uvicorn fastapi[/red]")
            sys.exit(1)

    @cli.command()
    def init_db() -> None:
        """Initialise the PostgreSQL database schema."""
        print_banner()
        _print("[cyan]Initialising database...[/cyan]")

        async def _init():
            from heaven.db.connection import init_db, close_all
            await init_db()
            await close_all()

        try:
            asyncio.run(_init())
            _print("[green]Database schema initialised successfully.[/green]")
        except Exception as e:
            _print(f"[red]DB init failed:[/red] {e}")
            sys.exit(1)

    @cli.command()
    @click.option("--output", "-o", type=click.Path(), help="Output report file path")
    def self_audit(output: Optional[str]) -> None:
        """Run security self-audit on HEAVEN installation."""
        print_banner()
        _print("[cyan]Running HEAVEN self-security audit...[/cyan]")

        from heaven.security.self_audit import SelfAuditor
        auditor = SelfAuditor()
        report = auditor.run_full_audit()

        score = report["score"]
        grade = report["grade"]
        _print(f"\n[bold]Security score: {score}/100 (grade: {grade})[/bold]")

        sev = report["severity_breakdown"]
        _print(f"  Critical: {sev.get('critical', 0)}  High: {sev.get('high', 0)}  "
               f"Medium: {sev.get('medium', 0)}  Low: {sev.get('low', 0)}")

        for rec in report.get("recommendations", []):
            _print(f"  → {rec}")

        if output:
            Path(output).write_text(json.dumps(report, indent=2))
            _print(f"\n  Full report written to: {output}")

    @cli.command()
    @click.option("--output", "-o", type=click.Path(), default="data/mitre_navigator.json",
                  help="Navigator layer output path")
    def mitre_report(output: str) -> None:
        """Generate MITRE ATT&CK Navigator heatmap layer from scan results."""
        print_banner()
        _print("[cyan]Generating MITRE ATT&CK report...[/cyan]")

        from heaven.mitre.attack_mapper import MITREAttackMapper
        mapper = MITREAttackMapper()
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        mapper.export_navigator_layer(Path(output))
        _print(f"[green]Navigator layer exported to: {output}[/green]")
        summary = mapper.get_tactic_coverage()
        _print(f"  Tactic coverage: {summary['coverage_pct']}%")

    # ════════════════════════════════════════════════════════════════════
    # PENTESTER WORKFLOW COMMANDS
    # ════════════════════════════════════════════════════════════════════

    def _engagement_db_path(name: Optional[str] = None) -> Path:
        """Resolve engagement DB. Default = current dir, or named ./engagements/<name>.db"""
        import os
        if name:
            return Path("engagements") / f"{name}.db"
        env_path = os.environ.get("HEAVEN_ENGAGEMENT")
        if env_path:
            return Path(env_path)
        return Path("engagement.db")

    @cli.command()
    @click.option("--engagement", help="Engagement name")
    @click.option("--scan-id", help="Specific scan ID to resume (default: most recent unfinished)")
    @click.option("--i-have-authorization", is_flag=True, required=True,
                  help="Re-confirm authorization for the resumed scan")
    @click.option("--skip-dep-check", is_flag=True)
    def resume(engagement: Optional[str], scan_id: Optional[str],
                i_have_authorization: bool, skip_dep_check: bool) -> None:
        """Resume an interrupted scan from its last checkpoint."""
        from heaven.engagement import EngagementStore
        if not i_have_authorization:
            _print("[red]Resume requires --i-have-authorization[/red]")
            sys.exit(3)

        store = EngagementStore(_engagement_db_path(engagement))
        unfinished = store.find_resumable_scans()
        if not unfinished:
            _print("[yellow]No interrupted scans to resume.[/yellow]")
            return

        if scan_id:
            target_scan = next((s for s in unfinished if s["id"] == scan_id), None)
            if not target_scan:
                _print(f"[red]Scan {scan_id} not found or already completed.[/red]")
                sys.exit(2)
        else:
            target_scan = unfinished[0]
            _print(f"[cyan]Resuming most recent unfinished scan:[/cyan] {target_scan['id']}")

        # Pull the original scan config
        config_json = target_scan.get("config_json") or "{}"
        original_config = json.loads(config_json)
        targets = original_config.get("targets") or original_config

        if not targets.get("ips") and not targets.get("urls"):
            _print("[red]Resumed scan has no targets in its checkpoint config.[/red]")
            sys.exit(2)

        from heaven.orchestrator import build_full_scan
        cfg = get_config()
        orch = build_full_scan(targets, cfg, checkpoint_store=store,
                                resume_scan_id=target_scan["id"])

        def progress_callback(progress):
            _print(f"  [{progress.phase.value}] {progress.progress_pct:.0f}% — {progress.current_task}")

        orch.on_progress(progress_callback)
        try:
            try:
                summary = asyncio.run(orch.run())
            except RuntimeError:
                loop = asyncio.get_event_loop()
                summary = loop.run_until_complete(orch.run())
        except KeyboardInterrupt:
            _print("\n[yellow]Resume aborted — checkpoints saved, run again to continue.[/yellow]")
            sys.exit(0)

        _print(f"\n[green]Resumed scan completed in {summary['elapsed_seconds']}s[/green]")
        _print(f"  Tasks: {summary['completed']}/{summary['total_tasks']} (failed: {summary['failed']})")

        # Persist findings + mark scan complete
        scan_id_done = target_scan["id"]
        for f in summary.get("vulnerabilities", []) + summary.get("findings", []):
            try:
                store.upsert_finding(scan_id_done, f)
            except Exception:
                pass
        store.record_scan_complete(scan_id_done, summary)

    @cli.group()
    def engage() -> None:
        """Manage pentest engagements (scope, scans, findings)."""

    @engage.command("init")
    @click.argument("name")
    @click.option("--client", default="", help="Client name")
    @click.option("--sow", default="", help="Statement of work / contract reference")
    def engage_init(name: str, client: str, sow: str) -> None:
        """Initialize a new engagement (creates ./engagements/<name>.db)."""
        from heaven.engagement import EngagementStore
        path = _engagement_db_path(name)
        store = EngagementStore(path)
        eng = store.create_engagement(name, client=client, statement_of_work=sow)
        _print(f"[green]Engagement initialised:[/green] {path}")
        _print(f"  Name: {eng.name}")
        if eng.client:
            _print(f"  Client: {eng.client}")
        _print(f"\nSet [cyan]HEAVEN_ENGAGEMENT={path}[/cyan] in your shell to use it by default.")

    @engage.command("status")
    @click.option("--engagement", help="Engagement name (default: HEAVEN_ENGAGEMENT env)")
    def engage_status(engagement: Optional[str]) -> None:
        """Show engagement summary."""
        from heaven.engagement import EngagementStore
        path = _engagement_db_path(engagement)
        if not path.exists():
            _print(f"[red]Engagement DB not found: {path}[/red]")
            sys.exit(2)
        store = EngagementStore(path)
        eng = store.get_engagement()
        stats = store.stats()
        _print(f"[cyan]Engagement:[/cyan] {eng.name if eng else '(no metadata)'}")
        if eng and eng.client:
            _print(f"[cyan]Client:[/cyan] {eng.client}")
        _print(f"[cyan]Targets in scope:[/cyan] {stats['scope_targets']}")
        _print(f"[cyan]Scans run:[/cyan] {stats['scans_run']}")
        _print(f"[cyan]Total findings:[/cyan] {stats['total_findings']}")
        if stats["by_severity"]:
            _print("\n[cyan]By severity:[/cyan]")
            for sev, count in stats["by_severity"].items():
                _print(f"  {sev:10}: {count}")
        if stats["by_status"]:
            _print("\n[cyan]By status:[/cyan]")
            for st, count in stats["by_status"].items():
                _print(f"  {st:18}: {count}")

    @cli.group()
    def scope() -> None:
        """Manage in-scope targets for the active engagement."""

    @scope.command("add")
    @click.argument("target")
    @click.option("--engagement", help="Engagement name")
    @click.option("--kind", type=click.Choice(["ip", "cidr", "host", "url", "domain"]), default="host")
    @click.option("--notes", default="")
    def scope_add(target: str, engagement: Optional[str], kind: str, notes: str) -> None:
        """Add a target to the engagement scope (this is the authorization gate)."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        store.add_scope(target, kind=kind, in_scope=True, notes=notes)
        _print(f"[green]Added to scope:[/green] {target} ({kind})")

    @scope.command("import")
    @click.argument("path", type=click.Path(exists=True, dir_okay=False))
    @click.option("--engagement", help="Engagement name")
    def scope_import(path: str, engagement: Optional[str]) -> None:
        """Import scope from a file (one target per line, # for comments)."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        n = store.import_scope_file(Path(path))
        _print(f"[green]Imported {n} targets from {path}[/green]")

    @scope.command("list")
    @click.option("--engagement", help="Engagement name")
    @click.option("--all", "show_all", is_flag=True, help="Include out-of-scope entries")
    def scope_list(engagement: Optional[str], show_all: bool) -> None:
        """List scope targets."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        entries = store.list_scope(in_scope_only=not show_all)
        if not entries:
            _print("[yellow]No scope entries.[/yellow]")
            return
        for e in entries:
            mark = "[green]✓[/green]" if e.in_scope else "[red]✗[/red]"
            _print(f"  {mark} {e.target:40} ({e.kind})  {e.notes}")

    @scope.command("remove")
    @click.argument("target")
    @click.option("--engagement", help="Engagement name")
    def scope_remove(target: str, engagement: Optional[str]) -> None:
        """Remove a target from scope."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        if store.remove_scope(target):
            _print(f"[green]Removed:[/green] {target}")
        else:
            _print(f"[yellow]Not in scope:[/yellow] {target}")

    @cli.command()
    @click.option("--engagement", help="Engagement name")
    @click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]),
                  help="Filter by severity")
    @click.option("--status", type=click.Choice(["open", "verified", "false_positive", "accepted_risk", "fixed"]),
                  help="Filter by status")
    @click.option("--target", help="Filter by target (substring match)")
    @click.option("--vuln-type", help="Filter by vulnerability type (sqli, xss, ...)")
    @click.option("--min-confidence", type=float, default=0.0,
                  help="Minimum confidence (0.0-1.0)")
    @click.option("--limit", type=int, default=100, help="Max rows to show")
    @click.option("--format", "fmt", type=click.Choice(["table", "json", "ids"]),
                  default="table", help="Output format")
    def findings(engagement: Optional[str], severity: Optional[str],
                 status: Optional[str], target: Optional[str],
                 vuln_type: Optional[str], min_confidence: float,
                 limit: int, fmt: str) -> None:
        """List findings from the engagement DB."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        results = store.list_findings(
            severity=severity, status=status, target=target,
            vuln_type=vuln_type, min_confidence=min_confidence, limit=limit,
        )
        if not results:
            _print("[yellow]No findings match.[/yellow]")
            return

        if fmt == "json":
            print(json.dumps([
                {**f.__dict__, "evidence": f.evidence} for f in results
            ], indent=2, default=str))
        elif fmt == "ids":
            for f in results:
                print(f.id)
        else:
            for f in results:
                sev_color = {"critical": "bold red", "high": "red",
                             "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity, "dim")
                _print(
                    f"  [{sev_color}]{f.severity[:4].upper():4}[/{sev_color}] "
                    f"{f.id}  conf={f.confidence:.2f}  {f.vuln_type:18} {f.target[:40]:40} "
                    f"[dim]{f.status}[/dim]"
                )
            _print(f"\n[dim]{len(results)} finding(s) shown.[/dim]")

    @cli.command()
    @click.argument("finding_id")
    @click.option("--engagement", help="Engagement name")
    def show(finding_id: str, engagement: Optional[str]) -> None:
        """Show full details for a single finding (request, response, repro)."""
        from heaven.engagement import EngagementStore
        from heaven.devsecops.evidence import package_finding
        store = EngagementStore(_engagement_db_path(engagement))
        f = store.get_finding(finding_id)
        if not f:
            _print(f"[red]Finding not found:[/red] {finding_id}")
            sys.exit(2)
        finding_dict = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "confidence_bucket": f.confidence_bucket, "cve_id": f.cve_id,
            "risk_score": f.risk_score, "status": f.status,
            "operator_notes": f.operator_notes, "evidence": f.evidence,
        }
        pkg = package_finding(finding_dict)
        # Print Markdown to terminal — Rich-friendly
        if HAS_RICH:
            from rich.markdown import Markdown
            from heaven.utils.logger import console
            if console:
                console.print(Markdown(pkg.to_markdown()))
                return
        print(pkg.to_markdown())

    @cli.command()
    @click.argument("finding_id")
    @click.argument("status", type=click.Choice([
        "open", "verified", "false_positive", "accepted_risk", "fixed",
    ]))
    @click.option("--engagement", help="Engagement name")
    @click.option("--notes", default="", help="Operator notes for the status change")
    def mark(finding_id: str, status: str, engagement: Optional[str], notes: str) -> None:
        """Mark a finding's status (verified, false-positive, accepted-risk, fixed)."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        if store.update_finding_status(finding_id, status, notes=notes):
            _print(f"[green]Updated[/green] {finding_id} → {status}")
        else:
            _print(f"[red]Finding not found:[/red] {finding_id}")
            sys.exit(2)

    @cli.command()
    @click.argument("finding_id")
    @click.option("--engagement", help="Engagement name")
    def replay(finding_id: str, engagement: Optional[str]) -> None:
        """Print the curl command needed to manually re-verify a finding."""
        from heaven.engagement import EngagementStore
        from heaven.devsecops.evidence import package_finding
        store = EngagementStore(_engagement_db_path(engagement))
        f = store.get_finding(finding_id)
        if not f:
            _print(f"[red]Finding not found:[/red] {finding_id}")
            sys.exit(2)
        finding_dict = {
            "target": f.target, "vuln_type": f.vuln_type,
            "evidence": f.evidence, **(f.evidence or {}),
        }
        pkg = package_finding(finding_dict)
        if pkg.curl_command:
            print(pkg.curl_command)
        else:
            _print(f"[yellow]No reproducible request stored for {finding_id}.[/yellow]")
            sys.exit(1)

    @cli.command()
    @click.option("--engagement", help="Engagement name")
    @click.option("--output", "-o", required=True, type=click.Path(), help="Output file")
    @click.option("--format", "fmt",
                  type=click.Choice(["markdown", "csv", "json", "sarif", "burp", "proxy-jsonl"]),
                  default="markdown", help="Export format")
    @click.option("--severity",
                  type=click.Choice(["critical", "high", "medium", "low", "info"]),
                  help="Filter by minimum severity")
    @click.option("--status", type=click.Choice([
        "open", "verified", "false_positive", "accepted_risk", "fixed",
    ]), help="Only export findings in this status")
    @click.option("--min-confidence", type=float, default=0.0)
    def export(engagement: Optional[str], output: str, fmt: str,
               severity: Optional[str], status: Optional[str],
               min_confidence: float) -> None:
        """Export engagement findings.

        Formats:
          markdown    Human-readable report with curl repros (default)
          csv         For Jira / spreadsheet import
          json        Raw findings, full evidence
          sarif       SARIF 2.1.0 for code-scanning dashboards
          burp        Burp Suite XML — load into Site Map, replay in Repeater
          proxy-jsonl JSONL with full request/response, for mitmproxy / Caido
        """
        from heaven.engagement import EngagementStore
        from heaven.devsecops.evidence import (
            export_findings_markdown, export_findings_csv,
        )
        store = EngagementStore(_engagement_db_path(engagement))
        eng = store.get_engagement()

        # If severity filter set, include that level AND higher
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if severity:
            keep_sev = {s for s, r in sev_rank.items() if r <= sev_rank[severity]}
        else:
            keep_sev = set(sev_rank.keys())

        all_findings = store.list_findings(
            status=status, min_confidence=min_confidence, limit=10000,
        )
        # Filter severity in Python (we want >=, not ==)
        all_findings = [f for f in all_findings if f.severity in keep_sev]

        finding_dicts = []
        for f in all_findings:
            d = {
                "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                "title": f.title, "severity": f.severity,
                "confidence": f.confidence, "confidence_bucket": f.confidence_bucket,
                "cve_id": f.cve_id, "risk_score": f.risk_score,
                "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at,
                "status": f.status, "operator_notes": f.operator_notes,
                "evidence": f.evidence,
            }
            finding_dicts.append(d)

        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "markdown":
            text = export_findings_markdown(finding_dicts,
                                             engagement_name=eng.name if eng else "")
            out_path.write_text(text)
        elif fmt == "csv":
            out_path.write_text(export_findings_csv(finding_dicts))
        elif fmt == "json":
            out_path.write_text(json.dumps(finding_dicts, indent=2, default=str))
        elif fmt == "sarif":
            from heaven.devsecops.aggregator import export_sarif
            out_path.write_text(json.dumps(
                export_sarif({"vulnerabilities": finding_dicts}), indent=2,
            ))
        elif fmt == "burp":
            from heaven.devsecops.burp_export import export_burp_xml
            out_path.write_text(export_burp_xml(
                finding_dicts, engagement_name=eng.name if eng else ""))
            _print("[dim]Import into Burp:[/dim] [cyan]File → Import → Items[/cyan]")
        elif fmt == "proxy-jsonl":
            from heaven.devsecops.burp_export import export_proxy_history_jsonl
            out_path.write_text(export_proxy_history_jsonl(finding_dicts))

        _print(f"[green]Exported {len(finding_dicts)} findings → {output} ({fmt})[/green]")

    @cli.command()
    @click.option("--scan-id", required=True)
    @click.option("--engagement")
    def pause(scan_id, engagement):
        """Pause a running scan."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        if store.pause_scan(scan_id):
            _print(f"[green]Scan {scan_id[:8]} paused.[/green]")
        else:
            _print(f"[red]Could not pause {scan_id[:8]}[/red]")

    @cli.command(name="status")
    @click.option("--engagement")
    def status_cmd(engagement):
        """Show all scans in the engagement."""
        from heaven.engagement import EngagementStore
        store = EngagementStore(_engagement_db_path(engagement))
        scans = store.list_all_scans()
        if not scans:
            _print("[yellow]No scans found.[/yellow]")
            return
        status_color = {"running": "green", "completed": "cyan",
                        "paused": "yellow", "failed": "red"}
        for s in scans:
            col = status_color.get(s["status"], "dim")
            _print(f"  [{col}]{s['status']:12}[/{col}] "
                   f"{s['id'][:8]}  findings:{s['findings']:4}  "
                   f"started:{(s['started_at'] or '')[:16]}")

    @cli.command()
    @click.option("--engagement")
    @click.option("--output", "-o", required=True, type=click.Path())
    @click.option("--framework",
                  type=click.Choice(["OWASP_TOP10", "NIST_CSF"]),
                  default="OWASP_TOP10")
    def report(engagement, output, framework):
        """Generate compliance-mapped HTML report."""
        from heaven.engagement import EngagementStore
        from heaven.devsecops.compliance_report import ComplianceReportGenerator
        store = EngagementStore(_engagement_db_path(engagement))
        findings = store.list_findings(limit=10000)
        finding_dicts = [{"id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                          "title": f.title, "severity": f.severity,
                          "confidence": f.confidence,
                          "predicted_cvss_score": f.risk_score,
                          "priority_score": f.risk_score} for f in findings]
        eng = store.get_engagement()
        gen = ComplianceReportGenerator()
        gen.generate_html_report(finding_dicts,
                                  engagement_name=eng.name if eng else "",
                                  output_path=Path(output))
        _print(f"[green]Report written:[/green] {output} ({len(finding_dicts)} findings)")
        sev = {}
        for f in finding_dicts:
            s = f.get("severity", "info").lower()
            sev[s] = sev.get(s, 0) + 1
        for s, n in sorted(sev.items()):
            _print(f"  {s:10}: {n}")

    @cli.command(name="train-model")
    @click.option("--data-dir", default="nvd_data", type=click.Path())
    @click.option("--model-dir", default="models", type=click.Path())
    def train_model_cmd(data_dir, model_dir):
        """Download NVD data and train the CVSS prediction model."""
        from heaven.ml.train_model import train_cvss_model
        metrics = train_cvss_model(Path(data_dir), Path(model_dir))
        _print(f"[green]Training complete:[/green] R²={metrics['r2']}  RMSE={metrics['rmse']}")
        _print(f"  Trained on {metrics['n_train']:,} CVEs, tested on {metrics['n_test']:,}")

    @cli.command(name="kill-chain")
    @click.option("--engagement", help="Engagement name")
    @click.option("--output", "-o", type=click.Path(), help="Save report as JSON")
    def kill_chain_cmd(engagement: Optional[str], output: Optional[str]) -> None:
        """Show Lockheed Cyber Kill Chain phase coverage for current findings."""
        from heaven.engagement import EngagementStore
        from heaven.mitre.kill_chain import KillChainAnalyzer
        store = EngagementStore(_engagement_db_path(engagement))
        all_findings = store.list_findings(limit=10000)
        if not all_findings:
            _print("[yellow]No findings yet — run a scan first.[/yellow]")
            return

        finding_dicts = [
            {"type": f.vuln_type, "vuln_type": f.vuln_type,
             "title": f.title or f.vuln_type, "severity": f.severity,
             "target": f.target, "cve_id": f.cve_id}
            for f in all_findings
        ]
        analyzer = KillChainAnalyzer()
        analyzer.ingest(finding_dicts)
        report = analyzer.report()
        path = analyzer.attack_path_summary()

        _print(f"\n[bold cyan]Cyber Kill Chain Coverage:[/bold cyan] "
               f"{report['coverage_score']}/100  ({report['phases_with_findings']}/7 phases)")
        _print("")
        for phase in report["phases"]:
            colour = "red" if phase["finding_count"] > 0 else "dim"
            _print(f"  [{colour}]{phase['phase']:25}[/{colour}] "
                   f"{phase['finding_count']:4} finding(s)")
        if path:
            _print("\n[bold]Attacker workflow if these findings are chained:[/bold]")
            for step in path:
                # Escape brackets in phase names to avoid Rich markup parsing
                phase_safe = step['phase'].replace("[", r"\[").replace("]", r"\]")
                title_safe = (step['representative_finding'] or "—").replace("[", r"\[").replace("]", r"\]")
                _print(f"  → \\[{phase_safe}] {title_safe} ({step['severity']})")

        if output:
            Path(output).write_text(json.dumps({
                "report": report, "attack_path": path,
                "mermaid": analyzer.to_mermaid(),
            }, indent=2))
            _print(f"\n[green]Report saved:[/green] {output}")


else:
    # Fallback CLI without click
    def cli():
        """Minimal CLI fallback when click is not installed."""
        print(__banner__)
        print(f"HEAVEN v{__version__}")
        print("\nUsage: pip install click rich aiohttp && python -m heaven.main scan --help")
        print("\nAvailable commands: scan, info, serve, init-db, self-audit, mitre-report")
        print("Install click for full CLI: pip install click")


if __name__ == "__main__":
    cli()
