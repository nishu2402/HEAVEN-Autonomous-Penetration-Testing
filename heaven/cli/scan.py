"""HEAVEN — Scan-lifecycle CLI commands: `scan`, `schedule`, `resume`, `pause`, `status`."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Optional

import click

from heaven.cli._helpers import (
    _URL_REGEX,
    _engagement_db_path,
    _print,
    _validate_target_string,
    _verify_authorization,
)
from heaven.config import ScanMode, get_config
from heaven.utils.logger import HAS_RICH, get_logger, print_banner

logger = get_logger("cli.scan")


class _SkipHud(Exception):
    """Sentinel — raised inside the Rich-HUD try-block when --watch-tail
    has already run the scan and bound `summary`. Caught by an except
    clause that does nothing, letting control fall through to the post-
    scan persistence."""


def _print_inventory(assets: Optional[list]) -> None:
    """Print the host & service inventory (open ports / versions / OS).

    Fed by the network scanner's ``assets``; values are shown exactly as nmap
    observed them. Silent when no network scan ran (e.g. a web-only mode).
    """
    from heaven.devsecops.inventory import inventory_totals, normalize_assets
    inventory = normalize_assets(assets)
    if not inventory:
        return
    tot = inventory_totals(inventory)
    _print(f"\n[bold]Host & Service Inventory[/bold]  [dim]— {tot['hosts']} host(s), "
           f"{tot['open_ports']} open port(s), {tot['distinct_services']} service(s)[/dim]")
    for h in inventory:
        os_txt = h.get("os_label") or "OS not determined"
        _print(f"  [cyan]{h['host']}[/cyan]  [dim]{os_txt}[/dim]")
        for p in h.get("ports", []):
            ver = p.get("service_version") or ""
            _print(f"    [dim]{p['port']:>5}/{p.get('protocol','tcp')}[/dim]  "
                   f"{(p.get('service') or '—')[:14]:14}  {ver}")
    _print("  [dim]View later:[/dim] [cyan]heaven assets[/cyan]  "
           "[dim](an OS marked 'heuristic — unconfirmed' is a TTL guess)[/dim]")


# ═══════════════════════════════════════════════════════════════════════════
# scan — the big one
# ═══════════════════════════════════════════════════════════════════════════

@click.command(epilog="""
\b
Examples:
  heaven scan -t 10.0.0.5 --i-have-authorization
  heaven scan -u https://app.example.com -m web --api-scan --i-have-authorization
  heaven scan -t 10.0.0.0/24 --engagement acme --auto-prove --i-have-authorization
  heaven scan -u https://app.example.com --cookie-file cookies.txt -m web --i-have-authorization

Tip: run `heaven use <engagement>` once to stop repeating --engagement.
""")
@click.option("--target", "-t", multiple=True, help="Target IPs, hostnames, or CIDRs")
@click.option("--url", "-u", multiple=True, help="Target URLs for web scanning")
@click.option("--repo", "-r", multiple=True, help="Git repositories to scan")
@click.option("--cloud", "-c", multiple=True, help="Cloud providers (aws, gcp, azure)")
@click.option("--mode", "-m", type=click.Choice([m.value for m in ScanMode]), default="full")
@click.option("--ports", "-p", default="1-65535", help="Port range for network scan (default: all ports)")
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
@click.option("--seed", type=int, default=None,
              help="Integer seed for deterministic scans. Persisted with the engagement "
                   "so `heaven replay <scan-id>` reproduces the exact same scan.")
@click.option("--cookie-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Netscape cookie file (curl/wget -c format) used for authenticated scans.")
@click.option("--auth", default="", metavar="SPEC",
              help='Form-login spec: "url=/login,user=admin,pass=password[,csrf_field=token]". '
                   "HEAVEN logs in once and reuses the session cookies for the whole scan.")
@click.option("--auto-prove", is_flag=True,
              help="After detection, automatically run exploit_proof on every high-confidence "
                   "SQLi/cmdi/SSRF finding. Captures proof artifacts (sqlmap dump, RCE canary, "
                   "SSRF callback) into evidence.exploit_proof[].")
@click.option("--autonomous", is_flag=True,
              help="Full autonomous mode: --auto-prove + chain post-exploitation modules "
                   "(linpeas / cred-reuse) from initial-access findings. Requires explicit "
                   "operator authorization.")
@click.option("--watch-tail", is_flag=True,
              help="Headless mode: disable the Rich live HUD and stream a flat log line per "
                   "phase / finding to stdout. Better for CI, ssh sessions, and `tee` piping.")
@click.option("--cloud-buckets", is_flag=True,
              help="Also hunt for publicly exposed S3/GCS/Azure buckets guessed from the "
                   "target domain. Off by default — it fires external requests to the cloud "
                   "providers, so it stays an explicit opt-in.")
def scan(
    target: tuple[str, ...], url: tuple[str, ...],
    repo: tuple[str, ...], cloud: tuple[str, ...],
    mode: str, ports: str, stealth: str,
    output: str, output_file: Optional[str],
    ad_domain: str, ad_dc: str,
    iot: bool, api_scan: bool, container: bool, mitre_map: bool,
    engagement: Optional[str], use_scope: bool,
    i_have_authorization: bool, skip_dep_check: bool,
    seed: Optional[int], cookie_file: Optional[str], auth: str,
    auto_prove: bool, autonomous: bool,
    watch_tail: bool = False, cloud_buckets: bool = False,
) -> None:
    """Launch a vulnerability scan against specified targets."""
    print_banner()

    # Seed for reproducibility — must be set BEFORE any orchestrator/AI brain
    # call so all subsequent random.choice / RNG draws come from the same stream.
    if seed is not None:
        from heaven.utils.seeding import set_seed
        set_seed(seed)
        _print(f"[cyan]Deterministic mode:[/cyan] seed={seed}")

    # Authenticated-scan session — Netscape cookie file or form login.
    # Activated process-wide so every scanner module picks it up.
    if cookie_file or auth:
        from heaven.recon.auth_session import (
            load_cookie_file, parse_auth_string,
            perform_form_login, set_active_session,
        )
        try:
            if cookie_file:
                sess = load_cookie_file(Path(cookie_file))
                set_active_session(sess)
                _print(f"[cyan]Authenticated scan:[/cyan] {sess.label}")
            if auth:
                spec = parse_auth_string(auth)
                base = url[0] if url else (target[0] if target else "http://localhost")
                sess = asyncio.run(perform_form_login(base, spec))
                set_active_session(sess)
                _print(f"[cyan]Authenticated scan:[/cyan] {sess.label}")
        except Exception as e:
            _print(f"[red]Auth setup failed:[/red] {e}")
            sys.exit(4)

    # --autonomous implies --auto-prove
    if autonomous:
        auto_prove = True
        _print("[bold magenta]⚙ AUTONOMOUS MODE[/bold magenta] — auto-prove + post-ex chaining enabled")

    targets: dict[str, Any] = {
        "ips": list(target), "urls": list(url),
        "repositories": list(repo), "cloud_providers": list(cloud),
        "ports": ports, "stealth_level": stealth,
        "ad_domain": ad_domain, "ad_dc": ad_dc,
        "enable_iot": iot, "enable_api_scan": api_scan,
        "enable_container": container, "enable_mitre": mitre_map,
        "auto_prove": auto_prove, "autonomous": autonomous,
        "cloud_buckets": cloud_buckets,
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
            kept_ips, dropped_ips = [], []
            for t in list(targets["ips"]):
                if engagement_store.is_in_scope(t):
                    kept_ips.append(t)
                else:
                    dropped_ips.append(t)
            kept_urls, dropped_urls = [], []
            for u in list(targets["urls"]):
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
                cast_urls: list[str] = targets["urls"]
                cast_urls.append(target_input)
            else:
                cast_ips: list[str] = targets["ips"]
                cast_ips.append(target_input)

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

    # Target validation
    invalid = []
    for t in list(targets["ips"]):
        ok, _kind = _validate_target_string(t)
        if not ok:
            invalid.append(t)
    for u in list(targets["urls"]):
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

    # Pass the mode explicitly so the orchestrator registers only the tasks
    # that belong to it (FULL runs everything; a focused mode runs its
    # dedicated modules + the shared scoring/report tail).
    orch = build_full_scan(targets, config, checkpoint_store=engagement_store,
                           scan_mode=ScanMode(mode))

    if engagement_store:
        # Name the scan after its targets (e.g. "app.example.com +2") so it reads
        # the same in the CLI, the web Scans list and downloaded reports.
        from heaven.engagement import scan_display_name
        _scan_name = scan_display_name(
            list(targets.get("urls") or []) + list(targets.get("ips") or []), mode,
        )
        engagement_store.record_scan_start(
            orch.scan_id, name=_scan_name, mode=mode,
            config={"targets": targets, "seed": seed},
        )

    # --watch-tail short-circuits the Rich live HUD with a flat stdout stream.
    # Useful for CI / ssh sessions / `heaven scan ... | tee scan.log` workflows
    # where the live HUD ends up scrambled in the recording.
    if watch_tail:
        import time as _time

        tail_sev_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }

        def _tail_progress(p) -> None:
            ts = _time.strftime("%H:%M:%S")
            phase = p.phase.value.upper()
            pct = p.progress_pct
            task = p.current_task or ""
            print(f"{ts}  [{phase:14}] {pct:5.1f}%  {task}", flush=True)

        def _tail_finding(f: dict) -> None:
            ts = _time.strftime("%H:%M:%S")
            sev = (f.get("severity") or "info").lower()
            tail_sev_counts[sev] = tail_sev_counts.get(sev, 0) + 1
            vt = (f.get("vuln_type") or f.get("type") or "")[:24]
            tgt = (f.get("target") or "")[:60]
            conf = f.get("confidence", 0)
            try:
                conf_str = f"{float(conf):.2f}"
            except (TypeError, ValueError):
                conf_str = "—"
            print(f"{ts}  FINDING  [{sev:<8}] {vt:24} {tgt:60} conf={conf_str}",
                  flush=True)

        orch.on_progress(_tail_progress)
        orch.on_finding(_tail_finding)
        try:
            try:
                summary = asyncio.run(orch.run())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    summary = loop.run_until_complete(orch.run())
                finally:
                    loop.close()
        except KeyboardInterrupt:
            print("Scan aborted.", flush=True)
            sys.exit(0)

        elapsed = summary.get("elapsed_seconds", 0)
        print(
            f"\nScan complete in {elapsed}s · "
            f"crit={tail_sev_counts['critical']} high={tail_sev_counts['high']} "
            f"med={tail_sev_counts['medium']} low={tail_sev_counts['low']} "
            f"info={tail_sev_counts['info']}",
            flush=True,
        )
        # Skip past the Rich HUD block — `summary` is bound; fall through
        # to the post-scan persistence by jumping over the HUD `try:`.
        _watch_tail_handled = True
    else:
        _watch_tail_handled = False

    try:
        if _watch_tail_handled:
            raise _SkipHud()
        from rich.live import Live
        from rich.layout import Layout
        from rich.progress import (
            Progress, BarColumn, TextColumn,
            TimeElapsedColumn, SpinnerColumn,
        )
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        import time as _time

        findings_log: list[dict[str, Any]] = []
        log_lines: list[str] = []
        sev_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        _sev_colors = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "cyan", "info": "dim white",
        }

        progress_bar = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=36, style="cyan", complete_style="bold green"),
            TextColumn("[bold green]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            expand=False,
        )
        scan_task = progress_bar.add_task("INIT", total=100)

        def build_layout() -> Layout:
            p = orch.progress

            elapsed_s = p.elapsed_seconds
            elapsed_str = f"{int(elapsed_s // 60)}m{int(elapsed_s % 60):02d}s"
            crit = sev_counts["critical"]
            high = sev_counts["high"]
            med = sev_counts["medium"]
            if crit + high + med:
                sev_str = (
                    f"[bold red]{crit}C[/]  "
                    f"[red]{high}H[/]  "
                    f"[yellow]{med}M[/]  "
                    f"[cyan]{sev_counts['low']}L[/]"
                )
            else:
                sev_str = "[dim]none yet[/dim]"

            stats_grid = Table.grid(padding=(0, 3))
            stats_grid.add_column()
            stats_grid.add_column()
            stats_grid.add_column()
            stats_grid.add_column()
            stats_grid.add_row(
                f"[cyan]Phase[/]   [bold white]{p.phase.value.upper()}[/]",
                f"[cyan]Tasks[/]   [green]{p.completed_tasks}[/][dim]/{p.total_tasks}[/]",
                f"[cyan]Findings[/]   {sev_str}",
                f"[cyan]Assets[/]   [bold]{p.assets_discovered}[/]  "
                f"[cyan]Elapsed[/]   [bold]{elapsed_str}[/]",
            )
            stats_panel = Panel(
                stats_grid,
                title="[bold cyan] HEAVEN [/bold cyan]",
                border_style="cyan",
                padding=(0, 1),
            )

            ftable = Table(
                show_header=True,
                header_style="bold cyan",
                border_style="dim",
                padding=(0, 1),
                expand=True,
            )
            ftable.add_column("SEV",  width=6,  no_wrap=True)
            ftable.add_column("TYPE", width=24, no_wrap=True)
            ftable.add_column("TARGET", ratio=1)
            ftable.add_column("CONF", width=6, justify="right")

            if findings_log:
                for f in findings_log[-20:]:
                    sev = (f.get("severity") or "info").lower()
                    color = _sev_colors.get(sev, "dim")
                    conf_val = f.get("confidence", 0)
                    try:
                        conf_str = f"{float(conf_val):.2f}"
                    except (TypeError, ValueError):
                        conf_str = "—"
                    ftable.add_row(
                        f"[{color}]{sev[:4].upper()}[/{color}]",
                        str(f.get("vuln_type") or f.get("type") or "")[:24],
                        str(f.get("target") or "")[:70],
                        conf_str,
                    )
            else:
                ftable.add_row(
                    "[dim]—[/dim]",
                    "[dim]Waiting for findings...[/dim]",
                    "[dim]—[/dim]",
                    "[dim]—[/dim]",
                )

            findings_panel = Panel(
                ftable,
                title="[bold cyan]Live Findings[/bold cyan]",
                border_style="dim",
                padding=(0, 0),
            )

            progress_panel = Panel(
                progress_bar,
                border_style="dim",
                padding=(0, 1),
            )

            log_panel = Panel(
                Text("\n".join(log_lines[-5:]), style="dim"),
                title="[dim]Activity[/dim]",
                border_style="dim",
                padding=(0, 1),
            )

            layout = Layout()
            layout.split_column(
                Layout(stats_panel,    name="stats",    size=4),
                Layout(findings_panel, name="findings"),
                Layout(progress_panel, name="progress", size=4),
                Layout(log_panel,      name="log",      size=7),
            )
            return layout

        def progress_callback(progress) -> None:
            pct = progress.progress_pct
            phase = progress.phase.value.upper()
            progress_bar.update(scan_task, completed=pct, description=phase)
            task_name = progress.current_task
            if task_name:
                ts = _time.strftime("%H:%M:%S")
                log_lines.append(f"{ts}  ✓ {task_name}")

        def finding_callback(finding: dict) -> None:
            findings_log.append(finding)
            sev = (finding.get("severity") or "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        with Live(build_layout(), refresh_per_second=4, screen=False) as live:
            def _on_progress(p):
                progress_callback(p)
                live.update(build_layout())
            orch.on_progress(_on_progress)
            orch.on_finding(finding_callback)
            try:
                summary = asyncio.run(orch.run())
            except KeyboardInterrupt:
                _print("[yellow]Scan aborted.[/yellow]")
                sys.exit(0)

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
                if console:
                    console.print(ft)

    except _SkipHud:
        # --watch-tail already ran the scan + bound `summary`; nothing to do.
        pass
    except ImportError:
        # Fallback when Rich is not available
        def _plain_progress_callback(progress: Any) -> None:
            _print(
                f"  [{progress.phase.value}] {progress.progress_pct:.0f}% "
                f"({progress.completed_tasks}/{progress.total_tasks}) — {progress.current_task}"
            )

        orch.on_progress(_plain_progress_callback)
        try:
            try:
                summary = asyncio.run(orch.run())
            except RuntimeError:
                # asyncio.run() already closed its loop — use a fresh one.
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    summary = loop.run_until_complete(orch.run())
                finally:
                    loop.close()
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

    _print_inventory(summary.get("assets"))

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
                gen = PDFReportGenerator()
                if gen.generate(summary, output_file):
                    if gen.available:
                        _print(f"  PDF report written to: {output_file}")
                    else:
                        html_path = (output_file[:-4] + ".html"
                                     if output_file.endswith(".pdf") else output_file + ".html")
                        _print(f"  [yellow]reportlab not installed — wrote HTML report instead:"
                               f"[/yellow] {html_path}")
                        _print("  [dim]For PDF: pip install reportlab  (then re-run)[/dim]")
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
                Path(output_file).write_text(export_findings_markdown(
                    findings_in_summary, assets=summary.get("assets")))
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


# ═══════════════════════════════════════════════════════════════════════════
# schedule
# ═══════════════════════════════════════════════════════════════════════════

@click.command(hidden=True)
@click.argument("interval_minutes", type=int)
@click.option("--target", "-t", multiple=True, required=True, help="Target IPs or URLs")
@click.option("--mode", "-m", type=click.Choice([m.value for m in ScanMode]), default="full")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required for scheduled scans — confirms all targets are authorized")
def schedule(interval_minutes: int, target: tuple[str, ...], mode: str,
             i_have_authorization: bool) -> None:
    """[Deprecated — use `heaven watch`] Re-scan targets every N minutes.

    Kept for backward compatibility. This is a naive fixed-interval re-scan
    with no diffing and no alert-on-change. `heaven watch` supersedes it: it
    diffs each run against the previous one and only alerts when something
    actually changed, with optional auto-ticketing.
    """
    print_banner()
    _print("[yellow]Note:[/yellow] `heaven schedule` is deprecated — "
           "`heaven watch` adds change-detection and alert-on-change. "
           "See [cyan]heaven watch --help[/cyan].")

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
        # Import apscheduler dynamically to avoid hard dependency at module-import time
        import importlib
        try:
            AsyncIOScheduler = getattr(importlib.import_module("apscheduler.schedulers.asyncio"), "AsyncIOScheduler")
        except Exception:
            raise ImportError
        import subprocess  # nosec B404 -- runs vetted CLI tools, no shell
        from datetime import datetime

        def run_scan_job():
            _print(f"\n[green]Scheduled scan triggered: {datetime.now().isoformat()}[/green]")
            cmd = ["heaven", "scan", "-m", mode, "--i-have-authorization"]
            for t in target:
                if t.startswith("http"):
                    cmd.extend(["-u", t])
                else:
                    cmd.extend(["-t", t])
            subprocess.run(cmd, check=False)  # nosec B603 -- fixed argv, no shell

        run_scan_job()  # Run once immediately

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        scheduler = AsyncIOScheduler(event_loop=loop)
        scheduler.add_job(run_scan_job, "interval", minutes=interval_minutes)
        scheduler.start()

        _print("[green]Scheduler started. Press Ctrl+C to exit.[/green]")
        try:
            loop.run_forever()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            scheduler.shutdown(wait=False)
            loop.close()
    except ImportError:
        _print("[red]Error: apscheduler required. Install with: pip install apscheduler[/red]")


# ═══════════════════════════════════════════════════════════════════════════
# resume
# ═══════════════════════════════════════════════════════════════════════════

@click.command()
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

    config_json = target_scan.get("config_json") or "{}"
    original_config = json.loads(config_json)
    targets = original_config.get("targets") or original_config

    if not targets.get("ips") and not targets.get("urls"):
        _print("[red]Resumed scan has no targets in its checkpoint config.[/red]")
        sys.exit(2)

    from heaven.orchestrator import build_full_scan
    cfg = get_config()
    # Rebuild the same focused task graph the original scan used so resume
    # replays the right modules.
    _resume_mode = target_scan.get("mode") or original_config.get("mode") or "full"
    try:
        _resume_scan_mode = ScanMode(_resume_mode)
    except ValueError:
        _resume_scan_mode = ScanMode.FULL
    orch = build_full_scan(targets, cfg, checkpoint_store=store,
                            resume_scan_id=target_scan["id"],
                            scan_mode=_resume_scan_mode)

    def progress_callback(progress):
        _print(f"  [{progress.phase.value}] {progress.progress_pct:.0f}% — {progress.current_task}")

    orch.on_progress(progress_callback)
    try:
        try:
            summary = asyncio.run(orch.run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                summary = loop.run_until_complete(orch.run())
            finally:
                loop.close()
    except KeyboardInterrupt:
        _print("\n[yellow]Resume aborted — checkpoints saved, run again to continue.[/yellow]")
        sys.exit(0)

    _print(f"\n[green]Resumed scan completed in {summary['elapsed_seconds']}s[/green]")
    _print(f"  Tasks: {summary['completed']}/{summary['total_tasks']} (failed: {summary['failed']})")

    _print_inventory(summary.get("assets"))

    scan_id_done = target_scan["id"]
    for f in summary.get("vulnerabilities", []) + summary.get("findings", []):
        try:
            store.upsert_finding(scan_id_done, f)
        except Exception:
            logger.debug("suppressed non-fatal exception", exc_info=True)
    store.record_scan_complete(scan_id_done, summary)


# ═══════════════════════════════════════════════════════════════════════════
# pause / status
# ═══════════════════════════════════════════════════════════════════════════

@click.command()
@click.option("--scan-id", required=True)
@click.option("--engagement")
def pause(scan_id: str, engagement: Optional[str]) -> None:
    """Pause a running scan."""
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement))
    if store.pause_scan(scan_id):
        _print(f"[green]Scan {scan_id[:8]} paused.[/green]")
    else:
        _print(f"[red]Could not pause {scan_id[:8]}[/red]")


@click.command(name="status")
@click.option("--engagement")
def status_cmd(engagement: Optional[str]) -> None:
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


def register(cli: click.Group) -> None:
    cli.add_command(scan)
    cli.add_command(schedule)
    cli.add_command(resume)
    cli.add_command(pause)
    cli.add_command(status_cmd)
