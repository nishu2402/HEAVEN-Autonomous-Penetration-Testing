"""HEAVEN — `heaven watch` continuous-monitoring loop."""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Optional

import click

from heaven.cli._helpers import (
    _engagement_db_path, _print, _validate_target_string,
    _verify_authorization, _URL_REGEX,
)
from heaven.config import ScanMode, get_config


@click.command(name="watch")
@click.option("--target", "-t", multiple=True, help="Target IPs / hostnames / CIDRs")
@click.option("--url", "-u", multiple=True, help="Target URLs")
@click.option("--engagement", required=True,
              help="Engagement to record scans into (REQUIRED — watch loop persists everything)")
@click.option("--interval", "-i", default="60m",
              help="Time between scan starts. Suffix: s (seconds), m (minutes), h (hours), d (days). Default 60m.")
@click.option("--jitter", default=0.1, type=float,
              help="Randomisation factor on the interval (0.0 to 0.5). Default 0.1.")
@click.option("--mode", "-m", type=click.Choice([m.value for m in ScanMode]),
              default="web")
@click.option("--max-iterations", type=int, default=0,
              help="Stop after this many iterations. 0 = run forever (default).")
@click.option("--heartbeat", is_flag=True,
              help="Send an alert at every iteration, even when nothing changed.")
@click.option("--auto-tickets", is_flag=True,
              help="Auto-create Jira/Linear tickets on new criticals + every regression.")
@click.option("--seed", type=int, default=None,
              help="RNG seed (+ iteration index) for reproducible watch runs.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required. Watch will keep scanning until stopped — you must have written authorization for every target.")
def watch(
    target: tuple[str, ...], url: tuple[str, ...],
    engagement: str, interval: str, jitter: float,
    mode: str, max_iterations: int,
    heartbeat: bool, auto_tickets: bool,
    seed: Optional[int], i_have_authorization: bool,
) -> None:
    """Continuously monitor targets. Diffs each scan vs. the last, alerts ONLY on change.

    Killer feature: alert fatigue elimination. The old `heaven schedule`
    pinged Slack every cron tick. `heaven watch` only pings when:
      - a NEW finding appeared, OR
      - a fixed finding REGRESSED (was closed, came back), OR
      - --heartbeat is set (operator wants confirmation every run)

    Example — watch a SaaS app every 30 min, auto-create Jira tickets on new criticals:

        heaven watch -u https://app.example.com \\
            --engagement prod-monitor \\
            --interval 30m \\
            --auto-tickets \\
            --i-have-authorization
    """
    interval_s = _parse_duration(interval)
    if not 0 <= jitter <= 0.5:
        _print("[red]--jitter must be between 0.0 and 0.5[/red]")
        sys.exit(2)

    # Pull list[str] out before constructing the dict so mypy can keep the
    # type narrow when we iterate later (otherwise `targets_dict["ips"]` is
    # `object` because the dict has mixed value types).
    ip_list: list[str] = list(target)
    url_list: list[str] = list(url)
    targets_dict: dict[str, Any] = {
        "ips": ip_list, "urls": url_list,
        "repositories": [], "cloud_providers": [],
        "ports": "1-1024",
        "stealth_level": "normal",
        "ad_domain": "", "ad_dc": "",
        "enable_iot": False, "enable_api_scan": False,
        "enable_container": False, "enable_mitre": True,
        "auto_prove": False, "autonomous": False,
    }
    has_any = bool(ip_list) or bool(url_list)
    if not has_any:
        _print("[red]Need at least one --target or --url.[/red]")
        sys.exit(2)

    # Target validation
    invalid: list[str] = []
    for t in ip_list:
        ok, _ = _validate_target_string(t)
        if not ok:
            invalid.append(t)
    for u in url_list:
        if not _URL_REGEX.match(u):
            invalid.append(u)
    if invalid:
        _print("[bold red]Invalid target(s):[/bold red]")
        for x in invalid:
            _print(f"  - {x}")
        sys.exit(2)

    if not _verify_authorization(targets_dict, i_have_authorization):
        sys.exit(3)

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        _print(f"Run: [cyan]heaven engage init {engagement}[/cyan]")
        sys.exit(2)

    cfg = get_config()
    try:
        cfg.scan_mode = ScanMode(mode)
    except ValueError:
        pass

    from heaven.utils.watcher import WatchConfig, run_watch
    wc = WatchConfig(
        targets=targets_dict, engagement_name=engagement,
        interval_s=interval_s, jitter_pct=jitter,
        max_iterations=max_iterations,
        alert_on_heartbeat=heartbeat,
        auto_create_tickets=auto_tickets,
        seed=seed,
    )

    _print("[bold cyan]🔁 HEAVEN WATCH[/bold cyan]")
    _print(f"  Engagement: {engagement}")
    _print(f"  Targets:    {', '.join(target + url)}")
    _print(f"  Interval:   {interval_s}s ± {int(jitter * 100)}%")
    _print(f"  Iterations: {max_iterations or '∞'}")
    _print(f"  Alerts:     {'heartbeat + change' if heartbeat else 'change-only'}")
    _print(f"  Tickets:    {'auto-create on new crit + regression' if auto_tickets else 'off'}")
    _print("")
    _print("[dim]Press Ctrl+C to stop. State persists in the engagement DB.[/dim]")
    _print("")

    def _on_iteration(it):
        marker = "[bold red]⚠[/bold red]" if (it.new or it.regressed) else "[dim]·[/dim]"
        _print(f"  {marker} iter {it.n}: scan={it.scan_id[:8] if it.scan_id else '—'} "
               f"  new={it.new}  regressed={it.regressed}  resolved={it.resolved}  "
               f"alert={'✓' if it.alert_dispatched else '·'}  "
               f"tix={it.tickets_created}"
               + (f"  [red]error: {it.error}[/red]" if it.error else ""))

    try:
        summary = asyncio.run(run_watch(wc, cfg, on_iteration=_on_iteration))
    except KeyboardInterrupt:
        _print("\n[yellow]Watch interrupted by operator.[/yellow]")
        return

    out = summary.to_dict()
    _print(f"\n[bold]Watch finished:[/bold] {out['stop_reason']}")
    _print(f"  Iterations:   {out['iterations']}")
    _print(f"  Alerts sent:  {out['alerts_dispatched']}")
    _print(f"  Tickets:      {out['tickets_created']}")
    _print(f"  Duration:     {out['duration_s']:.0f}s")


def _parse_duration(spec: str) -> int:
    """Parse "60m" / "2h" / "30s" / "1d" → seconds. Bare digits = seconds."""
    spec = spec.strip().lower()
    if spec.isdigit():
        return int(spec)
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if spec[-1] in multiplier:
        try:
            return int(spec[:-1]) * multiplier[spec[-1]]
        except ValueError:
            pass
    raise click.BadParameter(f"can't parse duration {spec!r}; use 30s / 5m / 2h / 1d")


def register(cli: click.Group) -> None:
    cli.add_command(watch)
