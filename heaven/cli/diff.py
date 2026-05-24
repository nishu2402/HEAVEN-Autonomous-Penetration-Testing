"""HEAVEN — `heaven diff` (differential scanning)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


@click.command(name="diff")
@click.argument("baseline_scan_id")
@click.argument("current_scan_id")
@click.option("--engagement", help="Engagement name (default: active)")
@click.option("--format", "fmt",
              type=click.Choice(["table", "markdown", "json"]),
              default="table")
@click.option("--include-unchanged", is_flag=True,
              help="Include the (usually huge) unchanged bucket in output")
@click.option("--output", "-o", type=click.Path(),
              help="Write the report to this path (format follows --format)")
def diff(baseline_scan_id: str, current_scan_id: str,
         engagement: Optional[str], fmt: str,
         include_unchanged: bool, output: Optional[str]) -> None:
    """Compare two scans of the same engagement.

    Bucketed output: NEW · RESOLVED · REGRESSED · PROMOTED · DEMOTED · UNCHANGED.
    `regressed` is the most-important bucket — those are findings that were
    dispositioned closed (fixed / false_positive / accepted_risk) but came
    back in the current scan.

    Example:

        # Run baseline scan, dispostion findings, scan again, then diff
        heaven scan -u https://app.example.com --engagement q1 \\
            --i-have-authorization                                # records scan-A
        heaven findings mark <id> fixed --engagement q1
        heaven scan -u https://app.example.com --engagement q1 \\
            --i-have-authorization                                # records scan-B
        heaven diff scan-A scan-B --engagement q1
    """
    from heaven.devsecops.diff_finder import (
        compute_diff, render_diff_markdown,
    )
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        sys.exit(2)

    store = EngagementStore(db_path)
    report = compute_diff(store, baseline_scan_id, current_scan_id)
    s = report.to_dict()["summary"]

    if fmt == "json":
        out_text = json.dumps(report.to_dict(), indent=2, default=str)
    elif fmt == "markdown":
        out_text = render_diff_markdown(report, include_unchanged=include_unchanged)
    else:
        # Table — pretty terminal output
        out_text = ""
        _print(f"\n[bold]Scan diff — {current_scan_id[:8]} vs. {baseline_scan_id[:8]}[/bold]")
        _print(f"  🆕 New:       [bold green]{s['new']:4}[/bold green]   "
               f"({s['critical_new']} critical)")
        _print(f"  ✅ Resolved:  [green]{s['resolved']:4}[/green]")
        _print(f"  ⚠️  Regressed: [bold red]{s['regressed']:4}[/bold red]   "
               f"({s['regressed_critical_or_high']} critical/high) "
               + ("← URGENT" if s['regressed_critical_or_high'] else ""))
        _print(f"  ⬆️  Promoted:  [yellow]{s['promoted']:4}[/yellow]")
        _print(f"  ⬇️  Demoted:   [cyan]{s['demoted']:4}[/cyan]")
        _print(f"  = Unchanged: [dim]{s['unchanged']:4}[/dim]")

        def _print_bucket(title: str, rows, color: str = "") -> None:
            if not rows:
                return
            _print(f"\n[bold]{title}[/bold] ({len(rows)})")
            for r in rows[:10]:
                sev_color = {"critical": "bold red", "high": "red",
                             "medium": "yellow", "low": "cyan",
                             "info": "dim"}.get(r.severity, "dim")
                _print(f"  [{sev_color}]{r.severity[:4].upper():4}[/{sev_color}] "
                       f"{r.vuln_type:20} {(r.target or '')[:50]:50}  "
                       f"conf={r.confidence:.2f}")
            if len(rows) > 10:
                _print(f"  [dim]… and {len(rows) - 10} more[/dim]")

        _print_bucket("🆕 New findings", report.new)
        _print_bucket("⚠️ Regressed (closed → reopened)", report.regressed)
        _print_bucket("⬆️ Promoted", report.promoted)
        _print_bucket("✅ Resolved", report.resolved)

    if output:
        Path(output).write_text(out_text or json.dumps(report.to_dict(), indent=2, default=str))
        _print(f"\n[green]Diff written:[/green] {output}")
    elif fmt != "table":
        print(out_text)

    # Exit code for CI: non-zero if regressed critical/high present
    if s["regressed_critical_or_high"] > 0:
        sys.exit(1)


def register(cli: click.Group) -> None:
    cli.add_command(diff)
