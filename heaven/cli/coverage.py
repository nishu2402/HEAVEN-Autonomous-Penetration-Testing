"""HEAVEN — `heaven coverage` (engagement self-grading)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


@click.command(name="coverage")
@click.option("--engagement", help="Engagement name (default: HEAVEN_ENGAGEMENT env)")
@click.option("--no-llm", is_flag=True,
              help="Skip the LLM gap-analysis pass (deterministic, no API key needed)")
@click.option("--output", "-o", type=click.Path(),
              help="Write the JSON report to this path")
def coverage(engagement: Optional[str], no_llm: bool, output: Optional[str]) -> None:
    """Grade the active engagement's coverage and recommend next steps.

    Always-on rule-based scoring:
      - Scope target hit rate
      - OWASP Top 10 / OWASP API Top 10 category coverage
      - Authenticated-scan / auto-prove / post-ex run flags

    LLM-augmented (when ANTHROPIC/OPENAI/GEMINI key is set):
      - Free-form gap analysis: classes of issue you'd expect to see that
        aren't represented, why they're probably missing, what to do next
    """
    from heaven.ai.coverage_grader import grade_engagement
    from heaven.engagement import EngagementStore

    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        _print(f"Run: [cyan]heaven engage init {engagement or '<name>'}[/cyan]")
        sys.exit(2)

    store = EngagementStore(db_path)
    report = asyncio.run(grade_engagement(store, use_llm=not no_llm))

    grade_color = {"A": "green", "B": "cyan", "C": "yellow",
                   "D": "red", "F": "red bold"}.get(report.grade, "dim")
    _print(f"\n[bold]Coverage grade: [{grade_color}]{report.grade}[/{grade_color}][/bold]")
    _print(f"  Engagement:         {report.engagement_name or '(unnamed)'}")
    _print(f"  Scope coverage:     {report.scope_coverage_pct:.0f}%  "
           f"({report.scanned_target_count}/{report.scope_target_count} targets)")
    _print(f"  OWASP Top 10:       {report.owasp_coverage_pct:.0f}%  "
           f"({sum(1 for c in report.owasp_top10 if c.covered)}/10 categories)")
    _print(f"  Total findings:     {report.total_findings}")
    _print(f"  Authenticated:      {'✓' if report.authenticated else '✗'}")
    _print(f"  Auto-prove run:     {'✓' if report.auto_prove_run else '✗'}")
    _print(f"  Post-ex chained:    {'✓' if report.postex_chained else '✗'}")

    if report.untested_scope_targets:
        _print("\n[bold yellow]Untested scope targets:[/bold yellow]")
        for t in report.untested_scope_targets:
            _print(f"  - {t}")

    _print("\n[bold]OWASP Top 10 coverage:[/bold]")
    for c in report.owasp_top10:
        mark = "[green]✓[/green]" if c.covered else "[red]✗[/red]"
        _print(f"  {mark} {c.code:10}  {c.name:42}  {c.finding_count} finding(s)")

    if report.recommendations:
        _print("\n[bold cyan]Recommendations:[/bold cyan]")
        for r in report.recommendations:
            _print(f"  → {r}")

    if report.llm_gap_summary:
        _print("\n[bold cyan]LLM gap analysis:[/bold cyan]")
        _print(report.llm_gap_summary)

    if output:
        Path(output).write_text(json.dumps(report.to_dict(), indent=2, default=str))
        _print(f"\n[green]Report written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(coverage)
