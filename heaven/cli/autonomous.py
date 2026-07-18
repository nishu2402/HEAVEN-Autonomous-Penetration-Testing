"""HEAVEN — `heaven autonomous` (iterative agent-loop pen-test).

Replaces the fixed DAG with an LLM-driven observe → plan → act loop. The
operator points HEAVEN at one or more seed targets, sets a budget, and
the loop decides each iteration what to do next based on findings so far.

Falls back to a deterministic rule-based planner when no LLM API key is
configured, so the command runs end-to-end on a fresh install with no
secrets — the LLM upgrade just makes the planning smarter.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import (
    _engagement_db_path, _print, _verify_authorization, _validate_target_string,
    _URL_REGEX,
)
from heaven.config import get_config
from heaven.utils.logger import print_banner


@click.command(name="autonomous")
@click.option("--target", "-t", multiple=True, help="Seed IP/host/CIDR (one or more)")
@click.option("--url", "-u", multiple=True, help="Seed URL (one or more)")
@click.option("--engagement", help="Engagement name (REQUIRED — autonomous mode persists everything)")
@click.option("--max-iterations", type=int, default=8, show_default=True,
              help="Hard cap on planner iterations.")
@click.option("--time-budget", type=int, default=1800, show_default=True,
              help="Hard cap in seconds on total loop runtime.")
@click.option("--objective", default="",
              help='Free-text early-stop hint. Example: "critical rce on internal host". '
                   "When any finding matches, the loop exits with objective_met=True.")
@click.option("--no-llm", is_flag=True,
              help="Skip the LLM planner and use the rule-based playbook only "
                   "(deterministic, works without ANTHROPIC/OPENAI/GEMINI keys).")
@click.option("--seed", type=int, default=None,
              help="RNG seed — propagated to bandit + planner for reproducible runs.")
@click.option("--output", "-o", type=click.Path(),
              help="Write the JSON run summary to this path on completion.")
@click.option("--i-have-authorization", is_flag=True, required=True,
              help="Required. Autonomous mode chains exploits and post-ex; you must "
                   "have explicit written permission for every seed target.")
def autonomous(
    target: tuple[str, ...], url: tuple[str, ...],
    engagement: Optional[str],
    max_iterations: int, time_budget: int, objective: str,
    no_llm: bool, seed: Optional[int], output: Optional[str],
    i_have_authorization: bool,
) -> None:
    """Run an LLM-driven iterative pen-test against the seed targets.

    The loop:
      1. Observe — read all findings stored so far
      2. Plan    — ask the LLM (or rule-based fallback): what next?
      3. Act     — execute that plan (scan / prove / post-ex) via the orchestrator
      4. Score   — credit the bandit based on new findings produced
      5. Repeat until: max-iterations, time-budget, objective-met, or planner gives up
    """
    print_banner()

    if seed is not None:
        from heaven.utils.seeding import set_seed
        set_seed(seed)
        _print(f"[cyan]Deterministic mode:[/cyan] seed={seed}")

    if not engagement:
        _print("[red]--engagement is required for autonomous mode.[/red]")
        _print("Initialise one first: [cyan]heaven engage init <name>[/cyan]")
        sys.exit(2)

    targets_dict = {
        "ips": list(target), "urls": list(url),
    }
    has_any = any(targets_dict[k] for k in ("ips", "urls"))
    if not has_any:
        _print("[red]Need at least one --target or --url.[/red]")
        sys.exit(2)

    # Validate every seed target
    invalid: list[str] = []
    for t in targets_dict["ips"]:
        ok, _ = _validate_target_string(t)
        if not ok:
            invalid.append(t)
    for u in targets_dict["urls"]:
        if not _URL_REGEX.match(u):
            invalid.append(u)
    if invalid:
        _print("[bold red]Invalid target(s):[/bold red]")
        for x in invalid:
            _print(f"  - {x}")
        sys.exit(2)

    if not _verify_authorization(targets_dict, i_have_authorization):
        sys.exit(3)

    from heaven.engagement import EngagementStore
    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        _print(f"[red]Engagement DB not found:[/red] {db_path}")
        _print(f"Run: [cyan]heaven engage init {engagement}[/cyan]")
        sys.exit(2)
    store = EngagementStore(db_path)

    _print(f"[bold magenta]⚙ AUTONOMOUS LOOP[/bold magenta] — "
           f"max_iter={max_iterations} budget={time_budget}s "
           f"llm={'OFF' if no_llm else 'ON'}")
    _print(f"  Seeds: {', '.join(list(target) + list(url))}")
    if objective:
        _print(f"  Objective: {objective}")
    _print("")

    from heaven.ai.autonomous_loop import run_autonomous
    cfg = get_config()

    summary = asyncio.run(run_autonomous(
        seed_targets=targets_dict,
        engagement_store=store,
        base_config=cfg,
        max_iterations=max_iterations,
        time_budget_s=time_budget,
        objective=objective,
        use_llm_planner=not no_llm,
    ))

    out_dict = summary.to_dict()
    _print("")
    _print("[bold magenta]══ AUTONOMOUS RUN REPORT ══[/bold magenta]")

    # Executive summary — the professional headline.
    if out_dict.get("executive_summary"):
        _print("")
        _print("[bold]Executive summary[/bold]")
        _print(f"  {out_dict['executive_summary']}")

    _print("")
    _print(f"[bold cyan]Run:[/bold cyan] {out_dict['stop_reason']}")
    _print(f"  Iterations:   {out_dict['iterations_run']}")
    _print(f"  Duration:     {out_dict['duration_s']:.0f}s")
    _print(f"  Hosts engaged: {len(out_dict.get('hosts_engaged', []))}")
    if out_dict.get("actions_taken"):
        acts = ", ".join(f"{k}×{v}" for k, v in out_dict["actions_taken"].items())
        _print(f"  Actions:      {acts}")
    if out_dict["objective_met"]:
        _print(f"  [green]✓ Objective met:[/green] {out_dict['objective']}")

    # Severity breakdown.
    sb = out_dict.get("severity_breakdown") or {}
    _print("")
    _print(f"[bold]Findings ({out_dict['total_findings']} total)[/bold]")
    _print(f"  [red]critical {sb.get('critical', 0)}[/red]  "
           f"[bright_red]high {sb.get('high', 0)}[/bright_red]  "
           f"[yellow]medium {sb.get('medium', 0)}[/yellow]  "
           f"[cyan]low {sb.get('low', 0)}[/cyan]  "
           f"[dim]info {sb.get('info', 0)}[/dim]")

    # Top findings.
    top = out_dict.get("top_findings") or []
    if top:
        _print("")
        _print("[bold]Top findings[/bold]")
        for f in top:
            cve = f" [dim]{f['cve_id']}[/dim]" if f.get("cve_id") else ""
            _print(f"  [{f['severity']:8s}] {f['title'][:56]:56s} "
                   f"[dim]{(f.get('target') or '')[:32]}[/dim]{cve}")

    # Iteration trace.
    if out_dict["iterations"]:
        _print("")
        _print("[bold]Iteration trace[/bold]")
        for r in out_dict["iterations"]:
            _print(f"  [{r['n']}] {r['action']['kind']:18s} "
                   f"target={(r['action']['target'] or '-')[:38]:38s} "
                   f"+{r['new_findings']} findings  reward={r['reward']:.2f}")

    # Recommendations.
    recs = out_dict.get("recommendations") or []
    if recs:
        _print("")
        _print("[bold]Recommendations[/bold]")
        for rec in recs:
            _print(f"  • {rec}")

    if output:
        Path(output).write_text(json.dumps(out_dict, indent=2, default=str))
        _print(f"\n[green]Summary written:[/green] {output}")


def register(cli: click.Group) -> None:
    cli.add_command(autonomous)
