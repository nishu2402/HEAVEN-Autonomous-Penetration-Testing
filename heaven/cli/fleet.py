"""HEAVEN — `heaven fleet` (the default-on multi-agent engine).

Runs a role-based agent fleet over an engagement: one lead per backend scan mode
plus recon / strategy / hypothesis / FP-critic / coverage roles, coordinated
through the engagement blackboard. Roles PROPOSE work; the real deterministic
oracles VERIFY it; only confirmed findings are persisted. Nothing is faked, and
no agent ever writes a finding.

Zero-key / zero-stress: the whole fleet runs at full strength with no LLM and no
API keys (the intelligence ladder auto-selects a better brain only if one is
already present, and never blocks, downloads, or requires anything). Read-only by
default; the Exploit lead and active hypothesis verification stay behind
`--i-have-authorization`, exactly like the rest of HEAVEN.

This wraps the classic pipeline — it does not replace it. `heaven scan` and the UI
are unchanged. Use this when you want the fleet to drive breadth across every mode
and depth onto the surface it discovers.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import (
    _URL_REGEX,
    _engagement_db_path,
    _print,
    _validate_target_string,
    _verify_authorization,
)
from heaven.config import ScanMode, get_config
from heaven.utils.logger import get_logger, print_banner

logger = get_logger("cli.fleet")

# Modes the operator can focus a fleet run on (the UI-visible set + full). Backend
# only modes (devsecops/ci) are reachable via the roster under `full`.
_FOCUS_MODES = ["full"] + [m.value for m in ScanMode if m.value != "full"]


@click.command(name="fleet")
@click.option("--target", "-t", multiple=True, help="Seed IP/host/CIDR (one or more)")
@click.option("--url", "-u", multiple=True, help="Seed URL (one or more)")
@click.option("--engagement", help="Engagement name (REQUIRED; the fleet persists everything)")
@click.option("--mode", type=click.Choice(_FOCUS_MODES), default="full", show_default=True,
              help="Focus the fleet on one scan mode. `full` runs every mode lead.")
@click.option("--objective", default="",
              help='Free-text early-stop hint, e.g. "critical rce on internal host".')
@click.option("--max-iterations", type=int, default=6, show_default=True,
              help="Hard cap on coordinator iterations.")
@click.option("--time-budget", type=int, default=1800, show_default=True,
              help="Seconds after which the fleet starts no new iteration. A scan "
                   "already in flight finishes under its own per-phase deadlines.")
@click.option("--workers", type=int, default=1, show_default=True,
              help="Scale-out: >1 fans scan tasks across that many worker processes "
                   "that share the engagement DB (for the very biggest targets). "
                   "1 keeps the default single-process adaptive fleet.")
@click.option("--output", "-o", type=click.Path(),
              help="Write the JSON run summary to this path on completion.")
@click.option("--i-have-authorization", is_flag=True, default=False,
              help="Enable the Exploit lead + active hypothesis verification. "
                   "Without it the fleet is strictly read-only.")
def fleet(
    target: tuple[str, ...], url: tuple[str, ...], engagement: Optional[str],
    mode: str, objective: str, max_iterations: int, time_budget: int,
    workers: int, output: Optional[str], i_have_authorization: bool,
) -> None:
    """Run the multi-agent Agent Fleet against the seed targets.

    The coordinator loops observe → plan → act: it snapshots the engagement,
    lets every mode-appropriate role propose work, runs each proposal through the
    real verify oracle, and repeats until the surface is covered, the objective is
    met, or the budget/iteration cap is hit.
    """
    print_banner()

    if not engagement:
        _print("[red]--engagement is required for the fleet engine.[/red]")
        _print("Initialise one first: [cyan]heaven engage init <name>[/cyan]")
        sys.exit(2)

    targets_dict = {"ips": list(target), "urls": list(url)}
    if not any(targets_dict.values()):
        _print("[red]Need at least one --target or --url.[/red]")
        sys.exit(2)

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

    # Read-only runs need no authorization. Only require the flag's *verification*
    # step when the operator opted into exploit/post-ex-class activity.
    if i_have_authorization and not _verify_authorization(targets_dict, i_have_authorization):
        sys.exit(3)

    from heaven.engagement import EngagementStore
    db_path = _engagement_db_path(engagement)
    if not db_path.exists():
        # Auto-create rather than abort, matching `heaven scan`. The fleet
        # persists everything into this engagement, so a first-time name is a
        # convenience, never a blocker that sends the user off to run a separate
        # `engage init` before their run can start.
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _print(f"[cyan]Creating engagement:[/cyan] {engagement}")
    store = EngagementStore(db_path)
    try:
        store.create_engagement(name=engagement)
    except Exception:  # noqa: BLE001 — already exists / best-effort
        logger.debug("engagement create was a no-op / already exists", exc_info=True)

    # --workers is the discoverable front door to scale-out; it just sets the same
    # env var run_fleet reads, so the CLI and a pre-set HEAVEN_FLEET_WORKERS agree.
    if workers and workers > 1:
        os.environ["HEAVEN_FLEET_WORKERS"] = str(workers)

    from heaven.ai.fleet import FleetBrain, fleet_workers, run_fleet
    cfg = get_config()
    brain_info = FleetBrain().describe()
    resolved_workers = fleet_workers()

    _print(f"[bold magenta]⚙ AGENT FLEET[/bold magenta] ·  mode={mode} "
           f"max_iter={max_iterations} budget={time_budget}s "
           f"auth={'ON' if i_have_authorization else 'read-only'} "
           f"scale={'%d workers' % resolved_workers if resolved_workers > 1 else 'single-process'}")
    _print(f"  Seeds: {', '.join(list(target) + list(url))}")
    _print(f"  Brain: {brain_info.get('label', 'deterministic')} "
           f"({'available' if brain_info.get('available') else 'deterministic · AI optional'})")
    if objective:
        _print(f"  Objective: {objective}")
    _print("")

    def _on_iter(rep: dict) -> None:
        _print(f"  [dim]iter {rep['n']}: proposed {rep['proposed']} · ran {rep['ran']} "
               f"· +{rep['new_findings']} findings[/dim]")

    summary = asyncio.run(run_fleet(
        seed_targets=targets_dict, engagement_store=store, base_config=cfg,
        objective=objective, active_mode=mode, max_iterations=max_iterations,
        time_budget_s=float(time_budget), authorized=i_have_authorization,
        engagement_name=engagement, on_iteration=_on_iter,
    ))

    out = summary.to_dict()
    _render(out)

    if output:
        Path(output).write_text(json.dumps(out, indent=2, default=str))
        _print(f"\n[green]Summary written:[/green] {output}")


def _render(out: dict) -> None:
    _print("")
    _print("[bold magenta]══ AGENT FLEET REPORT ══[/bold magenta]")
    _print("")
    _print(f"[bold cyan]Run:[/bold cyan] {out['stop_reason']}")
    _print(f"  Iterations:    {out['iterations_run']}")
    _print(f"  Duration:      {out['duration_s']:.0f}s")
    _print(f"  Hosts engaged: {len(out.get('hosts_engaged', []))}")
    cov = out.get("coverage", {})
    if cov.get("modes_exercised"):
        modes = ", ".join(f"{k}×{v}" for k, v in cov["modes_exercised"].items())
        _print(f"  Modes run:     {modes}")
    if out.get("objective_met"):
        _print(f"  [green]✓ Objective met:[/green] {out['objective']}")

    sb = out.get("severity_breakdown") or {}
    _print("")
    _print(f"[bold]Findings ({out['total_findings']} total)[/bold]")
    _print(f"  [red]critical {sb.get('critical', 0)}[/red]  "
           f"[bright_red]high {sb.get('high', 0)}[/bright_red]  "
           f"[yellow]medium {sb.get('medium', 0)}[/yellow]  "
           f"[cyan]low {sb.get('low', 0)}[/cyan]  "
           f"[dim]info {sb.get('info', 0)}[/dim]")

    cr = out.get("combined_risk") or {}
    if cr.get("total_combinations"):
        _print("")
        _print("[bold]Combined risk[/bold]")
        _print(f"  {cr['total_combinations']} correlated issue(s) · "
               f"{cr.get('critical_combinations', 0)} critical · "
               f"{cr.get('total_attack_paths', 0)} attack path(s)")

    top = out.get("top_findings") or []
    if top:
        _print("")
        _print("[bold]Top findings[/bold]")
        for f in top:
            cve = f" [dim]{f['cve_id']}[/dim]" if f.get("cve_id") else ""
            _print(f"  [{f['severity']:8s}] {f['title'][:56]:56s} "
                   f"[dim]{(f.get('target') or '')[:32]}[/dim]{cve}")

    m = out.get("metrics") or {}
    _print("")
    _print("[bold]Fleet activity[/bold]")
    _print(f"  tasks proposed {m.get('tasks_proposed', 0)} · ran {m.get('tasks_run', 0)} "
           f"· verified {m.get('findings_verified', 0)} · brain calls {m.get('brain_calls', 0)}")


def register(cli: click.Group) -> None:
    cli.add_command(fleet)
