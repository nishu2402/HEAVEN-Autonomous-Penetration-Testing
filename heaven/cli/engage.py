"""HEAVEN — Engagement and scope management CLI groups (`engage` and `scope`)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print


# ── engage group ─────────────────────────────────────────────────────────────

@click.group()
def engage() -> None:
    """Manage pentest engagements (scope, scans, findings)."""


@engage.command("init")
@click.argument("name")
@click.option("--client", default="", help="Client name")
@click.option("--sow", default="", help="Statement of work / contract reference")
def engage_init(name: str, client: str, sow: str) -> None:
    """Initialize a new engagement (creates <data_dir>/engagements/<name>.db)."""
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


# ── scope group ──────────────────────────────────────────────────────────────

@click.group()
def scope() -> None:
    """Manage in-scope targets for the active engagement."""


@scope.command("add")
@click.argument("target")
@click.option("--engagement", help="Engagement name")
@click.option("--kind", type=click.Choice(["ip", "cidr", "host", "url", "domain"]), default="host")
@click.option("--criticality",
              type=click.Choice(["low", "medium", "high", "crown_jewel"]),
              default="medium",
              help="Business-context risk multiplier: "
                   "low (0.7) / medium (1.0) / high (1.3) / crown_jewel (1.5). "
                   "Multiplied into every finding's risk_score, so a critical SQLi "
                   "on a crown_jewel host outranks the same finding on a low-crit dev box.")
@click.option("--notes", default="")
def scope_add(target: str, engagement: Optional[str], kind: str,
              criticality: str, notes: str) -> None:
    """Add a target to the engagement scope (this is the authorization gate)."""
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement))
    store.add_scope(target, kind=kind, in_scope=True,
                    criticality=criticality, notes=notes)
    mul = {"low": 0.7, "medium": 1.0, "high": 1.3, "crown_jewel": 1.5}[criticality]
    _print(f"[green]Added to scope:[/green] {target} ({kind}, "
           f"criticality={criticality}, ×{mul})")


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
    _crit_color = {
        "low": "dim", "medium": "white",
        "high": "yellow", "crown_jewel": "bold red",
    }
    for e in entries:
        mark = "[green]✓[/green]" if e.in_scope else "[red]✗[/red]"
        color = _crit_color.get(e.criticality, "white")
        crit = f"[{color}]{e.criticality:11}[/{color}]"
        _print(f"  {mark} {e.target:40} ({e.kind:6}) {crit}  {e.notes}")


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


def register(cli: click.Group) -> None:
    cli.add_command(engage)
    cli.add_command(scope)
