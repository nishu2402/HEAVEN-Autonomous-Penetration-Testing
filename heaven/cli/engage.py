"""HEAVEN — Engagement and scope management CLI groups (`engage` and `scope`)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import (
    _engagement_db_path,
    _engagement_dirs,
    _print,
    clear_current_engagement,
    get_current_engagement,
    resolve_engagement_name,
)


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


@engage.command("list")
def engage_list() -> None:
    """List every engagement with finding/scan counts and the active marker."""
    from heaven.engagement import DEMO_DB_NAME, EngagementStore

    active = resolve_engagement_name()
    # Dedupe by stem across the canonical + legacy dirs (canonical wins).
    seen: dict[str, Path] = {}
    for d in _engagement_dirs():
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.db")):
            seen.setdefault(p.stem, p)
    if not seen:
        _print("[yellow]No engagements yet.[/yellow] Create one with: "
               "[cyan]heaven engage init <name>[/cyan]")
        return
    _print("[cyan]Engagements:[/cyan]")
    for name in sorted(seen):
        try:
            stats = EngagementStore(seen[name]).stats()
            findings = stats.get("total_findings", 0)
            scans = stats.get("scans_run", 0)
        except Exception:  # noqa: BLE001 — skip unreadable/locked DBs
            findings = scans = 0
        marker = "[green]●[/green]" if name == active else " "
        tag = " [dim](sample)[/dim]" if name == DEMO_DB_NAME else ""
        detail = (f"{findings} finding{'s' if findings != 1 else ''}, "
                  f"{scans} scan{'s' if scans != 1 else ''}")
        _print(f"  {marker} [bold]{name}[/bold]{tag}  [dim]— {detail}[/dim]")
    _print("\nSwitch with [cyan]heaven use <name>[/cyan] · "
           "delete with [cyan]heaven engage delete <name>[/cyan]")


@engage.command("delete")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def engage_delete(name: str, yes: bool) -> None:
    """Permanently delete an engagement (its scans, findings and scope).

    Removes the SQLite DB and its WAL sidecars. If the deleted engagement is the
    current selection, the sticky `heaven use` context and the web UI's active
    pointer are cleared so nothing keeps pointing at a store that no longer
    exists.
    """
    from heaven.engagement import (
        EngagementStore,
        clear_active_engagement,
        delete_engagement_store,
        get_active_engagement,
    )

    path = _engagement_db_path(name)
    if not path.exists():
        _print(f"[red]Engagement DB not found: {path}[/red]")
        sys.exit(2)

    try:
        stats = EngagementStore(path).stats()
        summary = (f"{stats.get('total_findings', 0)} findings, "
                   f"{stats.get('scans_run', 0)} scans")
    except Exception:  # noqa: BLE001
        summary = "unknown contents"
    if not yes:
        _print(f"[yellow]About to permanently delete[/yellow] "
               f"[bold]{name}[/bold] ({summary}) at [dim]{path}[/dim].")
        if not click.confirm("This cannot be undone. Continue?", default=False):
            _print("[dim]Aborted.[/dim]")
            return

    if not delete_engagement_store(path):
        _print(f"[red]Nothing was deleted for {name}.[/red]")
        sys.exit(1)

    # Drop any pointer that still names the now-deleted engagement.
    if get_current_engagement() == name:
        clear_current_engagement()
    if get_active_engagement() == name:
        clear_active_engagement()

    _print(f"[green]✓[/green] Deleted engagement [bold]{name}[/bold].")


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
