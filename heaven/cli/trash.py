"""HEAVEN — Recycle Bin CLI group (`heaven trash`).

Deleting a scan or an engagement moves it to the Recycle Bin (see `heaven engage
delete` and the web UI). These commands review what is in the Bin and either
restore an item or delete it permanently. The same store backs the web Bin page.
"""

from __future__ import annotations

import sys

import click

from heaven.cli._helpers import _print


@click.group()
def trash() -> None:
    """Review and manage deleted scans and engagements (the Recycle Bin)."""


@trash.command("list")
def trash_list() -> None:
    """List items in the Recycle Bin, newest first."""
    from heaven import trash as trash_mod

    items = trash_mod.list_items()
    if not items:
        _print("[dim]The Recycle Bin is empty.[/dim]")
        return
    _print(f"[cyan]Recycle Bin[/cyan] [dim]({len(items)} item(s), kept "
           f"{trash_mod.retention_days()} days)[/dim]:")
    for it in items:
        kind = it["kind"]
        icon = "📁" if kind == "engagement" else "🔍"
        summ = it.get("summary", {})
        if kind == "engagement":
            detail = (f"{summ.get('findings', 0)} findings, "
                      f"{summ.get('scans', 0)} scans")
        else:
            detail = (f"engagement {it.get('engagement')!r} · "
                      f"{summ.get('findings', 0)} findings")
        _print(f"  {icon} [bold]{it['label']}[/bold] [dim]({kind})[/dim]  "
               f"[dim]{detail} · deleted {it['deleted_at']} · "
               f"by {it.get('deleted_by') or '?'} · id {it['id']}[/dim]")
    _print("\nRestore with [cyan]heaven trash restore <id>[/cyan] · "
           "delete one permanently with [cyan]heaven trash purge <id>[/cyan] · "
           "empty the Bin with [cyan]heaven trash empty[/cyan]")


@trash.command("restore")
@click.argument("trash_id")
def trash_restore(trash_id: str) -> None:
    """Restore a trashed scan or engagement by its id (from `heaven trash list`)."""
    from heaven import trash as trash_mod

    if not trash_mod.is_valid_trash_id(trash_id):
        _print(f"[red]Invalid trash id: {trash_id}[/red]")
        sys.exit(2)
    try:
        result = trash_mod.restore(trash_id)
    except KeyError:
        _print(f"[red]No Bin item with id {trash_id}.[/red]")
        sys.exit(1)
    except FileNotFoundError as e:
        _print(f"[red]Owning engagement '{e}' no longer exists; "
               f"restore it from the Bin first.[/red]")
        sys.exit(1)

    if result["kind"] == "engagement":
        extra = " [dim](renamed, the original name was taken)[/dim]" if result.get("renamed") else ""
        _print(f"[green]✓[/green] Restored engagement "
               f"[bold]{result['restored']}[/bold]{extra}.")
    else:
        _print(f"[green]✓[/green] Restored scan [bold]{result['restored']}[/bold] "
               f"into engagement [bold]{result.get('engagement')}[/bold].")


@trash.command("purge")
@click.argument("trash_id")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def trash_purge(trash_id: str, yes: bool) -> None:
    """Permanently delete ONE item from the Bin by id. This cannot be undone."""
    from heaven import trash as trash_mod

    if not trash_mod.is_valid_trash_id(trash_id):
        _print(f"[red]Invalid trash id: {trash_id}[/red]")
        sys.exit(2)
    item = trash_mod.get_item(trash_id)
    if item is None:
        _print(f"[red]No Bin item with id {trash_id}.[/red]")
        sys.exit(1)
    if not yes and not click.confirm(
            f"Permanently delete '{item['label']}'? This cannot be undone.",
            default=False):
        _print("[dim]Aborted.[/dim]")
        return
    trash_mod.purge(trash_id)
    _print(f"[green]✓[/green] Permanently deleted [bold]{item['label']}[/bold].")


@trash.command("empty")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def trash_empty(yes: bool) -> None:
    """Permanently delete EVERY item in the Bin. This cannot be undone."""
    from heaven import trash as trash_mod

    items = trash_mod.list_items()
    if not items:
        _print("[dim]The Recycle Bin is already empty.[/dim]")
        return
    if not yes and not click.confirm(
            f"Permanently delete all {len(items)} item(s) in the Bin? "
            "This cannot be undone.", default=False):
        _print("[dim]Aborted.[/dim]")
        return
    count = trash_mod.empty()
    _print(f"[green]✓[/green] Emptied the Recycle Bin ({count} item(s)).")


def register(cli: click.Group) -> None:
    cli.add_command(trash)
