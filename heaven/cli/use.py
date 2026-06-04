"""HEAVEN — `heaven use` current-engagement selector.

Git-branch-style sticky context so operators stop retyping --engagement on
every command. The selection is stored per working directory in
./.heaven/current_engagement and is honoured by every command that resolves
an engagement DB (findings, scan, report, diff, watch, …).

Precedence (highest first):
    explicit --engagement flag  >  HEAVEN_ENGAGEMENT env  >  `heaven use`  >  default

Examples:
    heaven use acme-corp        # make acme-corp the active engagement
    heaven use                  # show current + list available
    heaven use --clear          # drop back to the default engagement
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import (
    _print,
    clear_current_engagement,
    get_current_engagement,
    set_current_engagement,
)


def _list_engagements() -> list[str]:
    """Names of engagements discoverable under ./engagements/*.db."""
    eng_dir = Path("engagements")
    if not eng_dir.is_dir():
        return []
    return sorted(p.stem for p in eng_dir.glob("*.db"))


@click.command(name="use")
@click.argument("engagement", required=False)
@click.option("--clear", "do_clear", is_flag=True,
              help="Clear the current-engagement context.")
def use(engagement: Optional[str], do_clear: bool) -> None:
    """Select the active engagement so you stop retyping --engagement.

    With no argument, shows the current selection and lists the engagements
    found under ./engagements/. The choice sticks per working directory.
    """
    if do_clear:
        if clear_current_engagement():
            _print("[green]✓[/green] Cleared current engagement. "
                   "Commands now use the default ([cyan]engagement.db[/cyan]).")
        else:
            _print("[dim]No current engagement was set.[/dim]")
        return

    available = _list_engagements()

    # No argument → status view
    if not engagement:
        current = get_current_engagement()
        if current:
            _print(f"Current engagement: [bold cyan]{current}[/bold cyan]")
        else:
            _print("[dim]No current engagement set "
                   "(using default engagement.db).[/dim]")
        if available:
            _print("\nAvailable engagements:")
            for name in available:
                marker = "[green]●[/green]" if name == current else " "
                _print(f"  {marker} {name}")
            _print("\nSwitch with: [cyan]heaven use <name>[/cyan]")
        else:
            _print("\n[dim]No engagements yet. Create one with:[/dim]")
            _print("  [cyan]heaven engage init <name> --client \"Acme\"[/cyan]")
        return

    # Set the engagement
    set_current_engagement(engagement)
    _print(f"[green]✓[/green] Active engagement set to "
           f"[bold cyan]{engagement}[/bold cyan].")

    if engagement not in available:
        db_path = Path("engagements") / f"{engagement}.db"
        _print(f"[yellow]![/yellow] No DB at [dim]{db_path}[/dim] yet — "
               f"create it with:")
        _print(f"  [cyan]heaven engage init {engagement} "
               f"--client \"<client>\"[/cyan]")
    else:
        _print("[dim]All engagement-aware commands now target it by default.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(use)
