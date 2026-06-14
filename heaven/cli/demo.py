"""HEAVEN — `heaven demo` : load realistic sample data to explore the tool.

A fresh install opens to empty pages. `heaven demo` drops an example engagement
with a spread of critical→info findings into the same store the web dashboard
reads, so you can immediately explore Findings, Finding Detail, Kill Chain,
Coverage and Reports without running a real scan. Idempotent and offline.
"""

from __future__ import annotations

import click

from heaven.cli._helpers import _print

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


@click.command(name="demo")
@click.option("--engagement", default=None,
              help="Engagement to seed. Default: the one the web dashboard shows.")
def demo_cmd(engagement: str | None) -> None:
    """Load realistic sample data so every page is populated to explore.

    Writes an example engagement + findings to the same SQLite store the web UI
    reads, then tells you how to view it. Re-running is safe (it dedupes).
    Nothing is scanned — the targets are reserved/placeholder addresses.
    """
    from heaven.demo import DEMO_ENGAGEMENT, resolve_demo_store, seed_demo

    store = resolve_demo_store(engagement)
    result = seed_demo(store)

    _print(f"[green]✓ Loaded sample data[/green] into engagement "
           f"[bold]{DEMO_ENGAGEMENT}[/bold]  [dim]({store.db_path})[/dim]")
    by = result["by_severity"]
    parts = [f"{by[s]} {s}" for s in _SEV_ORDER if by.get(s)]
    _print(f"  [dim]{result['findings']} findings across {result['targets']} "
           f"targets[/dim]  ·  " + "  ".join(parts))
    _print("")
    _print("[bold]Explore it:[/bold]")
    _print("  [cyan]heaven serve[/cyan]            # open the web UI → Dashboard is now populated")
    _print("  [cyan]heaven findings[/cyan]         # list the sample findings in the terminal")
    _print("  [cyan]heaven report -o demo.html --framework OWASP_TOP10[/cyan]   # generate a report")
    _print("")
    _print("[dim]Sample data only — no systems were scanned. Re-run `heaven demo` "
           "anytime; it updates in place.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(demo_cmd)
