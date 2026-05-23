"""HEAVEN — `heaven init-db` command (PostgreSQL schema init)."""

from __future__ import annotations

import asyncio

import click

from heaven.cli._helpers import _print
from heaven.utils.logger import print_banner


@click.command(name="init-db")
def init_db_cmd() -> None:
    """Initialise the PostgreSQL database schema (optional — core features use SQLite)."""
    print_banner()
    _print("[cyan]Initialising PostgreSQL schema...[/cyan]")
    _print("[dim]Note: PostgreSQL is optional. HEAVEN uses SQLite for engagement data by default.[/dim]")

    async def _init():
        from heaven.db.connection import init_db, close_all
        ok = await init_db()
        await close_all()
        return ok

    try:
        ok = asyncio.run(_init())
        if ok:
            _print("[green]PostgreSQL schema initialised successfully.[/green]")
        else:
            _print(
                "[yellow]PostgreSQL not available — HEAVEN will use SQLite for engagements.[/yellow]\n"
                "[dim]To enable PostgreSQL: set HEAVEN_DB_PASSWORD and run docker compose up -d postgres[/dim]"
            )
    except Exception as e:
        _print(f"[yellow]PostgreSQL init skipped:[/yellow] {e}")
        _print("[dim]HEAVEN's core features work without PostgreSQL.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(init_db_cmd)
