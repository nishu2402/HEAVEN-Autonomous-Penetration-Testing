"""HEAVEN — `heaven quickstart` : zero → ready in one command.

The single friendliest entry point for a brand-new user. It:
  1. ensures a ``.env`` exists (generating a strong admin password if missing),
  2. loads realistic sample data so every page is populated,
  3. prints exactly what to do next (or launches the web UI with ``--serve``).

Everything it does is also doable piecemeal (`heaven init`, `heaven demo`,
`heaven serve`) — quickstart just chains them so there's nothing to remember.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import click

from heaven.cli._helpers import _print, emit_json, json_output


@click.command(name="quickstart")
@click.option("--serve", "do_serve", is_flag=True,
              help="Launch the web UI immediately after setup.")
@click.option("--no-demo", is_flag=True, help="Skip loading sample data.")
@click.pass_context
def quickstart_cmd(ctx: click.Context, do_serve: bool, no_demo: bool) -> None:
    """Get from a fresh clone to a populated dashboard in one step."""
    from heaven.cli.init import _load_env, _write_env

    env_path = Path(".env").resolve()
    existing = _load_env(env_path)
    created = False
    generated_pw = None
    admin_user = existing.get("HEAVEN_ADMIN_USERNAME") or "admin"

    if not existing.get("HEAVEN_ADMIN_PASSWORD"):
        values = dict(existing)
        values["HEAVEN_ADMIN_USERNAME"] = admin_user
        generated_pw = secrets.token_urlsafe(18)
        values["HEAVEN_ADMIN_PASSWORD"] = generated_pw
        values.setdefault("HEAVEN_DB_PASSWORD", secrets.token_urlsafe(18))
        _write_env(env_path, values)
        # Make the new values live for this process so demo/serve see them.
        os.environ["HEAVEN_ADMIN_USERNAME"] = admin_user
        os.environ["HEAVEN_ADMIN_PASSWORD"] = values["HEAVEN_ADMIN_PASSWORD"]
        os.environ["HEAVEN_DB_PASSWORD"] = values["HEAVEN_DB_PASSWORD"]
        created = True

    # Load sample data so the dashboard isn't empty on first open.
    seeded = 0
    if not no_demo:
        from heaven.demo import resolve_demo_store, seed_demo
        seeded = seed_demo(resolve_demo_store())["findings"]

    if json_output():
        emit_json({
            "env_created": created, "env_path": str(env_path),
            "admin_username": admin_user, "admin_password": generated_pw,
            "demo_findings": seeded,
        })
        return

    _print("[bold cyan]🚀 HEAVEN quickstart[/bold cyan]\n")
    if created:
        _print(f"[green]✓ Created[/green] {env_path}")
        _print(f"  Web UI login:  [bold]{admin_user}[/bold] / [bold]{generated_pw}[/bold]")
        _print("  [dim](saved in .env — change it anytime in the web UI → Settings)[/dim]")
    else:
        _print(f"[green]✓ Using existing[/green] {env_path}  [dim](admin: {admin_user})[/dim]")
    if seeded:
        _print(f"[green]✓ Loaded[/green] {seeded} sample findings — every page is populated to explore")
    _print("")

    if do_serve:
        _print("[bold]Starting the web UI…[/bold]  [dim](Ctrl-C to stop)[/dim]\n")
        from heaven.cli.server import serve
        ctx.invoke(serve)
        return

    _print("[bold]Next:[/bold]")
    _print("  [cyan]heaven serve[/cyan]    # open the web UI → http://localhost:8443, then sign in")
    _print("  [dim]Explore the sample data, then run a real scan:[/dim]")
    _print("  [cyan]heaven scan -u https://target.example.com --i-have-authorization[/cyan]")


def register(cli: click.Group) -> None:
    cli.add_command(quickstart_cmd)
