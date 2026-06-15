"""HEAVEN — `heaven config` : manage API keys & integration settings.

The CLI counterpart of the web-UI **Settings** page. Both read and write the
same ``.env`` (via :mod:`heaven.settings_catalog`), so a key set here shows up
in the browser and vice-versa — one source of truth.

  heaven config list                 # every key, grouped, with set/unset state
  heaven config get GEMINI_API_KEY   # masked value + where to get it
  heaven config set GEMINI_API_KEY   # prompts (hidden) then persists to .env
  heaven config set NVD_API_KEY xxx  # or pass the value inline
  heaven config unset SHODAN_API_KEY # remove a key
"""

from __future__ import annotations

import click

from heaven.cli._helpers import _print, emit_json, json_output
from heaven.settings_catalog import (
    SETTINGS,
    apply_settings,
    catalog_status,
    mask,
    spec_for,
)


@click.group(name="config")
def config_grp() -> None:
    """Manage API keys & integrations (shared with the web-UI Settings page)."""


@config_grp.command(name="list")
def list_cmd() -> None:
    """Show every configurable key, grouped, with whether it's set."""
    status = catalog_status()
    if json_output():
        emit_json(status)
        return
    _print(f"[dim]Source of truth: {status['env_path']}[/dim]\n")
    for group in status["groups"]:
        _print(f"[bold cyan]{group['name']}[/bold cyan]")
        for s in group["settings"]:
            if s["is_set"]:
                shown = s["masked"] if s["secret"] else (s["value"] or "")
                mark = f"[green]✓[/green] {s['key']} = [green]{shown}[/green]"
            else:
                mark = f"[dim]·[/dim] {s['key']} [dim](not set)[/dim]"
            _print(f"  {mark}")
        _print("")
    _print("[dim]Set one with:  heaven config set <KEY>[/dim]")


@config_grp.command(name="get")
@click.argument("key")
def get_cmd(key: str) -> None:
    """Show a single key's (masked) value + where to obtain it."""
    spec = spec_for(key)
    if spec is None:
        _print(f"[red]Unknown key:[/red] {key}")
        _print("[dim]Run `heaven config list` to see valid keys.[/dim]")
        raise SystemExit(1)
    import os
    raw = (os.environ.get(key) or "").strip()
    shown = (mask(raw) if spec.secret else raw) if raw else "[dim](not set)[/dim]"
    _print(f"[bold]{spec.label}[/bold]  ([dim]{spec.group}[/dim])")
    _print(f"  {key} = {shown}")
    _print(f"  [dim]{spec.help}[/dim]")
    if spec.url:
        _print(f"  [dim]Get it: {spec.url}[/dim]")


@config_grp.command(name="set")
@click.argument("key")
@click.argument("value", required=False)
def set_cmd(key: str, value: str | None) -> None:
    """Set KEY to VALUE (prompts securely if VALUE is omitted)."""
    spec = spec_for(key)
    if spec is None:
        _print(f"[red]Unknown key:[/red] {key}")
        _print("[dim]Run `heaven config list` to see valid keys.[/dim]")
        raise SystemExit(1)
    if value is None:
        if spec.url:
            _print(f"[dim]Get it: {spec.url}[/dim]")
        value = click.prompt(spec.label, hide_input=spec.secret, default="",
                             show_default=False)
    result = apply_settings({key: value})
    if result["changed"]:
        action = "Unset" if not value.strip() else "Set"
        _print(f"[green]✓ {action}[/green] {key}  [dim]→ {result['status']['env_path']}[/dim]")
        _print("[dim]Live now for the CLI; restart `heaven serve` if it's running.[/dim]")
    else:
        _print(f"[dim]{key} unchanged (same value).[/dim]")


@config_grp.command(name="unset")
@click.argument("key")
def unset_cmd(key: str) -> None:
    """Remove KEY from the .env file."""
    if spec_for(key) is None:
        _print(f"[red]Unknown key:[/red] {key}")
        raise SystemExit(1)
    result = apply_settings({key: ""})
    if result["changed"]:
        _print(f"[green]✓ Removed[/green] {key}")
    else:
        _print(f"[dim]{key} was not set.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(config_grp)


# Re-export so other modules / tests can introspect the catalog by importing
# from the CLI surface if they prefer.
__all__ = ["config_grp", "register", "SETTINGS"]
