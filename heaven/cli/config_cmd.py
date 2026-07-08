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


@config_grp.command(name="test-nvd")
def test_nvd_cmd() -> None:
    """Live-check NVD reachability + that NVD_API_KEY (if set) is valid.

    Makes one real lookup. NVD answers a good query with HTTP 200 (key valid or
    no key) but HTTP 404 when the key is rejected — so this tells you whether CVE
    enrichment will actually return results before you run a scan.
    """
    import asyncio

    from heaven.vulnscan.nvd_client import NVDClient

    async def _run() -> dict:
        client = NVDClient()
        try:
            return await client.test_connectivity()
        finally:
            await client.close()

    res = asyncio.run(_run())
    if json_output():
        emit_json(res)
        return
    if res.get("ok"):
        _print(f"[green]✓ NVD reachable[/green] — {res['reason']}")
        if res.get("sample_results") is not None:
            _print(f"  [dim]sample query returned {res['sample_results']} CVEs[/dim]")
    else:
        _print(f"[red]✗ NVD check failed[/red] — {res['reason']}")
        if res.get("status_code"):
            _print(f"  [dim]HTTP {res['status_code']}[/dim]")
        raise SystemExit(1)


@config_grp.command(name="test-llm")
@click.option("--live", is_flag=True,
              help="Make one real minimal completion to confirm the key works "
                   "end-to-end (a tiny billed call). Off by default.")
def test_llm_cmd(live: bool) -> None:
    """Check the LLM configuration used by every AI layer.

    Without ``--live`` this is the same cheap check as the web-UI Settings page:
    it confirms a provider is selected, a key is present and the SDK is importable
    — no billed call. With ``--live`` it sends a one-token prompt through the same
    gateway the AI layers use, so you can confirm the key actually works before a
    scan relies on it. HEAVEN runs fully without any of this (in-house fallbacks).
    """
    from heaven.ai.llm_gateway import LLMGateway

    gw = LLMGateway()
    res: dict = {
        "provider": gw.provider or None,
        "model": gw.model or None,
        "available": bool(gw.available),
        "reason": (
            "ready" if gw.available else
            "no provider/key configured" if not (gw.provider and gw.api_key) else
            "provider SDK not installed (pip install the provider extra)"
        ),
    }

    if live and gw.available:
        from heaven.ai.llm_gateway import LLMRequest
        resp = gw.complete(LLMRequest(
            prompt="Reply with the single word: pong",
            max_tokens=5, temperature=0.0, redact_secrets=False,
        ))
        res["live_ok"] = bool(resp.ok())
        res["latency_ms"] = round(resp.latency_ms, 1)
        res["live_reply"] = (resp.text or "").strip()[:40]
        if resp.error:
            res["live_error"] = resp.error

    if json_output():
        emit_json(res)
        if not res["available"] or (live and res.get("live_ok") is False):
            raise SystemExit(1)
        return

    if not res["available"]:
        _print(f"[yellow]· LLM not configured[/yellow] — {res['reason']}")
        _print("[dim]HEAVEN runs fully without it (in-house planning, triage & "
               "remediation). To enable: heaven config set ANTHROPIC_API_KEY[/dim]")
        raise SystemExit(1)

    _print(f"[green]✓ LLM ready[/green] — provider [bold]{res['provider']}[/bold], "
           f"model [bold]{res['model']}[/bold]")
    if live:
        if res.get("live_ok"):
            _print(f"  [green]✓ live round-trip[/green] — reply "
                   f"'{res['live_reply']}' in {res['latency_ms']} ms")
        else:
            _print(f"  [red]✗ live call failed[/red] — {res.get('live_error', 'unknown')}")
            raise SystemExit(1)
    else:
        _print("  [dim]Add --live to confirm the key with a real one-token call.[/dim]")


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
