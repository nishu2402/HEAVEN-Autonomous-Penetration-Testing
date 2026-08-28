"""HEAVEN — `heaven ai` command group: local-LLM setup + management.

Makes a fast, private, rate-limit-free local model a one-command affair:

    heaven ai setup            # detect Ollama, pull the default model, wire .env
    heaven ai models           # list installed local models
    heaven ai pull qwen2.5:7b  # pull a specific model
    heaven ai test             # live-test the current LLM config
    heaven ai status           # provider/model + local runtime health

All of it shares the same gateway + settings the CLI/API/web use, so a model set
here is immediately live everywhere.
"""

from __future__ import annotations

import subprocess  # nosec B404 -- runs the vetted `ollama` installer/CLI, fixed argv
from typing import Optional

import click

from heaven.cli._helpers import _print


@click.group("ai")
def ai_cmd() -> None:
    """Local LLM (Ollama / OpenAI-compatible) setup & management."""


@ai_cmd.command("status")
def ai_status() -> None:
    """Show the active LLM provider/model and local-runtime health."""
    from heaven.ai import local_llm
    from heaven.ai.llm_gateway import get_gateway
    gw = get_gateway()
    _print("[bold cyan]LLM gateway[/bold cyan]")
    if gw.available:
        _print(f"  [green]✓[/green] provider [bold]{gw.provider}[/bold] · model [bold]{gw.model}[/bold]")
    else:
        reason = gw._init_error or "not configured"
        _print(f"  [yellow]·[/yellow] not ready — {reason}")
    if gw.fallback_provider:
        _print(f"  [dim]fallback provider: {gw.fallback_provider}[/dim]")

    st = local_llm.local_status()
    _print("\n[bold cyan]Local runtime (Ollama)[/bold cyan]")
    _print(f"  installed:  {'yes' if st['installed'] else 'no'}")
    _print(f"  host:       {st['host']}")
    _print(f"  reachable:  {'yes' if st['reachable'] else 'no'}")
    if st["models"]:
        _print(f"  models:     {', '.join(st['models'])}")
    else:
        _print("  models:     [dim](none pulled)[/dim]")
    if not st["installed"]:
        _print(f"\n  [dim]Install Ollama:[/dim] {local_llm.install_hint()}")
    _print(f"\n  [dim]Recommended default:[/dim] {st['default_model']}  "
           f"[dim](run: heaven ai setup)[/dim]")


@ai_cmd.command("models")
@click.option("--provider", "-p", "provider", default=None,
              help="anthropic | openai | gemini | deepseek | ollama | local. "
                   "Defaults to the active provider, else Ollama.")
def ai_models(provider: Optional[str]) -> None:
    """List the models a provider will actually serve (discovered live).

    With no --provider this lists the active provider's models (or Ollama's pulled
    tags if none is configured). For a cloud provider it queries that provider's
    live models API using your key, so you see every current model, not a fixed
    short-list; the curated recommended picks are marked with a star.
    """
    import os

    from heaven.ai import llm_gateway as gw
    from heaven.ai import local_llm

    p = (provider or os.environ.get("HEAVEN_LLM_PROVIDER") or "ollama").lower()

    # Ollama keeps its friendly "is it installed / reachable" guidance.
    if p == "ollama":
        if not local_llm.is_ollama_installed():
            _print(f"[yellow]Ollama not installed.[/yellow] {local_llm.install_hint()}")
            return
        if not local_llm.ollama_reachable():
            _print("[yellow]Ollama server not reachable.[/yellow] Start it with "
                   "[cyan]ollama serve[/cyan] (or launch the Ollama app).")
            return

    key = os.environ.get(gw.PROVIDER_KEY_ENVS.get(p, ""), "")
    # One resolver (shared with the web picker): live where a key/runtime allows,
    # else the broader offline catalog, else the curated short-list.
    models, source, _live_n = gw.resolve_picker_models(p)

    if not models:
        if p == "ollama":
            _print("[dim]No models pulled yet.[/dim] Try: "
                   f"[cyan]heaven ai pull {local_llm.DEFAULT_OLLAMA_MODEL}[/cyan]")
        else:
            _print(f"[dim]No models found for provider '{p}'.[/dim]")
        return

    default = gw.PROVIDER_DEFAULT_MODELS.get(p, "")
    _print(f"[bold]{p} models[/bold] [dim]({len(models)}, {source})[/dim]:")
    for m in models:
        star = "[green]★[/green] " if m.get("recommended") else "  "
        is_default = " [dim](default)[/dim]" if m["id"] == default else ""
        note = f" [dim]— {m['note']}[/dim]" if m.get("note") else ""
        _print(f"  {star}{m['id']}{is_default}{note}")
    # If we're on the offline catalog because no key is set, say how to go live.
    if source == "catalog" and gw.PROVIDER_KEY_ENVS.get(p) and not key:
        _print(f"[dim]Showing the known catalog. Set {gw.PROVIDER_KEY_ENVS[p]} "
               f"([cyan]heaven config[/cyan]) to list {p}'s live roster.[/dim]")


@ai_cmd.command("pull")
@click.argument("model")
def ai_pull(model: str) -> None:
    """Pull an Ollama MODEL (e.g. qwen2.5:7b, llama3.1:8b)."""
    from heaven.ai import local_llm
    if not local_llm.is_ollama_installed():
        _print(f"[red]Ollama not installed.[/red] {local_llm.install_hint()}")
        raise SystemExit(1)
    _print(f"[cyan]Pulling {model}…[/cyan] (this can take a few minutes)")
    ok = local_llm.pull_model(model, on_output=lambda line: _print(f"[dim]{line}[/dim]"))
    if ok:
        _print(f"[green]✓ Pulled {model}[/green]")
    else:
        _print(f"[red]✗ Failed to pull {model}[/red]")
        raise SystemExit(1)


@ai_cmd.command("test")
def ai_test() -> None:
    """Live-test the current LLM configuration (one tiny real completion)."""
    from heaven.ai.llm_gateway import LLMGateway, LLMRequest, reset_gateway
    reset_gateway()
    gw = LLMGateway()
    if not gw.available:
        _print(f"[yellow]Not ready:[/yellow] {gw._init_error or 'no provider configured'}")
        _print("[dim]Run [cyan]heaven ai setup[/cyan] for a local model, or add a "
               "key with [cyan]heaven config set[/cyan].[/dim]")
        raise SystemExit(1)
    _print(f"[dim]Testing {gw.provider} ({gw.model})…[/dim]")
    resp = gw.complete(LLMRequest(prompt="Reply with exactly the word: OK",
                                  max_tokens=16, temperature=0))
    if resp.ok():
        _print(f"[green]✓ Ready[/green] — live reply in {resp.latency_ms:.0f}ms "
               f"([bold]{gw.provider}[/bold] / {gw.model})")
    else:
        _print(f"[red]✗ Configured but the call failed:[/red] {resp.error}")
        raise SystemExit(1)


@ai_cmd.command("setup")
@click.option("--provider", type=click.Choice(["ollama", "local"]), default="ollama",
              show_default=True, help="Local runtime to configure.")
@click.option("--model", default=None,
              help="Model id/tag (default: qwen2.5:7b for Ollama).")
@click.option("--base-url", default=None,
              help="OpenAI-compatible endpoint for --provider local (e.g. http://localhost:1234/v1).")
@click.option("--install", is_flag=True, help="Attempt to install Ollama if missing.")
@click.option("--yes", "-y", is_flag=True, help="Don't prompt (pull/install without asking).")
def ai_setup(provider: str, model: Optional[str], base_url: Optional[str],
             install: bool, yes: bool) -> None:
    """Set up a local LLM end-to-end and wire it into HEAVEN's .env.

    For Ollama (default): checks it's installed, pulls the model if needed, saves
    the config, and live-tests it. For a generic OpenAI-compatible server, pass
    --provider local --base-url … --model …."""
    from heaven.ai import local_llm
    from heaven.settings_catalog import apply_settings

    if provider == "local":
        if not base_url:
            _print("[red]--base-url is required for --provider local[/red] "
                   "(e.g. http://localhost:1234/v1)")
            raise SystemExit(1)
        if not model:
            _print("[red]--model is required for --provider local[/red] "
                   "(your served model id)")
            raise SystemExit(1)
        apply_settings({
            "HEAVEN_LLM_PROVIDER": "local",
            "HEAVEN_LLM_BASE_URL": base_url,
            "HEAVEN_LLM_MODEL": model,
        })
        _print(f"[green]✓ Configured[/green] local endpoint {base_url} (model {model})")
        _live_test()
        return

    # ── Ollama path ──
    model = model or local_llm.DEFAULT_OLLAMA_MODEL
    if not local_llm.is_ollama_installed():
        _print(f"[yellow]Ollama is not installed.[/yellow]\n  Install: "
               f"{local_llm.install_hint()}")
        cmd = local_llm.install_command()
        if install and cmd and (yes or click.confirm(f"\nRun `{' '.join(cmd)}` now?", default=True)):
            _print(f"[cyan]Installing Ollama…[/cyan] ({' '.join(cmd)})")
            try:
                subprocess.run(cmd, check=True)  # nosec B603 -- fixed argv, no shell
            except (subprocess.CalledProcessError, OSError) as e:
                _print(f"[red]Install failed:[/red] {e}. Install manually, then re-run "
                       "[cyan]heaven ai setup[/cyan].")
                raise SystemExit(1)
        else:
            _print("\n[dim]Install Ollama, then re-run [cyan]heaven ai setup[/cyan].[/dim]")
            raise SystemExit(1)

    if not local_llm.ollama_reachable():
        _print("[yellow]Ollama is installed but the server isn't reachable.[/yellow]")
        _print("  Start it with [cyan]ollama serve[/cyan] (or launch the Ollama app), "
               "then re-run this.")
        # Not fatal — we can still write config so it works once the server is up.

    have = set(local_llm.list_models())
    if model not in have and not any(m.split(":")[0] == model.split(":")[0] for m in have):
        if yes or click.confirm(f"Pull model [{model}] now? (a few hundred MB–GB)", default=True):
            _print(f"[cyan]Pulling {model}…[/cyan]")
            if not local_llm.pull_model(model, on_output=lambda ln: _print(f"[dim]{ln}[/dim]")):
                _print(f"[yellow]Could not pull {model}. You can pull it later with "
                       f"[cyan]heaven ai pull {model}[/cyan].[/yellow]")
        else:
            _print(f"[dim]Skipped pull. Later: [cyan]heaven ai pull {model}[/cyan][/dim]")

    apply_settings({
        "HEAVEN_LLM_PROVIDER": "ollama",
        "HEAVEN_LLM_MODEL": model,
        "HEAVEN_OLLAMA_HOST": local_llm.ollama_host(),
    })
    _print(f"[green]✓ Configured[/green] provider [bold]ollama[/bold], model "
           f"[bold]{model}[/bold] → saved to .env (live everywhere).")
    _live_test()


def _live_test() -> None:
    """Reset the gateway and make one tiny real call so setup ends with proof."""
    from heaven.ai.llm_gateway import LLMGateway, LLMRequest, reset_gateway
    reset_gateway()
    gw = LLMGateway()
    if not gw.available:
        _print(f"[yellow]Saved, but the gateway isn't ready yet:[/yellow] "
               f"{gw._init_error or 'unknown'}")
        return
    _print("[dim]Testing…[/dim]")
    resp = gw.complete(LLMRequest(prompt="Reply with exactly the word: OK",
                                  max_tokens=16, temperature=0))
    if resp.ok():
        _print(f"[green]✓ Local AI is live[/green] — reply in {resp.latency_ms:.0f}ms. "
               "Try [cyan]heaven chat[/cyan].")
    else:
        _print(f"[yellow]Saved, but the test call failed:[/yellow] {resp.error}")
        _print("  [dim]Make sure the model is pulled and the server is running.[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(ai_cmd)
