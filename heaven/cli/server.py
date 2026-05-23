"""HEAVEN — `heaven serve` command (FastAPI + Command Centre UI)."""

from __future__ import annotations

import sys

import click

from heaven.cli._helpers import _print, check_module_health
from heaven.utils.logger import print_banner


@click.command()
@click.option("--host", default="127.0.0.1",
              help="API server host (default: 127.0.0.1, use 0.0.0.0 only behind a TLS reverse proxy)")
@click.option("--port", default=8443, type=int, help="API server port")
def serve(host: str, port: int) -> None:
    """Start the HEAVEN API server and Command Centre."""
    print_banner()
    _print(f"[cyan]Starting HEAVEN API server on {host}:{port}[/cyan]")

    if host == "0.0.0.0":  # nosec B104 — intentional, user is warned below
        _print("[yellow]⚠  Binding to 0.0.0.0 — make sure you are behind a reverse proxy with TLS.[/yellow]")

    try:
        import uvicorn
        from heaven.api.server import create_app
        app = create_app()
        health = check_module_health()
        for mod, status in health.items():
            _print(f"  {'[green]OK[/green]' if status == 'OK' else '[yellow]' + status + '[/yellow]'} {mod}")
        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError:
        _print("[red]Error: uvicorn and fastapi required. Install with: pip install uvicorn fastapi[/red]")
        sys.exit(1)


def register(cli: click.Group) -> None:
    cli.add_command(serve)
