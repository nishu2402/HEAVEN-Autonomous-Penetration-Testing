"""HEAVEN — `heaven serve` command (FastAPI + Command Centre UI)."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser

import click

from heaven.cli._helpers import _print, check_module_health
from heaven.utils.logger import get_logger, print_banner

logger = get_logger("cli.serve")


def _browser_host(host: str) -> str:
    """Return a host a browser can actually reach.

    A server bound to 0.0.0.0 (all interfaces) or :: is not a routable address
    for a client — the loopback alias is. Everything else is used verbatim.
    """
    if host in ("0.0.0.0", "::", ""):  # nosec B104 — mapping bind-any → loopback
        return "127.0.0.1"
    return host


def _wait_and_open(host: str, port: int, url: str, timeout: float = 20.0) -> None:
    """Poll host:port until it accepts a TCP connection, then open ``url``.

    Runs in a daemon thread so it never blocks the server, and only opens the
    browser once uvicorn is genuinely listening (avoids a race where the tab
    loads before the socket is up). Any failure is logged and swallowed — the
    server must keep running even if no browser is available (e.g. headless).
    """
    deadline = time.monotonic() + timeout
    connect_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((connect_host, port), timeout=1.0):
                break
        except OSError:
            time.sleep(0.25)
    else:
        logger.debug("serve: server did not come up within %.0fs; skipping browser open", timeout)
        return
    try:
        if webbrowser.open(url):
            _print(f"[green]✓ Opened HEAVEN Command Centre in your browser →[/green] [cyan]{url}[/cyan]")
        else:
            _print(f"[yellow]Could not launch a browser automatically. Open manually →[/yellow] [cyan]{url}[/cyan]")
    except Exception as exc:  # pragma: no cover - platform webbrowser quirks
        logger.debug("serve: webbrowser.open failed: %s", exc)
        _print(f"[yellow]Open the Command Centre manually →[/yellow] [cyan]{url}[/cyan]")


@click.command()
@click.option("--host", default="127.0.0.1",
              help="API server host (default: 127.0.0.1, use 0.0.0.0 only behind a TLS reverse proxy)")
@click.option("--port", default=8443, type=int, help="API server port")
@click.option("--open/--no-open", "open_browser", default=True,
              help="Open the Command Centre in your browser once the server is up (default: on).")
def serve(host: str, port: int, open_browser: bool) -> None:
    """Start the HEAVEN API server and Command Centre."""
    print_banner()
    _print(f"[cyan]Starting HEAVEN API server on {host}:{port}[/cyan]")

    if host == "0.0.0.0":  # nosec B104 — intentional, user is warned below
        _print("[yellow]⚠  Binding to 0.0.0.0 — make sure you are behind a reverse proxy with TLS.[/yellow]")

    url = f"http://{_browser_host(host)}:{port}/"

    try:
        import uvicorn
        from heaven.api.server import create_app
        app = create_app()
        health = check_module_health()
        for mod, status in health.items():
            _print(f"  {'[green]OK[/green]' if status == 'OK' else '[yellow]' + status + '[/yellow]'} {mod}")

        # Honour a headless environment: opening a browser on a server/CI box is
        # pointless and can hang. Skip when there is no display and we're not on
        # macOS/Windows (which manage the browser without $DISPLAY).
        headless = (
            sys.platform not in ("darwin", "win32")
            and not os.environ.get("DISPLAY")
            and not os.environ.get("WAYLAND_DISPLAY")
        )
        if open_browser and not headless:
            _print(f"[dim]The Command Centre will open at {url} once the server is ready…[/dim]")
            threading.Thread(
                target=_wait_and_open, args=(host, port, url), daemon=True
            ).start()
        elif open_browser and headless:
            _print(f"[dim]Headless environment detected — open the Command Centre manually → {url}[/dim]")

        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError:
        _print("[red]Error: uvicorn and fastapi required. Install with: pip install uvicorn fastapi[/red]")
        sys.exit(1)


def register(cli: click.Group) -> None:
    cli.add_command(serve)
