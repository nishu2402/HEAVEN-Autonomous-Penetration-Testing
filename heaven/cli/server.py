"""HEAVEN — `heaven serve` command (FastAPI + Command Centre UI)."""

from __future__ import annotations

import errno
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


def _port_available(host: str, port: int) -> bool:
    """Return True if ``host:port`` is free to bind (mirrors uvicorn's bind).

    Lets ``serve`` fail fast with a friendly message instead of booting the whole
    application and dying on uvicorn's raw ``[Errno 48] address already in use``.
    An actively-listening socket cannot be re-bound even with SO_REUSEADDR, so
    this reliably detects "a server is already running here". A rare check→bind
    race is harmless: uvicorn would then surface the genuine (now uncommon) error.
    """
    bind_host = host or "0.0.0.0"
    try:
        infos = socket.getaddrinfo(
            bind_host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
        )
    except socket.gaierror:
        return True  # can't resolve → let uvicorn produce the real error
    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(sockaddr)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            # Any other bind error (e.g. EACCES on a privileged <1024 port) is
            # not "already in use" — let uvicorn surface its own precise error.
            return True
    return True


def _browser_host(host: str) -> str:
    """Return a host a browser can actually reach.

    A server bound to 0.0.0.0 (all interfaces) or :: is not a routable address
    for a client — the loopback alias is. Everything else is used verbatim.
    """
    if host in ("0.0.0.0", "::", ""):  # "0.0.0.0" is a match value, not a bind
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
    # Not a bind: "0.0.0.0" here is a match value we rewrite *to* loopback so the
    # readiness probe dials localhost, never all-interfaces.
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

    # Pre-flight: if the port is already taken, stop now with a clear, actionable
    # message rather than booting the app and crashing on uvicorn's raw errno.
    if not _port_available(host, port):
        reachable = f"http://{_browser_host(host)}:{port}/"
        _print(f"[red]✗ Cannot start: {host}:{port} is already in use.[/red]")
        _print("[yellow]  Something is already listening there — most likely a HEAVEN "
               "server you started earlier.[/yellow]")
        _print("")
        _print("[dim]  Do one of these:[/dim]")
        _print(f"[dim]   • If that server is the one you want, just open[/dim] [cyan]{reachable}[/cyan]")
        _print(f"[dim]   • Start this one on a free port:[/dim] [cyan]heaven serve --port {port + 1}[/cyan]")
        _print("[dim]   • Or stop whatever holds the port, then retry:[/dim]")
        _print(f"[cyan]       lsof -ti tcp:{port} | xargs kill[/cyan]   [dim](macOS / Linux)[/dim]")
        sys.exit(1)

    _print(f"[cyan]Starting HEAVEN API server on {host}:{port}[/cyan]")

    if host == "0.0.0.0":  # intentional all-interfaces bind; user is warned below
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
