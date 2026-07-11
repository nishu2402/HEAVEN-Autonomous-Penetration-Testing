"""Tests for `heaven serve` auto-open-browser behaviour.

Covers the browser-host mapping, the port-poll-then-open helper (against a real
loopback socket), and that the --open/--no-open flag actually gates whether a
browser is launched — all without ever starting uvicorn.
"""
from __future__ import annotations

import socket
import threading
import time

from click.testing import CliRunner

from heaven.cli import server as srv


# ── _browser_host ────────────────────────────────────────────────────────────
def test_browser_host_maps_bind_any_to_loopback():
    assert srv._browser_host("0.0.0.0") == "127.0.0.1"
    assert srv._browser_host("::") == "127.0.0.1"
    assert srv._browser_host("") == "127.0.0.1"


def test_browser_host_preserves_real_host():
    assert srv._browser_host("127.0.0.1") == "127.0.0.1"
    assert srv._browser_host("10.0.0.5") == "10.0.0.5"
    assert srv._browser_host("example.internal") == "example.internal"


# ── _wait_and_open ───────────────────────────────────────────────────────────
def test_wait_and_open_fires_once_socket_is_up(monkeypatch):
    """It should poll until the port accepts a connection, then open exactly once."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    port = lsock.getsockname()[1]
    lsock.listen(1)

    opened: list[str] = []
    monkeypatch.setattr(srv.webbrowser, "open", lambda u: opened.append(u) or True)
    try:
        srv._wait_and_open("127.0.0.1", port, f"http://127.0.0.1:{port}/", timeout=5.0)
    finally:
        lsock.close()

    assert opened == [f"http://127.0.0.1:{port}/"]


def test_wait_and_open_gives_up_when_nothing_listens(monkeypatch):
    """No server → the browser is never opened (and it does not hang forever)."""
    # An unbound ephemeral port: bind to grab a free one, then close it.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    opened: list[str] = []
    monkeypatch.setattr(srv.webbrowser, "open", lambda u: opened.append(u) or True)
    start = time.monotonic()
    srv._wait_and_open("127.0.0.1", port, f"http://127.0.0.1:{port}/", timeout=0.75)
    elapsed = time.monotonic() - start

    assert opened == []
    assert elapsed < 3.0  # bounded by the timeout, did not spin forever


def test_wait_and_open_swallows_browser_failure(monkeypatch):
    """A webbrowser backend that raises must not propagate out of the thread."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    port = lsock.getsockname()[1]
    lsock.listen(1)

    def _boom(_url):
        raise RuntimeError("no display")

    monkeypatch.setattr(srv.webbrowser, "open", _boom)
    try:
        srv._wait_and_open("127.0.0.1", port, f"http://127.0.0.1:{port}/", timeout=5.0)
    finally:
        lsock.close()
    # Reaching here without an exception is the assertion.


# ── CLI flag wiring (uvicorn stubbed — the server never actually starts) ──────
def _patch_serve_deps(monkeypatch, threads_started: list):
    """Stub uvicorn.run + create_app + health so `serve` returns immediately, and
    record any browser-opener thread that gets started."""
    monkeypatch.setattr(srv, "check_module_health", lambda: {})

    class _FakeUvicorn:
        @staticmethod
        def run(*_a, **_k):
            return None

    import sys
    import types
    fake = types.ModuleType("uvicorn")
    fake.run = _FakeUvicorn.run
    monkeypatch.setitem(sys.modules, "uvicorn", fake)

    fake_api = types.ModuleType("heaven.api.server")
    fake_api.create_app = lambda: object()
    monkeypatch.setitem(sys.modules, "heaven.api.server", fake_api)

    real_thread = srv.threading.Thread

    def _record_thread(*a, **k):
        t = real_thread(*a, **k)
        threads_started.append(t)
        return t

    monkeypatch.setattr(srv.threading, "Thread", _record_thread)
    # Force the non-headless branch so the flag alone decides.
    monkeypatch.setattr(srv.sys, "platform", "darwin")


def test_serve_no_open_does_not_start_browser_thread(monkeypatch):
    threads: list[threading.Thread] = []
    _patch_serve_deps(monkeypatch, threads)
    r = CliRunner().invoke(srv.serve, ["--no-open", "--port", "9"])
    assert r.exit_code == 0, r.output
    assert threads == []


def test_serve_default_starts_browser_thread(monkeypatch):
    threads: list[threading.Thread] = []
    _patch_serve_deps(monkeypatch, threads)
    # Neuter the opener target so the recorded thread does no real work.
    monkeypatch.setattr(srv, "_wait_and_open", lambda *a, **k: None)
    r = CliRunner().invoke(srv.serve, ["--port", "9"])
    assert r.exit_code == 0, r.output
    assert len(threads) == 1
    assert threads[0].daemon is True
