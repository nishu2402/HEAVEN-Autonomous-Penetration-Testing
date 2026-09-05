"""Runtime-capability probes — the Playwright browser readiness surfaced by
`heaven doctor` and the web System-Health panel.

The probe never launches a browser (it only checks whether Playwright's
resolved chromium executable exists on disk), and these tests stub that
resolution so the suite stays fast, offline, and deterministic — no driver is
ever spawned here.
"""
from __future__ import annotations

import logging
import sys

import heaven.utils.runtime_capabilities as rc


def _reset_cache():
    rc._cache_ts = 0.0
    rc._cache_val = None


def _by_name(caps, name):
    return next(c for c in caps if c["name"] == name)


def test_shape_and_armed(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(rc, "_chromium_status",
                        lambda: (True, "Chromium browser installed"))
    caps = rc.runtime_capabilities(use_cache=False)
    names = {c["name"] for c in caps}
    # Playwright + the local-LLM (Ollama) capability are both surfaced.
    assert {"playwright-chromium", "local-llm"} <= names
    c = _by_name(caps, "playwright-chromium")
    assert c["present"] is True
    assert c["hint"] == ""              # armed → no install hint
    assert "DAST" in c["purpose"]


def test_not_armed_offers_hint(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(
        rc, "_chromium_status",
        lambda: (False, "browser bundle not downloaded — run `playwright install chromium`"))
    c = _by_name(rc.runtime_capabilities(use_cache=False), "playwright-chromium")
    assert c["present"] is False
    assert c["hint"] == "playwright install chromium"
    assert "not downloaded" in c["detail"]


def test_missing_wheel_is_graceful(monkeypatch):
    # Defensive: even though playwright ships in base deps, an absent wheel must
    # degrade to an honest "not installed" rather than raising.
    _reset_cache()
    monkeypatch.setitem(sys.modules, "playwright", None)  # import → ImportError
    present, detail = rc._chromium_status()
    assert present is False
    assert "not installed" in detail


def test_filesystem_heuristic_finds_downloaded_browser(tmp_path, monkeypatch):
    (tmp_path / "chromium-1234").mkdir()
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    present, _ = rc._chromium_via_filesystem()
    assert present is True


def test_filesystem_heuristic_empty_dir_is_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    present, detail = rc._chromium_via_filesystem()
    assert present is False
    assert "playwright install chromium" in detail


def _log_record(msg, exc=None):
    r = logging.LogRecord("asyncio", logging.ERROR, "x.py", 1, msg, (), None)
    if exc is not None:
        r.exc_info = (type(exc), exc, None)
    return r


def test_teardown_filter_drops_only_playwright_noise():
    """The asyncio filter must hide Playwright's benign driver-teardown chatter
    (a browser probe / DAST proof leaves an init() future that ends in a
    TargetClosedError) while never masking a genuine asyncio error."""
    f = rc._PlaywrightTeardownFilter()

    # Playwright 'Task was destroyed' — the connection path is in the message.
    pw_task = _log_record(
        "Task was destroyed but it is pending!\n"
        "task: <Task coro=<Connection.run.<locals>.init() running at "
        "/x/playwright/_impl/_connection.py:344>>")
    assert f.filter(pw_task) is False

    # Playwright 'Future exception' — 'playwright' appears only in exc_info.
    class _PWErr(Exception):
        pass
    _PWErr.__module__ = "playwright._impl._errors"
    pw_future = _log_record(
        "Future exception was never retrieved\n"
        "future: <Future exception=TargetClosedError(...)>", exc=_PWErr("closed"))
    assert f.filter(pw_future) is False

    # A REAL non-Playwright pending task with the identical headline is KEPT.
    real_task = _log_record(
        "Task was destroyed but it is pending!\n"
        "task: <Task coro=<app.worker() running at /app/worker.py:20>>")
    assert f.filter(real_task) is True

    # Any unrelated asyncio error is KEPT.
    assert f.filter(_log_record("Exception in callback SomeHandler")) is True


def test_teardown_filter_installs_once():
    aio = logging.getLogger("asyncio")
    before = [x for x in aio.filters if isinstance(x, rc._PlaywrightTeardownFilter)]
    for x in before:  # start from a clean slate for a deterministic count
        aio.removeFilter(x)
    rc._teardown_filter_installed = False
    rc._install_playwright_teardown_filter()
    rc._install_playwright_teardown_filter()  # idempotent
    installed = [x for x in aio.filters if isinstance(x, rc._PlaywrightTeardownFilter)]
    assert len(installed) == 1


def test_cache_serves_prior_result(monkeypatch):
    _reset_cache()
    calls = {"n": 0}

    def _status():
        calls["n"] += 1
        return (True, "Chromium browser installed")

    monkeypatch.setattr(rc, "_chromium_status", _status)
    rc.runtime_capabilities(use_cache=True)
    rc.runtime_capabilities(use_cache=True)
    assert calls["n"] == 1              # second call served from cache
