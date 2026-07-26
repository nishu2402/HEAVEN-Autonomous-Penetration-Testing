"""HEAVEN — runtime capability probes.

These are optional feature-enablers that are **not** PATH binaries, so they
don't belong in ``tool_installer.TOOLS`` (which keys on ``shutil.which``).

Today this reports whether the Playwright **browser bundle** is installed. The
Playwright wheel ships in HEAVEN's base dependencies, but the ~150 MB Chromium
download is a separate step (``playwright install chromium`` — done
automatically by ``scripts/install.sh``). Without the browser, the
headless-browser DAST capabilities degrade gracefully to "detected/skipped":

  * the XSS **execution** proof (``heaven/vulnscan/exploit_proof.py``), and
  * the JS-rendered crawl (``heaven/recon/web_crawler.py``).

Operators previously had no way to tell whether that capability was actually
armed. ``heaven doctor`` and the web System-Health panel now surface it, shaped
exactly like the external-tool entries (``name`` / ``present`` / ``purpose`` /
``hint``) so both render it uniformly.

The status is reported honestly — ``present=True`` only when Playwright's own
resolved Chromium executable exists on disk. The probe runs in a short-lived
worker thread so it is safe to call from **both** the synchronous CLI and the
async web endpoint (Playwright's sync API refuses to start inside a running
asyncio loop).
"""

from __future__ import annotations

import glob
import os
import threading
import time
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("utils.runtime_capabilities")

# Cache the (present, detail) result briefly so repeated doctor/health calls
# don't re-spawn the Playwright driver, while still noticing a mid-session
# `playwright install` within the TTL.
_CACHE_TTL = 15.0
_PROBE_TIMEOUT = 8.0
_cache_ts = 0.0
_cache_val: Optional[tuple[bool, str]] = None

_INSTALL_HINT = "playwright install chromium"


def _chromium_via_api() -> Optional[tuple[bool, str]]:
    """Authoritative check via Playwright's own path resolution.

    Runs ``sync_playwright`` in a fresh thread (never the caller's, which may be
    driving an asyncio loop). ``chromium.executable_path`` returns the
    *would-be* path even when the browser isn't downloaded, so existence on disk
    is the real signal. Returns ``None`` when the probe can't complete
    (timeout/error) so the caller can fall back to a filesystem heuristic."""
    box: dict[str, object] = {}

    def _worker() -> None:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                ep = p.chromium.executable_path
                box["ok"] = bool(ep and os.path.exists(ep))
        except Exception as e:  # noqa: BLE001 — any failure → inconclusive
            box["err"] = repr(e)

    t = threading.Thread(target=_worker, name="pw-chromium-probe", daemon=True)
    t.start()
    t.join(_PROBE_TIMEOUT)
    if t.is_alive() or "err" in box:
        if "err" in box:
            logger.debug("playwright chromium probe error: %s", box["err"])
        return None
    ok = bool(box.get("ok"))
    detail = ("Chromium browser installed" if ok
              else f"browser bundle not downloaded — run `{_INSTALL_HINT}`")
    return ok, detail


def _chromium_via_filesystem() -> tuple[bool, str]:
    """Fallback heuristic: look for a downloaded chromium build under the
    resolved ``ms-playwright`` cache dir. Only used when the API probe above is
    inconclusive (timeout/error)."""
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env == "0":
        # Browsers live next to the package — not reliably locatable by path;
        # leave this to the authoritative API probe.
        return False, f"browser bundle not found — run `{_INSTALL_HINT}`"
    if env:
        # When set, this is Playwright's *only* browser location (no fallback to
        # the default cache dir), so honour that exactly.
        roots = [env]
    else:
        roots = [
            os.path.expanduser("~/Library/Caches/ms-playwright"),                 # macOS
            os.path.expanduser("~/.cache/ms-playwright"),                         # Linux
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright"),    # Windows
        ]
    for r in roots:
        if r and os.path.isdir(r) and (
            glob.glob(os.path.join(r, "chromium-*"))
            or glob.glob(os.path.join(r, "chromium_headless_shell-*"))
        ):
            return True, "Chromium browser present"
    return False, f"browser bundle not found — run `{_INSTALL_HINT}`"


def _chromium_status() -> tuple[bool, str]:
    # Is the wheel even importable? (It's in base deps, but stay defensive.)
    try:
        import playwright  # noqa: F401
    except Exception:  # noqa: BLE001
        return False, "playwright package not installed"
    api = _chromium_via_api()
    if api is not None:
        return api
    return _chromium_via_filesystem()


def _cached_chromium_status(use_cache: bool = True) -> tuple[bool, str]:
    global _cache_ts, _cache_val
    now = time.monotonic()
    if use_cache and _cache_val is not None and (now - _cache_ts) < _CACHE_TTL:
        return _cache_val
    val = _chromium_status()
    _cache_ts, _cache_val = now, val
    return val


def runtime_capabilities(use_cache: bool = True) -> list[dict]:
    """Optional runtime capabilities, shaped like the ``tool_installer`` entries
    (``name`` / ``present`` / ``purpose`` / ``hint``) so ``heaven doctor`` and
    the web System-Health panel render them uniformly."""
    present, detail = _cached_chromium_status(use_cache)
    return [{
        "name": "playwright-chromium",
        "present": present,
        "purpose": "Headless-browser DAST: XSS execution proof + JS-rendered crawl",
        "hint": "" if present else _INSTALL_HINT,
        "detail": detail,
    }]
