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

import gc
import glob
import logging
import os
import threading
import time
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("utils.runtime_capabilities")


class _PlaywrightTeardownFilter(logging.Filter):
    """Suppress Playwright's benign driver-teardown chatter on the asyncio logger.

    Probing the browser (``chromium.executable_path``) and the headless-browser
    DAST provers spin up Playwright's async driver connection. Stopping that
    connection leaves an ``init()`` future that ends in a harmless
    ``TargetClosedError``; asyncio logs it at garbage-collection time as
    "Task was destroyed but it is pending!" / "Future exception was never
    retrieved". The useful result is already in hand, so these are pure stderr
    noise. This filter drops *only* those two exact records when they are
    attributable to Playwright (by the connection path in the message, or a
    Playwright exception in ``exc_info``); every other asyncio error passes
    through untouched.
    """

    _MARKERS = ("Task was destroyed but it is pending",
                "Future exception was never retrieved")

    def filter(self, record: logging.LogRecord) -> bool:  # True == keep
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — never let the filter itself raise
            return True
        if not any(m in msg for m in self._MARKERS):
            return True
        if "playwright" in msg.lower():
            return False
        exc = record.exc_info[1] if record.exc_info else None
        if exc is not None and type(exc).__module__.split(".", 1)[0] == "playwright":
            return False
        return True


_teardown_filter_installed = False


def _install_playwright_teardown_filter() -> None:
    """Attach :class:`_PlaywrightTeardownFilter` to the asyncio logger once."""
    global _teardown_filter_installed
    if _teardown_filter_installed:
        return
    logging.getLogger("asyncio").addFilter(_PlaywrightTeardownFilter())
    _teardown_filter_installed = True

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
        finally:
            # Flush Playwright's driver-teardown futures now, while the
            # suppression filter is active, so their del-time asyncio noise is
            # dropped here instead of surfacing later on an unrelated GC pass.
            gc.collect()

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
    # Silence Playwright's benign driver-teardown chatter before the probe (and
    # any later headless-browser proof) can emit it to stderr.
    _install_playwright_teardown_filter()
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
    caps = [{
        "name": "playwright-chromium",
        "present": present,
        "purpose": "Headless-browser DAST: XSS execution proof + JS-rendered crawl",
        "hint": "" if present else _INSTALL_HINT,
        "detail": detail,
    }]

    # Local LLM runtime (Ollama) — private, rate-limit-free AI for every AI layer
    # + the chatbot. "Present" means a model is actually usable (server up), not
    # merely that the CLI is installed.
    try:
        from heaven.ai import local_llm
        installed = local_llm.is_ollama_installed()
        models = local_llm.list_models() if installed else []
        reachable = bool(models) or (installed and local_llm.ollama_reachable())
        if not installed:
            local_detail = "Ollama not installed"
        elif not reachable:
            local_detail = "installed, server not running (ollama serve)"
        elif not models:
            local_detail = f"server up, no models — heaven ai pull {local_llm.DEFAULT_OLLAMA_MODEL}"
        else:
            local_detail = "ready: " + ", ".join(models[:3])
        caps.append({
            "name": "local-llm",
            "present": bool(reachable and models),
            "purpose": "Local AI (no API key, no rate limits) for AI layers + chatbot",
            "hint": "" if (reachable and models) else "heaven ai setup",
            "detail": local_detail,
        })
    except Exception:  # noqa: BLE001 — capability probe must never raise
        logger.debug("local-llm capability probe failed", exc_info=True)

    return caps
