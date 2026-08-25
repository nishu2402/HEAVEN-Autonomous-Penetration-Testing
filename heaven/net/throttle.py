"""Global per-target request throttle for HEAVEN's in-process HTTP scanning.

Every web scanner (crawler, injection, fuzzer, dir-buster, access-control,
auth, param-miner, verifier, ...) runs its own aiohttp session with its own
internal concurrency. On a single target that adds up: a full scan can put a
hundred-plus simultaneous requests on one host. A well-resourced site shrugs
that off, but a legacy app, an embedded/IoT admin UI, or an emulated lab box
(the amd64 DVWA container under QEMU is the canonical example) buckles: its
worker pool or database connection pool exhausts, responses start timing out or
dropping, and the scan's own load silently destroys its recall.

This module is the one shared brake. It caps *concurrent in-flight requests per
target host across all scanners* and, more importantly, adapts that cap to how
the target is coping. It is TCP-style AIMD congestion control applied to scan
traffic:

  * start at a moderate per-host concurrency and grow it additively while the
    host answers cleanly, up to a ceiling;
  * the moment the host shows genuine distress (HTTP 429/503, or a timeout /
    reset / mid-response disconnect), cut the cap multiplicatively and stop
    growing for a short cool-off.

A healthy target therefore sees almost no throttling (the cap climbs out of the
way); a struggling one is automatically backed off before the scan knocks it
over. Nothing here weakens detection: it reshapes *when* requests go out, never
*whether* a check runs.

Wiring is centralised: the throttle installs itself as an aiohttp ``TraceConfig``
on the two places sessions are built (:func:`heaven.net.egress.client_session`
and :func:`heaven.recon.auth_session.aiohttp_session_kwargs`), so individual
scanners need no changes.

Defaults are deliberately generous so normal scans are unaffected; operators who
need polite/production-safe scanning can tighten every knob by env var, and
``HEAVEN_NO_THROTTLE=1`` turns the whole thing off (raw speed, e.g. for a
benchmark against a beefy host).

Env knobs (read once per host, so setting them before a scan is enough):

  HEAVEN_NO_THROTTLE      1/true  -> disable entirely (checked per request)
  HEAVEN_THROTTLE_START   initial per-host concurrency        (default 16)
  HEAVEN_THROTTLE_MAX     ceiling on per-host concurrency      (default 64)
  HEAVEN_THROTTLE_MIN     floor the backoff can reach          (default 2)
  HEAVEN_THROTTLE_STEP    additive-increase step per success   (default 1)
  HEAVEN_THROTTLE_BACKOFF grow-freeze window after distress, s (default 2.0)
  HEAVEN_THROTTLE_DISTRESS sustained-distress signals before a back-off (default 3)
  HEAVEN_THROTTLE_RPS     hard requests/sec cap per host, 0=off (default 0)

No new dependencies. Loop-isolated: all async primitives are created lazily and
kept in a per-event-loop registry, so the module is safe under pytest (a fresh
loop per test gets fresh, correctly-bound state) and under a long-lived scan
loop alike.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import weakref
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("net.throttle")


# ── env helpers ─────────────────────────────────────────────────────────────

def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    return int(_env_float(name, float(default)))


def throttle_disabled() -> bool:
    """True when the operator has switched the throttle off entirely. Read live
    (per request) so it can be toggled without a restart."""
    return (os.environ.get("HEAVEN_NO_THROTTLE") or "").strip().lower() in (
        "1", "true", "yes", "on", "enabled",
    )


# ── per-host adaptive state ─────────────────────────────────────────────────
# A request that acquires a slot but never releases it (a hard task-cancellation
# that skips aiohttp's exception trace) would leak concurrency for the life of
# the scan. We defend against that by timestamping every in-flight slot and
# reclaiming any older than this ceiling — comfortably longer than any real
# request timeout, so a live request is never reclaimed, but a genuinely leaked
# slot frees within a few minutes.
_STALE_SLOT_SECONDS = 180.0


class _HostState:
    """Adaptive concurrency + optional hard rate limit for one target host.

    Bound to the event loop it is created on (its :class:`asyncio.Condition`
    binds to the running loop on first use); the registry keys states by loop so
    a state is never touched from a foreign loop.
    """

    def __init__(self, host: str) -> None:
        self.host = host
        self.max = max(1, _env_int("HEAVEN_THROTTLE_MAX", 64))
        self.min = max(1, min(_env_int("HEAVEN_THROTTLE_MIN", 2), self.max))
        start = _env_int("HEAVEN_THROTTLE_START", 16)
        self.limit: float = float(max(self.min, min(start, self.max)))
        self.step = max(0.0, _env_float("HEAVEN_THROTTLE_STEP", 1.0))
        self.grow_freeze = max(0.0, _env_float("HEAVEN_THROTTLE_BACKOFF", 2.0))
        self.rps = max(0.0, _env_float("HEAVEN_THROTTLE_RPS", 0.0))

        self._cond = asyncio.Condition()
        self._tickets: dict[int, float] = {}   # ticket id -> acquire monotonic
        self._next_id = 0
        self._last_distress = 0.0
        # Distress is noisy: one stray timeout on an inherently-slow-but-healthy
        # host is not "overwhelmed". Back off only when distress is SUSTAINED —
        # a leaky-bucket failure detector. Each distress signal adds 1, each
        # clean response drains 1; the cap is cut only when the bucket fills.
        self._distress_threshold = max(1, _env_int("HEAVEN_THROTTLE_DISTRESS", 3))
        self._distress_score = 0.0

        # token bucket (only used when rps > 0)
        self._rl_lock = asyncio.Lock()
        self._tokens = self.rps          # start full so the first burst is free
        self._last_refill = time.monotonic()

    # ── rate limit (optional) ───────────────────────────────────────────────
    async def _await_token(self) -> None:
        if self.rps <= 0:
            return
        async with self._rl_lock:
            now = time.monotonic()
            self._tokens = min(self.rps, self._tokens + (now - self._last_refill) * self.rps)
            self._last_refill = now
            if self._tokens < 1.0:
                await asyncio.sleep((1.0 - self._tokens) / self.rps)
                self._tokens = 0.0
                self._last_refill = time.monotonic()
            else:
                self._tokens -= 1.0

    # ── concurrency gate ────────────────────────────────────────────────────
    def _prune_stale(self, now: float) -> None:
        if not self._tickets:
            return
        cutoff = now - _STALE_SLOT_SECONDS
        stale = [tid for tid, ts in self._tickets.items() if ts < cutoff]
        for tid in stale:
            self._tickets.pop(tid, None)
        if stale:
            logger.debug("throttle[%s]: reclaimed %d stale slot(s)", self.host, len(stale))

    async def acquire(self) -> int:
        await self._await_token()
        async with self._cond:
            while True:
                now = time.monotonic()
                self._prune_stale(now)
                if len(self._tickets) < max(1, int(self.limit)):
                    break
                await self._cond.wait()
            tid = self._next_id
            self._next_id += 1
            self._tickets[tid] = time.monotonic()
            return tid

    async def release(self, ticket: int, distress: bool) -> None:
        async with self._cond:
            saturating = len(self._tickets) >= max(1, int(self.limit))
            self._tickets.pop(ticket, None)
            if distress:
                self._distress_score += 1.0
            else:
                self._distress_score = max(0.0, self._distress_score - 1.0)

            if self._distress_score >= self._distress_threshold:
                # Sustained distress: cut the cap and drain the bucket part-way
                # (not to zero) so a genuinely overwhelmed host keeps backing off
                # every couple of further failures, while a single later blip
                # can't immediately re-trigger.
                self._last_distress = time.monotonic()
                self._distress_score = self._distress_threshold / 2.0
                new_limit = max(float(self.min), self.limit / 2.0)
                if new_limit < self.limit:
                    logger.debug("throttle[%s]: sustained distress -> limit %.1f -> %.1f",
                                 self.host, self.limit, new_limit)
                self.limit = new_limit
            elif (not distress and self.step > 0 and self.limit < self.max and saturating
                  and (time.monotonic() - self._last_distress) >= self.grow_freeze):
                # Only grow when we were actually saturating the cap and the host
                # has been clean for a while — no runaway growth on light load.
                self.limit = min(float(self.max), self.limit + self.step)
            # Wake enough waiters to fill the (possibly changed) headroom.
            free = max(1, int(self.limit)) - len(self._tickets)
            if free > 0:
                self._cond.notify(free)


# ── per-loop registry (keeps every asyncio primitive on its own loop) ───────

_registry: "weakref.WeakKeyDictionary[Any, dict[str, _HostState]]" = weakref.WeakKeyDictionary()
_registry_guard = threading.Lock()


def _state_for(host: str) -> Optional[_HostState]:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    with _registry_guard:
        per_loop = _registry.get(loop)
        if per_loop is None:
            per_loop = {}
            _registry[loop] = per_loop
        state = per_loop.get(host)
        if state is None:
            state = _HostState(host)
            per_loop[host] = state
        return state


def _reset_registry() -> None:
    """Drop all per-loop throttle state. For tests that want a clean slate."""
    with _registry_guard:
        _registry.clear()


# ── distress classification ─────────────────────────────────────────────────
# Only signals that genuinely mean "the server is struggling" back the scan off.
# A 500 from a fuzz payload, an SSL error on an https probe, or a connection
# refused on a closed port are normal scanning noise, NOT distress — treating
# them as such would throttle healthy targets for doing their job.
_DISTRESS_STATUS = frozenset({429, 503})


def _is_distress_status(status: int) -> bool:
    return status in _DISTRESS_STATUS


def _is_distress_exc(exc: BaseException) -> bool:
    if isinstance(exc, (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError)):
        return True
    try:
        import aiohttp
    except Exception:  # noqa: BLE001
        return False
    return isinstance(exc, (
        aiohttp.ServerDisconnectedError,
        aiohttp.ServerTimeoutError,
    ))


# ── aiohttp TraceConfig factory ─────────────────────────────────────────────

def throttle_trace_config() -> Optional[Any]:
    """Build an aiohttp ``TraceConfig`` that gates every request through the
    per-host throttle. Returns ``None`` when aiohttp is unavailable. The kill
    switch is honoured per request inside the callbacks, so a config can be
    installed once and still respond to ``HEAVEN_NO_THROTTLE`` toggling."""
    try:
        import aiohttp
    except Exception:  # noqa: BLE001
        return None

    async def on_request_start(session, context, params):  # noqa: ANN001
        context._heaven_ticket = None
        context._heaven_state = None
        if throttle_disabled():
            return
        host = getattr(params.url, "host", None)
        if not host:
            return
        state = _state_for(host)
        if state is None:
            return
        ticket = await state.acquire()
        context._heaven_state = state
        context._heaven_ticket = ticket

    async def _release(context, distress: bool) -> None:  # noqa: ANN001
        state = getattr(context, "_heaven_state", None)
        ticket = getattr(context, "_heaven_ticket", None)
        if state is None or ticket is None:
            return
        context._heaven_state = None
        context._heaven_ticket = None
        try:
            await state.release(ticket, distress)
        except Exception:  # noqa: BLE001 — releasing a slot must never break a scan
            logger.debug("throttle release failed", exc_info=True)

    async def on_request_end(session, context, params):  # noqa: ANN001
        status = getattr(getattr(params, "response", None), "status", 0) or 0
        await _release(context, _is_distress_status(int(status)))

    async def on_request_exception(session, context, params):  # noqa: ANN001
        exc = getattr(params, "exception", None)
        await _release(context, bool(exc is not None and _is_distress_exc(exc)))

    tc = aiohttp.TraceConfig()
    tc.on_request_start.append(on_request_start)
    tc.on_request_end.append(on_request_end)
    tc.on_request_exception.append(on_request_exception)
    tc._heaven_throttle = True   # marker so we never double-install
    return tc


# ── public: install into a ClientSession kwargs dict ─────────────────────────

def instrument_session_kwargs(kwargs: dict) -> dict:
    """Append HEAVEN's per-host throttle ``TraceConfig`` to a
    ``ClientSession(**kwargs)`` dict, merging with any ``trace_configs`` the
    caller already set and never installing twice. Mutates and returns *kwargs*
    (a no-op if aiohttp is missing). Safe to call unconditionally at every
    session-construction site."""
    tc = throttle_trace_config()
    if tc is None:
        return kwargs
    existing = list(kwargs.get("trace_configs") or [])
    if any(getattr(t, "_heaven_throttle", False) for t in existing):
        return kwargs
    existing.append(tc)
    kwargs["trace_configs"] = existing
    return kwargs
