"""Tests for the global per-target request throttle (heaven/net/throttle.py).

Covers three layers:
  * the pure adaptive-concurrency math on `_HostState` (backoff / growth);
  * distress classification (only real "server struggling" signals count);
  * end-to-end that a real aiohttp session carrying the throttle TraceConfig
    actually caps simultaneous in-flight requests to one host, that the kill
    switch removes the cap, and that a 503-spewing target gets backed off.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.net import throttle

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web  # noqa: E402


# ── helpers ─────────────────────────────────────────────────────────────────

def _fresh(monkeypatch, **env):
    """Reset per-loop throttle state and set the given HEAVEN_THROTTLE_* env."""
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    throttle._reset_registry()


class _ConcurrencyServer:
    """A tiny aiohttp server that records the peak number of simultaneously
    in-flight requests it saw, so a test can prove the throttle capped them."""

    def __init__(self, *, delay=0.05, status=200):
        self.delay = delay
        self.status = status
        self.current = 0
        self.peak = 0
        self._runner = None
        self.port = 0

    async def _handler(self, request):
        self.current += 1
        self.peak = max(self.peak, self.current)
        try:
            await asyncio.sleep(self.delay)
            return web.Response(status=self.status, text="ok")
        finally:
            self.current -= 1

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        self.port = self._runner.addresses[0][1]
        return self

    async def __aexit__(self, *exc):
        await self._runner.cleanup()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/"


async def _hammer(url, n, **session_kwargs):
    """Fire *n* concurrent GETs through a throttle-instrumented session."""
    kwargs = throttle.instrument_session_kwargs(dict(session_kwargs))
    async with aiohttp.ClientSession(**kwargs) as sess:
        async def _one(i):
            async with sess.get(f"{url}?i={i}") as r:
                await r.read()
                return r.status
        return await asyncio.gather(*[_one(i) for i in range(n)])


# ── instrument_session_kwargs ────────────────────────────────────────────────

def test_instrument_adds_one_throttle_trace_config(monkeypatch):
    _fresh(monkeypatch)
    kw = throttle.instrument_session_kwargs({})
    tcs = kw.get("trace_configs")
    assert tcs and len(tcs) == 1
    assert getattr(tcs[0], "_heaven_throttle", False) is True


def test_instrument_is_idempotent(monkeypatch):
    _fresh(monkeypatch)
    kw = throttle.instrument_session_kwargs({})
    throttle.instrument_session_kwargs(kw)   # second pass must not double-install
    assert len(kw["trace_configs"]) == 1


def test_instrument_preserves_caller_trace_configs(monkeypatch):
    _fresh(monkeypatch)
    caller_tc = aiohttp.TraceConfig()
    kw = throttle.instrument_session_kwargs({"trace_configs": [caller_tc]})
    assert caller_tc in kw["trace_configs"]
    assert len(kw["trace_configs"]) == 2


# ── distress classification ──────────────────────────────────────────────────

def test_distress_status_only_429_and_503():
    assert throttle._is_distress_status(429)
    assert throttle._is_distress_status(503)
    # 500/502/504/404 are normal scanning noise, NOT distress.
    for s in (200, 301, 404, 500, 502, 504):
        assert not throttle._is_distress_status(s)


def test_distress_exception_classification():
    assert throttle._is_distress_exc(asyncio.TimeoutError())
    assert throttle._is_distress_exc(ConnectionResetError())
    assert throttle._is_distress_exc(aiohttp.ServerDisconnectedError())
    # A closed port / bad payload / value error is not target distress.
    assert not throttle._is_distress_exc(ValueError("boom"))
    assert not throttle._is_distress_exc(aiohttp.InvalidURL("x"))


# ── adaptive math on _HostState ──────────────────────────────────────────────

def test_single_distress_does_not_back_off(monkeypatch):
    # A lone timeout on a slow-but-healthy host must NOT throttle it — back-off
    # is only for SUSTAINED distress (threshold 3 here).
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=8, HEAVEN_THROTTLE_MAX=16,
           HEAVEN_THROTTLE_MIN=2, HEAVEN_THROTTLE_DISTRESS=3, HEAVEN_THROTTLE_BACKOFF=0)

    async def _go():
        st = throttle._HostState("t")
        tickets = [await st.acquire() for _ in range(8)]
        await st.release(tickets.pop(), distress=True)     # score 1
        await st.release(tickets.pop(), distress=False)    # drains to 0
        await st.release(tickets.pop(), distress=True)     # score 1 again
        assert st.limit == pytest.approx(8.0)              # never crossed threshold
        for t in tickets:
            await st.release(t, distress=False)

    asyncio.run(_go())


def test_host_state_backs_off_on_sustained_distress(monkeypatch):
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=8, HEAVEN_THROTTLE_MAX=16,
           HEAVEN_THROTTLE_MIN=2, HEAVEN_THROTTLE_DISTRESS=3, HEAVEN_THROTTLE_BACKOFF=0)

    async def _go():
        st = throttle._HostState("t")
        tickets = [await st.acquire() for _ in range(8)]
        assert len(st._tickets) == 8
        # Three distress signals fill the bucket (threshold 3) -> first back-off.
        for _ in range(3):
            await st.release(tickets.pop(), distress=True)
        assert st.limit == pytest.approx(4.0)   # halved from 8
        # Bucket drained to 1.5; two more distress cross the threshold again.
        for _ in range(2):
            await st.release(tickets.pop(), distress=True)
        assert st.limit == pytest.approx(2.0)   # halved again, at the floor
        for _ in range(2):
            await st.release(tickets.pop(), distress=True)
        assert st.limit == pytest.approx(2.0)   # never below HEAVEN_THROTTLE_MIN
        for t in tickets:
            await st.release(t, distress=False)

    asyncio.run(_go())


def test_host_state_grows_only_while_saturating(monkeypatch):
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=4, HEAVEN_THROTTLE_MAX=8,
           HEAVEN_THROTTLE_MIN=2, HEAVEN_THROTTLE_STEP=1, HEAVEN_THROTTLE_BACKOFF=0)

    async def _go():
        st = throttle._HostState("t")
        # Saturate (4 in flight, limit 4): a clean release grows the cap.
        tickets = [await st.acquire() for _ in range(4)]
        await st.release(tickets.pop(), distress=False)
        assert st.limit == pytest.approx(5.0)
        # Now well under the cap (3 in flight, limit 5): a clean release must
        # NOT grow it — no runaway growth on light load.
        await st.release(tickets.pop(), distress=False)
        assert st.limit == pytest.approx(5.0)
        for t in tickets:
            await st.release(t, distress=False)

    asyncio.run(_go())


# ── end-to-end through a real aiohttp session ────────────────────────────────

def test_throttle_caps_concurrent_requests(monkeypatch):
    # Pin the cap (START == MAX) so it cannot grow during the test.
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=3, HEAVEN_THROTTLE_MAX=3,
           HEAVEN_THROTTLE_MIN=1)

    async def _go():
        async with _ConcurrencyServer(delay=0.05) as srv:
            results = await _hammer(srv.url, 15)
            assert all(s == 200 for s in results)
            assert srv.peak <= 3, f"throttle let {srv.peak} requests through at once"

    asyncio.run(_go())


def test_kill_switch_removes_the_cap(monkeypatch):
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=2, HEAVEN_THROTTLE_MAX=2,
           HEAVEN_NO_THROTTLE=1)

    async def _go():
        async with _ConcurrencyServer(delay=0.05) as srv:
            await _hammer(srv.url, 12)
            # With the throttle off, far more than the (ignored) cap of 2 run
            # simultaneously.
            assert srv.peak > 2, f"kill switch did not disable throttling (peak={srv.peak})"

    asyncio.run(_go())


def test_distress_responses_back_off_the_live_host(monkeypatch):
    _fresh(monkeypatch, HEAVEN_THROTTLE_START=8, HEAVEN_THROTTLE_MAX=8,
           HEAVEN_THROTTLE_MIN=1, HEAVEN_THROTTLE_BACKOFF=0)

    async def _go():
        async with _ConcurrencyServer(delay=0.02, status=503) as srv:
            await _hammer(srv.url, 24)
            st = throttle._state_for("127.0.0.1")
            # A wall of 503s must have driven the adaptive cap down from 8.
            assert st is not None
            assert st.limit < 8, f"limit did not back off under 503s (limit={st.limit})"

    asyncio.run(_go())
