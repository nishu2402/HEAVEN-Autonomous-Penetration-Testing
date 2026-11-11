"""WebAnomalyProbe.scan_endpoint must honour a mid-URL wall-budget deadline.

Live symptom (full-range FULL scan of a real cPanel host): the Anomaly Probe ran
562s even though the orchestrator gives it a 180s soft wall-budget, because that
budget was only checked BETWEEN URLs. ``scan_endpoint`` runs 8 batteries per param
over 5 params, and several are time-based (5s sleep payloads), so a single slow /
throttling URL kept one sweep running for minutes and overran the between-URL
check, up to the hard task cap.

The fix threads a ``time.monotonic()`` ``deadline`` into ``scan_endpoint`` and
checks it before every param AND before every per-param test -- the per-test
granularity matters: a no-cap live re-run showed that checking only per-param
still let ONE param's full battery overrun (562 -> 488s), so the guard runs before
each test, bounding the overshoot to a single test. It is purely a stop-sooner
guard: it never changes what counts as a candidate, so it cannot add a false
positive. These tests pin the behaviour with ZERO network -- the batteries are
stubbed and a fake monotonic clock drives the deadline.
"""
from __future__ import annotations

import asyncio
import itertools

from heaven.vulnscan import anomaly_probe as ap

_PARAMS = ["id", "q", "page", "file", "url"]
_N_PER_PARAM = 8  # command-injection / ssti / traversal / intover / ldap / xpath / nosql / proto


def _run(coro):
    return asyncio.run(coro)


def _stub_probe(monkeypatch):
    """A probe whose 8 per-param batteries are no-ops. ``calls`` records EVERY
    per-param test invocation (to prove mid-battery preemption); ``swept`` records
    the param each time the FIRST test (command injection) runs, i.e. the params
    whose battery actually started."""
    probe = ap.WebAnomalyProbe()
    swept: list[str] = []
    calls: list[str] = []

    def _mk(name, records_param=False):
        async def _f(session, url, param, method="GET"):
            calls.append(name)
            if records_param:
                swept.append(param)
            return [] if name == "nosql" else None  # nosql returns a LIST
        return _f

    monkeypatch.setattr(probe, "_test_command_injection", _mk("cmdi", records_param=True))
    monkeypatch.setattr(probe, "_test_ssti", _mk("ssti"))
    monkeypatch.setattr(probe, "_test_path_traversal", _mk("traversal"))
    monkeypatch.setattr(probe, "_test_integer_overflow", _mk("intover"))
    monkeypatch.setattr(probe, "_test_ldap_injection", _mk("ldap"))
    monkeypatch.setattr(probe, "_test_xpath_injection", _mk("xpath"))
    monkeypatch.setattr(probe, "_test_nosql_injection", _mk("nosql"))
    monkeypatch.setattr(probe, "_test_prototype_pollution", _mk("proto"))

    async def _url_empty(session, url):
        return []

    async def _url_none(session, url):
        return None

    monkeypatch.setattr(probe, "_test_header_injection", _url_empty)
    monkeypatch.setattr(probe, "_test_xxe", _url_none)
    monkeypatch.setattr(probe, "_test_websocket", _url_empty)
    return probe, swept, calls


class _Clock:
    """Deterministic monotonic source, swapped in as the module's ``time`` so the
    probe's guards read it WITHOUT touching the real ``time`` module (patching the
    shared module would also starve asyncio's own event-loop clock)."""

    def __init__(self, ticks):
        self._it = iter(ticks)

    def monotonic(self):
        return next(self._it)


def test_no_deadline_sweeps_every_param_and_test(monkeypatch):
    # Back-compat: without a deadline the guards short-circuit and nothing
    # changes -- every param runs its full 8-test battery.
    probe, swept, calls = _stub_probe(monkeypatch)
    out = _run(probe.scan_endpoint(None, "http://t/", _PARAMS))
    assert swept == _PARAMS
    assert len(calls) == len(_PARAMS) * _N_PER_PARAM
    assert out == []


def test_past_deadline_sweeps_nothing(monkeypatch):
    # A deadline already in the past stops before the first param -- no test runs.
    probe, swept, calls = _stub_probe(monkeypatch)
    out = _run(probe.scan_endpoint(None, "http://t/", _PARAMS, deadline=0.0))
    assert swept == []
    assert calls == []
    assert out == []


def test_deadline_preempts_mid_battery(monkeypatch):
    # Clock ticks 0,1,2,... (one per guard read). With deadline=11.5 the reads
    # land so param 0 runs its full 8-test battery (ticks 1-8), param 1 runs only
    # cmdi+ssti before tick 12 trips the guard, and param 2's top-guard (tick 13)
    # ends the sweep. 10 test calls (not 16) PROVES mid-battery preemption, not a
    # coarse per-param break.
    probe, swept, calls = _stub_probe(monkeypatch)
    monkeypatch.setattr(ap, "time", _Clock(itertools.count(0)))
    out = _run(probe.scan_endpoint(None, "http://t/", _PARAMS, deadline=11.5))
    assert swept == ["id", "q"]
    assert len(calls) == _N_PER_PARAM + 2  # 8 (param 0) + 2 (param 1: cmdi, ssti)
    assert out == []
