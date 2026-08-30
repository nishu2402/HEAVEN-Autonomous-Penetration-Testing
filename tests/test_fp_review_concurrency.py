"""AI-triage borderline FP review runs with bounded concurrency.

A live scan on a service-rich host produces dozens of borderline findings; a
strictly-sequential review loop spent ~112s blocked on the LLM. These tests lock
in that the reviewer now fans out concurrently, still honours the borderline
band, degrades to a no-op with no provider, and survives a single bad review.

NOTE: the module is imported *inside* each test and patched on that same object.
A sibling test (``test_advanced``) deletes ``heaven.*`` from ``sys.modules``; a
top-level import here would bind ``review_borderline_findings`` to a stale module
while ``monkeypatch`` re-imports a fresh one, so the patched ``get_gateway`` and
the function under test would live on different module objects. Resolving both at
call time keeps them the same object regardless of run order.
"""
from __future__ import annotations

import asyncio
import importlib


def _fpr():
    return importlib.import_module("heaven.ai.fp_review")


class _Resp:
    def __init__(self, fpr, delta: float = 0.1):
        self.structured = fpr.FPReviewVerdict(keep=True, confidence_delta=delta,
                                              reasoning="ok")
        self.error = None

    def ok(self):
        return True


class _CountingGateway:
    """Records how many reviews overlap so we can prove real concurrency."""

    available = True

    def __init__(self, fpr, hold: float = 0.02):
        self._fpr = fpr
        self.hold = hold
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0

    async def acomplete(self, req):
        self.calls += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.hold)
            return _Resp(self._fpr)
        finally:
            self.in_flight -= 1


def _mk(conf: float, i: int) -> dict:
    return {"confidence": conf, "vuln_type": "xss", "target": f"t{i}"}


def test_borderline_reviews_run_concurrently(monkeypatch):
    fpr = _fpr()
    gw = _CountingGateway(fpr)
    monkeypatch.setattr(fpr, "get_gateway", lambda: gw)
    findings = [_mk(0.5, i) for i in range(10)]  # all in the 0.4-0.7 band

    out = asyncio.run(fpr.review_borderline_findings(findings))

    assert out is findings                       # mutated in place, same object
    assert gw.calls == 10                         # every borderline finding reviewed
    assert gw.max_in_flight > 1                    # genuinely parallel, not serial
    assert all(f.get("llm_review_kept") is True for f in findings)


def test_concurrency_is_bounded(monkeypatch):
    fpr = _fpr()
    gw = _CountingGateway(fpr)
    monkeypatch.setattr(fpr, "get_gateway", lambda: gw)
    monkeypatch.setenv("HEAVEN_FP_REVIEW_CONCURRENCY", "3")
    findings = [_mk(0.5, i) for i in range(12)]

    asyncio.run(fpr.review_borderline_findings(findings))

    assert gw.calls == 12
    assert gw.max_in_flight <= 3                    # semaphore respected


def test_out_of_band_findings_are_not_reviewed(monkeypatch):
    fpr = _fpr()
    gw = _CountingGateway(fpr)
    monkeypatch.setattr(fpr, "get_gateway", lambda: gw)
    findings = [_mk(0.95, 0), _mk(0.1, 1), _mk(0.5, 2)]  # only the 0.5 is in band

    asyncio.run(fpr.review_borderline_findings(findings))

    assert gw.calls == 1                            # short-circuits before network I/O


def test_no_provider_is_a_noop(monkeypatch):
    fpr = _fpr()

    class _Down:
        available = False

        async def acomplete(self, req):  # pragma: no cover - must never be called
            raise AssertionError("should not be reached when unavailable")

    monkeypatch.setattr(fpr, "get_gateway", lambda: _Down())
    findings = [_mk(0.5, i) for i in range(5)]

    out = asyncio.run(fpr.review_borderline_findings(findings))

    assert out is findings
    assert all("llm_review_kept" not in f for f in findings)


def test_no_provider_with_borderline_logs_actionable_hint(monkeypatch, caplog):
    """When there's nothing to review with, say so once — actionably."""
    fpr = _fpr()

    class _Down:
        available = True  # gateway.available; reviewer.available also needs pydantic

        async def acomplete(self, req):  # pragma: no cover - unavailable path
            raise AssertionError("should not be reached when unavailable")

    down = _Down()
    down.available = False
    monkeypatch.setattr(fpr, "get_gateway", lambda: down)
    findings = [_mk(0.5, i) for i in range(3)]  # all in the borderline band

    with caplog.at_level("WARNING"):
        asyncio.run(fpr.review_borderline_findings(findings))

    msg = " ".join(r.message for r in caplog.records)
    assert "heaven ai setup" in msg
    assert "3 borderline" in msg


def test_no_provider_and_no_borderline_is_silent(monkeypatch, caplog):
    """No borderline findings → nothing to review → no noise."""
    fpr = _fpr()

    class _Down:
        available = False

        async def acomplete(self, req):  # pragma: no cover
            raise AssertionError("unavailable")

    monkeypatch.setattr(fpr, "get_gateway", lambda: _Down())
    findings = [_mk(0.95, 0), _mk(0.1, 1)]  # neither is in band

    with caplog.at_level("WARNING"):
        asyncio.run(fpr.review_borderline_findings(findings))

    assert not any("AI false-positive review" in r.message for r in caplog.records)


def test_ratelimited_provider_logs_partial_skip_notice(monkeypatch, caplog):
    """A quota/rate-limit breaker armed at the end → one actionable partial-skip note."""
    fpr = _fpr()

    class _RateLimited(_CountingGateway):
        rate_limited = True  # breaker armed (as after exhausting a free tier)

    gw = _RateLimited(fpr)
    monkeypatch.setattr(fpr, "get_gateway", lambda: gw)
    findings = [_mk(0.5, i) for i in range(4)]

    with caplog.at_level("WARNING"):
        asyncio.run(fpr.review_borderline_findings(findings))

    msg = " ".join(r.message for r in caplog.records)
    assert "rate limit" in msg.lower()
    assert "heaven ai setup" in msg


def test_one_bad_review_does_not_sink_the_batch(monkeypatch):
    fpr = _fpr()

    class _Flaky(_CountingGateway):
        async def acomplete(self, req):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("provider blew up on one finding")
            return _Resp(self._fpr)

    gw = _Flaky(fpr)
    monkeypatch.setattr(fpr, "get_gateway", lambda: gw)
    findings = [_mk(0.5, i) for i in range(5)]

    out = asyncio.run(fpr.review_borderline_findings(findings))

    assert out is findings
    kept = sum(1 for f in findings if f.get("llm_review_kept") is True)
    assert kept == 4                                # 4 succeed, 1 errored, none crash
