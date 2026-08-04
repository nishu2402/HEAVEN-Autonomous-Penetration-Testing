"""Time-based blind injection must be payload-controlled AND measured in isolation.

Two independent defences against timing false positives are pinned here:

1. ``_time_blind_confirmed`` — a hit must both clear the baseline by the injected
   sleep *and* scale when the sleep is doubled. A single jitter spike that clears
   one fixed threshold, but doesn't scale, is rejected.

2. The scanner's global timing lock — the injection scanner probes every
   parameter of a URL concurrently, so a genuinely-injectable param's SLEEP
   request and a benign param's probe are in flight at once. Against a serialising
   target (single-threaded PHP/MySQL, a rate-limiter) the benign request queues
   behind the real sleep and inherits its delay — a cross-parameter timing false
   positive the scale check alone cannot catch, because the interference scales
   too. The lock serialises every timed measurement so no two injected-sleep
   requests ever overlap. This was the live DVWA ``Submit``-param false positive.

See heaven/vulnscan/injection_scanner.py.
"""

from __future__ import annotations

import asyncio

import pytest

import heaven.vulnscan.injection_scanner as inj
from heaven.vulnscan.injection_scanner import _time_blind_confirmed


# ── 1. The pure differential decision ────────────────────────────────────────

def test_time_blind_confirmed_when_delay_scales() -> None:
    # baseline ~0.2s; single sleep adds ~3s; doubling adds ~3s more → controlled.
    assert _time_blind_confirmed(0.2, 3.3, 6.4, 3) is True


def test_time_blind_rejects_nonscaling_jitter() -> None:
    # A jitter spike cleared the first bar (3.3 ≥ 0.2 + 2.55) but doubling the
    # sleep added almost nothing (3.5 < 3.3 + 2.55) → not payload-controlled.
    assert _time_blind_confirmed(0.2, 3.3, 3.5, 3) is False
    assert _time_blind_confirmed(0.2, 4.0, 4.2, 3) is False


def test_time_blind_rejects_below_threshold() -> None:
    # The single sleep never even cleared the baseline margin.
    assert _time_blind_confirmed(0.2, 1.0, 9.0, 3) is False


def test_time_blind_confirmed_at_exact_threshold() -> None:
    # baseline 0, margin = 3 * 0.85 = 2.55: single == 2.55, double == 5.10.
    assert _time_blind_confirmed(0.0, 2.55, 5.10, 3) is True


# ── 2. Timed measurements are serialised (no cross-parameter interference) ────

_SLEEP_TOKENS = ("sleep(", "sleep ", "pg_sleep", "waitfor delay", "dbms_pipe", "rlike sleep")


def _carries_sleep(text: str) -> bool:
    low = (text or "").lower()
    return any(tok in low for tok in _SLEEP_TOKENS)


@pytest.mark.asyncio
async def test_timed_requests_never_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    """No two injected-sleep requests are ever in flight at once.

    Every param of the URL is probed concurrently, so without the timing lock the
    two params' SLEEP probes would overlap (and a serialising server would leak
    one's delay onto the other). The fake transport records how many sleep-payload
    requests are simultaneously in flight; the lock must hold that at 1.
    """
    state = {"active": 0, "max_active": 0}

    async def _track() -> None:
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        await asyncio.sleep(0.01)  # simulate the in-flight window
        state["active"] -= 1

    async def fake_get(session, url, headers=None, timeout=8.0):
        if _carries_sleep(url):
            await _track()
        return 200, "<html><body>x</body></html>"

    async def fake_post(session, url, data, headers=None, timeout=8.0):
        payload = " ".join(str(v) for v in (data or {}).values())
        if _carries_sleep(payload):
            await _track()
        return 200, "<html><body>x</body></html>"

    monkeypatch.setattr(inj, "_get", fake_get)
    monkeypatch.setattr(inj, "_post", fake_post)

    scanner = inj.InjectionScanner(concurrency=20)
    # Two GET params, both time-probed concurrently — exactly the id/Submit shape.
    await scanner._scan_url(None, "http://target/vuln?id=1&submit=go")

    assert state["max_active"] == 1, (
        f"injected-sleep requests overlapped (max_active={state['max_active']}) — "
        "the timing lock is not serialising time-based measurements, so one "
        "parameter's delay can leak onto another (cross-parameter timing FP)."
    )
