"""``heaven.utils.fanout.gather_budgeted`` — the shared salvage primitive.

Pins the contract every migrated fan-out scanner relies on: completed results
are kept in submission order, pending coroutines are cancelled and never block,
the deadline never raises, and a shared-state accumulator keeps exactly the
findings of the coroutines that finished in time.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from heaven.utils.fanout import gather_budgeted


@pytest.mark.asyncio
async def test_no_budget_runs_everything_in_order():
    async def work(i: int) -> int:
        await asyncio.sleep(0)
        return i * 10

    results, truncated = await gather_budgeted([work(i) for i in range(6)])
    assert results == [0, 10, 20, 30, 40, 50]
    assert truncated is False


@pytest.mark.asyncio
async def test_generous_budget_does_not_truncate():
    async def work(i: int) -> int:
        await asyncio.sleep(0.01)
        return i

    results, truncated = await gather_budgeted(
        [work(i) for i in range(5)], time_budget=5.0)
    assert sorted(results) == [0, 1, 2, 3, 4]
    assert truncated is False


@pytest.mark.asyncio
async def test_tiny_budget_keeps_completed_and_cancels_pending():
    # Three instant coroutines and many slow ones; the budget must keep the
    # instant results, flag truncation, and RETURN promptly on its own.
    async def fast(i: int) -> str:
        return f"fast{i}"

    async def slow(i: int) -> str:
        await asyncio.sleep(10.0)
        return f"slow{i}"

    coros = [fast(0), fast(1), fast(2)] + [slow(i) for i in range(25)]
    t0 = time.monotonic()
    # Outer guard far above the budget proves we return on our own deadline.
    results, truncated = await asyncio.wait_for(
        gather_budgeted(coros, time_budget=0.3), timeout=5.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 4.0, f"did not return on its own budget ({elapsed:.1f}s)"
    assert truncated is True
    assert set(results) == {"fast0", "fast1", "fast2"}


@pytest.mark.asyncio
async def test_shared_state_accumulator_salvages_partial():
    # Mirrors the findings-on-shared-state scanners (idor / client_audit / oob):
    # each coroutine appends to a shared list as it completes; the ones cancelled
    # at the budget never appended, exactly like the injection sweep.
    sink: list[str] = []

    async def audit(name: str, delay: float) -> None:
        await asyncio.sleep(delay)
        sink.append(name)

    coros = [audit("a", 0.0), audit("b", 0.0), audit("c", 10.0), audit("d", 10.0)]
    _results, truncated = await gather_budgeted(coros, time_budget=0.3)
    assert truncated is True
    assert set(sink) == {"a", "b"}  # slow c/d were cancelled before appending


@pytest.mark.asyncio
async def test_exceptions_are_captured_like_gather():
    async def boom(i: int):
        if i == 1:
            raise ValueError("kaboom")
        return i

    results, truncated = await gather_budgeted(
        [boom(0), boom(1), boom(2)], return_exceptions=True)
    assert truncated is False
    assert results[0] == 0
    assert isinstance(results[1], ValueError)
    assert results[2] == 2


@pytest.mark.asyncio
async def test_empty_input():
    results, truncated = await gather_budgeted([], time_budget=1.0)
    assert results == []
    assert truncated is False
