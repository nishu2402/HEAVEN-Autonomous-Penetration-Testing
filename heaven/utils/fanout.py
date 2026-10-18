"""Budget-aware fan-out for per-target scanners.

The orchestrator aggregates findings ONLY from tasks that reach ``COMPLETED``
(see ``heaven/orchestrator.py`` ``_run_task`` / the COMPLETED-only harvest). A
task whose coroutine is cancelled at its hard ``asyncio.wait_for`` timeout never
reaches its ``return``, so every finding it already gathered is discarded and
the task contributes ZERO. For a per-URL web fan-out on a slow or rate-limiting
host (hundreds of crawled URLs) that turns a timeout into total loss, not
partial results.

``gather_budgeted`` is the shared salvage primitive. It runs a fan-out of
coroutines concurrently and, once a soft ``time_budget`` elapses, stops waiting,
cancels the still-pending coroutines and RETURNS the results that completed in
time, instead of letting the orchestrator's hard timeout cancel the whole
scanner and drop everything. It never raises on the budget. The orchestrator
task passes ~90% of the task's *effective* (scope/stealth-scaled) timeout, so a
scanner drains and returns its partial results before the hard cancel.

It serves both fan-out shapes already in the codebase:
  * results-returned: ``results, truncated = await gather_budgeted(...)`` then
    the scanner flattens ``results`` (submission order is preserved; only the
    completed coroutines are present, so never positional-zip the result back
    against the full input list — iterate it directly);
  * findings-on-shared-state: the scanner ignores the returned list because each
    coroutine appends to a shared ``self._findings`` as it completes; a cancelled
    pending coroutine simply never appended, exactly like the injection sweep.

Precedents that predate this helper and keep their bespoke salvage:
``auth_scanner.scan_auth_targets`` and ``injection_scanner`` (both documented in
the ``fanout-scanner-soft-budget-salvage`` project memory).
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Iterable, TypeVar, cast

T = TypeVar("T")

__all__ = ["gather_budgeted"]


async def gather_budgeted(
    coros: Iterable[Awaitable[T]],
    *,
    time_budget: float | None = None,
    return_exceptions: bool = True,
) -> tuple[list[T], bool]:
    """Run ``coros`` concurrently under a soft wall-clock budget.

    Returns ``(results, truncated)``:
      * ``results`` holds the results of the coroutines that COMPLETED within
        the budget, in submission order. A coroutine that raised contributes its
        exception when ``return_exceptions`` is true (mirroring
        ``asyncio.gather``), otherwise it is skipped.
      * ``truncated`` is ``True`` when the budget elapsed with coroutines still
        pending (which were then cancelled), i.e. coverage is partial.

    With ``time_budget`` falsy or non-positive the call is an ordinary unbounded
    gather and ``truncated`` is always ``False``. The budget path never raises
    ``TimeoutError``: hitting the deadline is a normal, salvaged return so the
    caller's post-gather flatten runs with whatever completed.
    """
    tasks = [asyncio.ensure_future(c) for c in coros]
    if not tasks:
        return [], False

    if not time_budget or time_budget <= 0:
        gathered = await asyncio.gather(*tasks, return_exceptions=return_exceptions)
        # With return_exceptions the list may hold exceptions; callers that ask
        # for them treat them as data (mirroring asyncio.gather), so expose the
        # declared element type.
        return cast("list[T]", list(gathered)), False

    # asyncio.wait never raises on timeout — it returns the done/pending split,
    # so the already-completed coroutines' results are ours to keep.
    done, pending = await asyncio.wait(tasks, timeout=time_budget)
    truncated = bool(pending)
    for t in pending:
        t.cancel()
    if pending:
        # Drain the cancellations so no "Task was destroyed but it is pending"
        # warning escapes and the event loop is left clean.
        await asyncio.gather(*pending, return_exceptions=True)

    results: list[T] = []
    for t in tasks:  # submission order; completed-only
        if t not in done:
            continue
        exc = t.exception()
        if exc is not None:
            if return_exceptions:
                results.append(exc)  # type: ignore[arg-type]
            continue
        results.append(t.result())
    return results, truncated
