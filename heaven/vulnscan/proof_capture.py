"""
HEAVEN — Scan-scoped HTTP proof capture.

Every web detector proves a finding by sending a request and reading the
response, but historically only a few of them stored that response in the
finding's evidence. The rest left ``evidence`` without a ``status`` or a
``response_body``, so the report and UI rendered a misleading
``Response: HTTP 0 (0 bytes) — (no response captured)`` for a finding that was,
in fact, proved by a real transaction.

This module is the single, low-touch fix. A detector's fetch helper calls
:func:`record` with the exact ``(url, status, body)`` it observed; after the
scan phase aggregates its findings, the orchestrator calls :func:`attach_all`
once, which folds the captured transaction into each HTTP finding that is
missing it (matched by the URL the finding was proved on). Nothing is
fabricated: a finding whose URL was never fetched keeps whatever evidence it
already had, and an empty transaction is never recorded.

The store lives in a :class:`contextvars.ContextVar` so it is scan-scoped and
concurrency-safe: the orchestrator installs a fresh store for the run, every
``asyncio`` task spawned within inherits the same dict object (context copies
the reference, and detectors *mutate* it rather than reassign the var), and the
store is discarded when the scan context ends. Outside a scan context — a unit
test calling a detector directly — :func:`record` is a graceful no-op.
"""

from __future__ import annotations

import contextvars
from typing import Any, Optional

# The per-scan store: {url: (status, body_snippet)}. ``None`` means "no scan
# context is active" so record()/attach are inert (never raise, never leak
# across scans).
_STORE: contextvars.ContextVar[Optional[dict[str, tuple[int, str]]]] = (
    contextvars.ContextVar("heaven_proof_capture", default=None)
)

# Keep the stored body bounded — evidence excerpts are truncated for display
# anyway, and a chatty target must not grow the store without limit.
_MAX_BODY = 4000
_MAX_ENTRIES = 2000


def begin() -> contextvars.Token:
    """Install a fresh, empty capture store for the current scan scope.

    Returns the ContextVar token so the caller can :func:`end` it. Safe to call
    without a matching end (the store is garbage-collected with the context)."""
    return _STORE.set({})


def end(token: Optional[contextvars.Token] = None) -> None:
    """Tear down the capture store installed by :func:`begin`."""
    try:
        if token is not None:
            _STORE.reset(token)
        else:
            _STORE.set(None)
    except (LookupError, ValueError):
        # Token from a different context — best-effort clear instead.
        _STORE.set(None)


def active() -> bool:
    """True when a scan capture store is installed."""
    return _STORE.get() is not None


def record(url: str, status: int, body: str) -> None:
    """Record the proof transaction for ``url``. No-op outside a scan scope.

    Empty transactions (``status<=0`` and no body — a dead or timed-out probe)
    are never recorded: an unproved URL must not masquerade as a captured
    response."""
    store = _STORE.get()
    if store is None or not url:
        return
    if (status is None or status <= 0) and not body:
        return
    if len(store) >= _MAX_ENTRIES:
        # Simplest bound that never unboundedly grows; the newest scan traffic
        # is the most relevant to the findings being attached.
        store.clear()
    store[url] = (int(status or 0), (body or "")[:_MAX_BODY])


def get(url: str) -> Optional[tuple[int, str]]:
    """Return the recorded ``(status, body)`` for ``url`` if any."""
    store = _STORE.get()
    if store is None:
        return None
    return store.get(url)


def _candidate_urls(finding: dict) -> list[str]:
    """URLs a finding might have been proved on, most-specific first."""
    ev = finding.get("evidence") or {}
    out = []
    for u in (finding.get("target"), finding.get("request_url"),
              finding.get("url"), ev.get("request_url") if isinstance(ev, dict) else None,
              ev.get("url") if isinstance(ev, dict) else None):
        if isinstance(u, str) and u and u not in out:
            out.append(u)
    return out


def _as_int(value: Any) -> Optional[int]:
    """Best-effort int() of a status value; None if it is missing/unparseable."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def attach(finding: dict) -> bool:
    """Fold the captured transaction into one finding's evidence, in place.

    Only fills gaps: an existing ``status`` / ``response_body`` /
    ``response_excerpt`` is never overwritten. Returns True when something was
    attached. Findings whose URL was never fetched are left untouched."""
    if not isinstance(finding, dict):
        return False
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    has_status = bool(ev.get("status"))
    has_body = bool(ev.get("response_body") or ev.get("response_excerpt")
                    or finding.get("response_snippet"))
    if has_status and has_body:
        return False  # already complete
    recorded_status = ev.get("status")
    for url in _candidate_urls(finding):
        hit = get(url)
        if hit is None:
            continue
        status, body = hit
        # If the finding recorded its OWN status and the captured transaction's
        # status differs, this capture is a DIFFERENT request to the same URL
        # (e.g. a later race/POST probe that got a 405), not the proof of THIS
        # finding. Attaching its body would show a response that contradicts the
        # finding's own status (a status-200 detection with a "405 Method Not
        # Allowed" body), so skip it — an absent body is more honest than a
        # mismatched one.
        if has_status and status > 0 and _as_int(recorded_status) not in (None, status):
            continue
        changed = False
        if not has_status and status > 0:
            ev.setdefault("status", status)
            changed = True
        if not has_body and body:
            ev.setdefault("response_body", body)
            changed = True
        if changed:
            finding["evidence"] = ev
            return True
    return False


def attach_all(findings: list[dict]) -> int:
    """Attach captured responses to every finding that is missing one.

    Returns the number of findings enriched. Safe to call when no store is
    active (returns 0)."""
    if not active() or not findings:
        return 0
    return sum(1 for f in findings if attach(f))
