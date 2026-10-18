"""``scan_auth_targets`` time-budget salvage.

The auth audit fans out one per-URL sub-scan across every crawled page. On a
throttling host with hundreds of URLs the fan-out can outrun the orchestrator's
hard task timeout, which cancels the coroutine mid-``gather`` — the function
never reaches its ``return`` and every finding already collected is discarded,
so the task is recorded with ZERO findings (observed as the Authentication
Security Audit timing out on certifiedhacker.com over 361 crawled URLs).

With a ``time_budget`` the fan-out stops launching/awaiting further audits once
the budget elapses and RETURNS what it has, so the task completes with the
findings gathered before the deadline instead of losing all of them. These tests
pin that behaviour without any network: ``scan_auth`` is replaced with a
controllable fake (fast URLs return a finding immediately, slow URLs sleep well
past the budget).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from heaven.vulnscan import auth_scanner as A


def _finding(url: str) -> dict:
    return {"target": url, "vuln_type": "missing_security_header",
            "severity": "low", "confidence": 0.9}


@pytest.mark.asyncio
async def test_no_budget_audits_every_url(monkeypatch):
    # Baseline: with no budget the sweep audits every URL, exactly as before.
    async def fake(url, forms=None, **kw):
        return {"findings": [_finding(url)]}

    monkeypatch.setattr(A, "scan_auth", fake)
    urls = [f"http://h/{i}" for i in range(12)]
    res = await A.scan_auth_targets(urls)

    assert res["total"] == 12
    assert res["urls_audited"] == 12
    assert res["urls_requested"] == 12
    assert "budget_exhausted" not in res
    assert len(res["findings"]) == 12


@pytest.mark.asyncio
async def test_generous_budget_does_not_truncate(monkeypatch):
    # A budget larger than the (instant) work must not truncate anything.
    async def fake(url, forms=None, **kw):
        return {"findings": [_finding(url)]}

    monkeypatch.setattr(A, "scan_auth", fake)
    urls = [f"http://h/{i}" for i in range(8)]
    res = await A.scan_auth_targets(urls, time_budget=10.0)

    assert res["urls_audited"] == 8
    assert res["total"] == 8
    assert "budget_exhausted" not in res


@pytest.mark.asyncio
async def test_tiny_budget_salvages_partial_and_returns(monkeypatch):
    # Fast URLs return a finding immediately; slow URLs sleep far past the budget.
    # The sweep must RETURN promptly (not hang on the slow ones), keep the fast
    # URLs' findings, audit fewer than all URLs, and flag the truncation.
    async def fake(url, forms=None, **kw):
        if "slow" in url:
            await asyncio.sleep(10.0)
        return {"findings": [_finding(url)]}

    monkeypatch.setattr(A, "scan_auth", fake)
    urls = ([f"http://h/fast{i}" for i in range(3)]
            + [f"http://h/slow{i}" for i in range(25)])

    t0 = time.monotonic()
    # Outer guard far above the budget: proves we return on our own, not via it.
    res = await asyncio.wait_for(
        A.scan_auth_targets(urls, time_budget=0.5), timeout=5.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 4.0, f"sweep did not return on its own budget ({elapsed:.1f}s)"
    assert res.get("budget_exhausted") is True
    assert res["urls_requested"] == len(urls)
    assert res["urls_audited"] < len(urls), "budget did not cut the sweep short"
    # The three instant fast URLs are salvaged; their findings survive.
    assert res["total"] >= 3
    assert res["total"] == len(res["findings"])
