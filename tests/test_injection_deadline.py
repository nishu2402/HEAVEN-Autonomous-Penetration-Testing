"""Injection sweep must degrade gracefully under a slow target.

A slow or rate-limited host (an emulated VM, a WAF-throttled origin) can push
the injection sweep past the orchestrator's hard per-task timeout. That used to
cancel the coroutine and DISCARD every finding gathered so far, so the scan
reported zero injection on a vulnerable app and the dependent IDOR scan was
skipped as "failed". The scanner now honours a soft wall-clock deadline and
RETURNS the findings it already proved.

See heaven/vulnscan/injection_scanner.py (InjectionScanner deadline_s).
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan.injection_scanner import InjectionScanner


class _SlowScanner(InjectionScanner):
    """Records a finding per URL immediately, then hangs well past the deadline.
    No network I/O — deterministic and offline."""

    async def _scan_url(self, session, url, forms=None):  # type: ignore[override]
        self._add_finding(
            target=url, vuln_type="sqli", title="SQLi",
            severity="critical", confidence=0.9,
            evidence={"param": "id"}, remediation="", cwe="CWE-89",
        )
        await asyncio.sleep(30)  # would blow any real budget


class _FastScanner(InjectionScanner):
    async def _scan_url(self, session, url, forms=None):  # type: ignore[override]
        self._add_finding(
            target=url, vuln_type="xss", title="XSS",
            severity="high", confidence=0.8,
            evidence={"param": "q"}, remediation="", cwe="CWE-79",
        )


def test_soft_deadline_returns_partial_findings():
    scanner = _SlowScanner(concurrency=5, deadline_s=0.2)
    res = asyncio.run(scanner.scan(["http://t/a", "http://t/b", "http://t/c"]))
    # The sweep hit the deadline but returned normally (no cancellation escaped).
    assert res["partial"] is True
    assert res["urls_tested"] == 3
    # Every URL recorded its finding before hanging, so all three survive.
    assert len(res["findings"]) == 3
    assert {f["vuln_type"] for f in res["findings"]} == {"sqli"}


def test_no_deadline_completes_normally():
    scanner = _FastScanner(concurrency=5)  # deadline_s=None → unbounded, as before
    res = asyncio.run(scanner.scan(["http://t/a", "http://t/b"]))
    assert res["partial"] is False
    assert len(res["findings"]) == 2


def test_param_bearing_urls_are_scanned_first():
    """A deadline-truncated sweep must spend its budget where a finding can
    actually surface: URLs with a query string or a POST form come before bare
    URLs. Without this ordering the injection sweep on a slow target burns out
    on param-less pages and returns nothing (observed live)."""
    order: list[str] = []

    class _RecordOrder(InjectionScanner):
        async def _scan_url(self, session, url, forms=None):  # type: ignore[override]
            order.append(url)  # sync record before any await → creation order

    scanner = _RecordOrder(concurrency=5)
    targets = ["http://t/a", "http://t/b?id=1", "http://t/c", "http://t/form"]
    forms = {"http://t/form": [{"action": "http://t/form", "method": "POST",
                                "fields": [{"name": "x", "value": "1"}]}]}
    asyncio.run(scanner.scan(targets, forms_by_url=forms))

    # Both injectable URLs are visited before either bare URL.
    last_surface = max(order.index("http://t/b?id=1"), order.index("http://t/form"))
    first_bare = min(order.index("http://t/a"), order.index("http://t/c"))
    assert last_surface < first_bare
