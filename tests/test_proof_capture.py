"""Regression tests for scan-scoped HTTP proof capture.

These lock in the fix for "Proof of issue always shows HTTP 0 (0 bytes) — no
response captured": a web detector's real request/response must be folded into
its findings' evidence, so the report/UI render the transaction that proved the
finding rather than a fabricated empty one.
"""
from __future__ import annotations

import asyncio

from heaven.vulnscan import proof_capture as pc


def test_record_is_noop_outside_scan_scope() -> None:
    """No store installed → record does nothing and never raises."""
    pc.end()  # ensure no active store
    assert pc.active() is False
    pc.record("http://x/", 200, "body")  # must not raise
    assert pc.get("http://x/") is None


def test_record_and_attach_fills_gaps() -> None:
    token = pc.begin()
    try:
        pc.record("http://t/a?id=1", 200, "<html>proof</html>")
        finding = {"target": "http://t/a?id=1", "vuln_type": "sqli",
                   "evidence": {"param": "id"}}
        assert pc.attach(finding) is True
        assert finding["evidence"]["status"] == 200
        assert finding["evidence"]["response_body"] == "<html>proof</html>"
    finally:
        pc.end(token)


def test_attach_never_overwrites_existing_evidence() -> None:
    token = pc.begin()
    try:
        pc.record("http://t/b", 500, "captured")
        finding = {"target": "http://t/b",
                   "evidence": {"status": 200, "response_body": "original"}}
        assert pc.attach(finding) is False
        assert finding["evidence"]["status"] == 200
        assert finding["evidence"]["response_body"] == "original"
    finally:
        pc.end(token)


def test_empty_transaction_is_not_recorded() -> None:
    """A dead probe (status 0, empty body) must never masquerade as a response."""
    token = pc.begin()
    try:
        pc.record("http://t/dead", 0, "")
        assert pc.get("http://t/dead") is None
        finding = {"target": "http://t/dead", "evidence": {}}
        assert pc.attach(finding) is False
    finally:
        pc.end(token)


def test_attach_matches_evidence_url_fallback() -> None:
    """A POST finding whose target is the base URL still matches via evidence.url."""
    token = pc.begin()
    try:
        pc.record("http://t/login", 200, "welcome")
        finding = {"target": "http://t/other",
                   "evidence": {"url": "http://t/login"}}
        assert pc.attach(finding) is True
        assert finding["evidence"]["status"] == 200
    finally:
        pc.end(token)


def test_scan_scopes_are_isolated_across_tasks() -> None:
    """Two concurrent scan contexts must not see each other's captures."""
    async def scan(mark: str) -> tuple[int, object]:
        token = pc.begin()
        try:
            await asyncio.sleep(0)  # yield so both tasks interleave
            pc.record(f"http://t/{mark}", 200, mark)
            await asyncio.sleep(0)
            # This scope must only see its own capture.
            return (len(pc._STORE.get() or {}), pc.get(f"http://t/{mark}"))
        finally:
            pc.end(token)

    async def main() -> None:
        a, b = await asyncio.gather(scan("A"), scan("B"))
        assert a[0] == 1 and a[1] == (200, "A")
        assert b[0] == 1 and b[1] == (200, "B")

    asyncio.run(main())
