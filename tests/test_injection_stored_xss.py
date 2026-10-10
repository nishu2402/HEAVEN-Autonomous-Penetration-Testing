"""Regression: the stored-XSS detector must actually be able to fire.

``_test_xss_stored`` submits a UNIQUE per-request canary (``HVNSTORED…``) and
then re-fetches the page to prove persistence. It calls ``_xss_is_executable``
to confirm the stored markup survives unescaped. That helper used to hard-code
the shared reflected-probe canary (``h3av3n``), so a stored payload carrying a
different canary could NEVER satisfy it: the detector was wired into the scan
(see InjectionScanner._scan_url) yet structurally dead, and a write-only stored
sink shown on a later GET was silently missed.

The helper now takes the payload's own canary. These tests pin that a genuine
stored sink is reported, an escaping sink is not, and a non-persistent reflection
is not.
"""
from __future__ import annotations

import pytest

import heaven.vulnscan.injection_scanner as ij


@pytest.mark.asyncio
async def test_raw_stored_reflection_is_stored_xss(monkeypatch):
    store: dict[str, str] = {}

    async def fake_post(session, url, data, headers=None, timeout=8.0):
        # The guestbook stores the submitted value verbatim.
        store["last"] = next((v for v in data.values()
                              if isinstance(v, str) and "HVNSTORED" in v), "")
        return 200, "<html>saved</html>"

    async def fake_get(session, url, headers=None, timeout=8.0):
        # A fresh GET (no payload) renders the stored value RAW — executable.
        return 200, f"<div class=comment>{store.get('last', '')}</div>"

    monkeypatch.setattr(ij, "_post", fake_post)
    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_xss_stored(object(), "http://t/guestbook", "message", {})
    assert any(f["vuln_type"] == "xss_stored" for f in sc._findings), sc._findings
    f = next(f for f in sc._findings if f["vuln_type"] == "xss_stored")
    assert f["severity"] == "critical"
    assert f["evidence"]["stored"] is True


@pytest.mark.asyncio
async def test_escaped_stored_reflection_is_not_xss(monkeypatch):
    store: dict[str, str] = {}

    async def fake_post(session, url, data, headers=None, timeout=8.0):
        store["last"] = next((v for v in data.values()
                              if isinstance(v, str) and "HVNSTORED" in v), "")
        return 200, "<html>saved</html>"

    async def fake_get(session, url, headers=None, timeout=8.0):
        # Stored, but HTML-escaped on render: the canary persists yet is inert.
        escaped = (store.get("last", "").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;"))
        return 200, f"<div class=comment>{escaped}</div>"

    monkeypatch.setattr(ij, "_post", fake_post)
    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_xss_stored(object(), "http://t/guestbook", "message", {})
    assert sc._findings == [], "an escaped stored reflection must not be flagged XSS"


@pytest.mark.asyncio
async def test_non_persistent_reflection_is_not_stored_xss(monkeypatch):
    async def fake_post(session, url, data, headers=None, timeout=8.0):
        return 200, "<html>saved</html>"

    async def fake_get(session, url, headers=None, timeout=8.0):
        # The payload was NOT persisted — the refetch does not contain the canary.
        return 200, "<div class=comment>no comments yet</div>"

    monkeypatch.setattr(ij, "_post", fake_post)
    monkeypatch.setattr(ij, "_get", fake_get)
    sc = ij.InjectionScanner()
    await sc._test_xss_stored(object(), "http://t/guestbook", "message", {})
    assert sc._findings == [], "no persistence → no stored-XSS finding"


def test_xss_is_executable_honours_payload_canary():
    # Stored path: a non-default canary wrapped in raw <script> is executable.
    assert ij._xss_is_executable(
        "<script>HVNSTOREDdeadbeef</script>",
        "<div><script>HVNSTOREDdeadbeef</script></div>",
        "HVNSTOREDdeadbeef") is True
    # Escaped → not executable.
    assert ij._xss_is_executable(
        "<script>HVNSTOREDdeadbeef</script>",
        "<div>&lt;script&gt;HVNSTOREDdeadbeef&lt;/script&gt;</div>",
        "HVNSTOREDdeadbeef") is False
    # Default reflected canary still works unchanged.
    assert ij._xss_is_executable(
        f'<script>alert("{ij._XSS_CANARY}")</script>',
        f'<p><script>alert("{ij._XSS_CANARY}")</script></p>') is True
