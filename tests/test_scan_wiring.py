"""Regression tests for the authenticated-scan + scan-performance wiring fixes
(found via the live DVWA benchmark):

  * aiohttp_session_kwargs must deliver cookies as a flat `cookies=` dict, NOT a
    pre-filled cookie_jar (a jar built with update_cookies() has no domain, so
    aiohttp never sends the cookies → scanners silently hit protected pages
    unauthenticated and find nothing).
  * fuzz_targets must collapse payload-varying URLs to unique paths and cap the
    count, so the web-fuzz phase stays bounded (it was timing out at 600s).
"""

from __future__ import annotations

import pytest


def test_aiohttp_session_kwargs_uses_cookies_not_jar():
    from heaven.recon.auth_session import (
        AuthSession, aiohttp_session_kwargs, clear_active_session, set_active_session,
    )
    try:
        set_active_session(AuthSession(
            cookies={"PHPSESSID": "abc123", "security": "low"},
            headers={"X-Auth": "1"}, label="t"))
        kw = aiohttp_session_kwargs()
        # The bug: returning cookie_jar (domain-less) → cookies never sent.
        assert "cookie_jar" not in kw
        assert kw.get("cookies") == {"PHPSESSID": "abc123", "security": "low"}
        assert kw.get("headers") == {"X-Auth": "1"}
    finally:
        clear_active_session()
    assert aiohttp_session_kwargs() == {}


@pytest.mark.asyncio
async def test_fuzz_targets_collapses_payload_urls(monkeypatch):
    from heaven.vulnscan import web_fuzzer
    called: list[str] = []

    async def fake_fuzz_url(url, aggressive=False):
        called.append(url)
        return {"findings": []}

    monkeypatch.setattr(web_fuzzer, "fuzz_url", fake_fuzz_url)
    # 100 payload-varying URLs on ONE path → must collapse to a single fuzz call.
    urls = [f"http://h/search?q=payload{i}" for i in range(100)]
    await web_fuzzer.fuzz_targets(urls)
    assert len(called) == 1, f"payload-varying URLs must collapse to 1, got {len(called)}"


@pytest.mark.asyncio
async def test_fuzz_targets_caps_distinct_paths(monkeypatch):
    from heaven.vulnscan import web_fuzzer
    called: list[str] = []

    async def fake_fuzz_url(url, aggressive=False):
        called.append(url)
        return {"findings": []}

    monkeypatch.setattr(web_fuzzer, "fuzz_url", fake_fuzz_url)
    urls = [f"http://h/page{i}" for i in range(100)]  # 100 distinct paths
    await web_fuzzer.fuzz_targets(urls, max_urls=40)
    assert len(called) == 40, f"distinct paths must cap at max_urls=40, got {len(called)}"
