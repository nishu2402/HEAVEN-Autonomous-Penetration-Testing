"""
Stealth-level genuineness tests.

The web launcher / CLI expose four stealth levels (paranoid / stealth / normal /
aggressive). These tests prove the selection is NOT cosmetic: each level resolves
a distinct evasion profile and every scanner that accepts ``stealth_level`` turns
it into a real, observable behaviour change (concurrency + inter-request delay +
evasion posture). They also lock in the ``profile_for`` footgun fix — the bare
``EvasionProfile(stealth_level=…)`` constructor left all timing at 0, which used
to make stealth a no-op in the crawler / adaptive-intel paths.
"""

from __future__ import annotations

import pytest

from heaven.recon.evasion_engine import (
    StealthLevel,
    evasion_delay,
    get_profile,
    profile_for,
    resolve_stealth_level,
)


# ── evasion_engine core ────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("paranoid", StealthLevel.PARANOID),
    ("stealth", StealthLevel.STEALTH),
    ("normal", StealthLevel.NORMAL),
    ("aggressive", StealthLevel.AGGRESSIVE),
    ("PARANOID", StealthLevel.PARANOID),      # case-insensitive
    ("  Stealth ", StealthLevel.STEALTH),      # trimmed
    ("", StealthLevel.NORMAL),                 # empty → safe default
    ("nonsense", StealthLevel.NORMAL),         # unknown → safe default
    (StealthLevel.AGGRESSIVE, StealthLevel.AGGRESSIVE),  # enum passthrough
])
def test_resolve_stealth_level(value, expected):
    assert resolve_stealth_level(value) is expected


def test_profile_for_returns_configured_copy():
    """profile_for must return the fully-configured template — but a *copy*, so a
    caller (e.g. the long-lived API server) can never corrupt the shared profile."""
    p = profile_for("paranoid")
    template = get_profile(StealthLevel.PARANOID)
    assert p.max_concurrent == template.max_concurrent == 10
    assert p.max_delay_ms == template.max_delay_ms > 0
    assert p is not template  # a copy, not the shared singleton

    p.max_concurrent = 123_456
    assert get_profile(StealthLevel.PARANOID).max_concurrent == 10  # uncorrupted


def test_profiles_are_monotonic_by_stealth():
    """Stealthier ⇒ fewer concurrent connections AND longer delays."""
    order = ["aggressive", "normal", "stealth", "paranoid"]
    concurrency = [profile_for(x).max_concurrent for x in order]
    max_delay = [profile_for(x).max_delay_ms for x in order]
    assert concurrency == sorted(concurrency, reverse=True), concurrency
    assert max_delay == sorted(max_delay), max_delay
    # Aggressive is the only level that skips UA rotation (fast/loud lab use).
    assert profile_for("aggressive").rotate_user_agents is False
    assert profile_for("paranoid").rotate_user_agents is True


@pytest.mark.asyncio
async def test_evasion_delay_scales_with_level(monkeypatch):
    """The inter-request delay is a real sleep for stealthy levels and zero for
    aggressive (previously a no-op for every level via the bare-profile bug)."""
    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("heaven.recon.evasion_engine.asyncio.sleep", fake_sleep)

    await evasion_delay(profile_for("aggressive"))
    assert slept == []  # aggressive never pauses

    await evasion_delay(profile_for("paranoid"))
    assert slept and slept[0] > 0  # paranoid genuinely sleeps


# ── web_crawler: concurrency now honours the profile ───────────────────────

@pytest.mark.asyncio
async def test_crawl_targets_concurrency_tracks_level(monkeypatch):
    from heaven.recon import web_crawler

    captured: dict[str, int] = {}

    async def fake_crawl_url(url, semaphore=None, evasion_headers=None, auth_config=None):
        # Semaphore._value is the remaining permit count == the initial ceiling
        # here (nothing has acquired it yet). This is the concurrency the crawl
        # will actually use.
        captured["permits"] = semaphore._value
        return []

    async def fake_discover_apis(url, timeout=10.0, evasion_headers=None):
        return []

    async def fake_extract(js_files):
        return []

    async def no_delay(self):
        return None

    monkeypatch.setattr(web_crawler, "crawl_url", fake_crawl_url)
    monkeypatch.setattr(web_crawler, "discover_apis", fake_discover_apis)
    monkeypatch.setattr(web_crawler, "extract_js_endpoints", fake_extract)
    monkeypatch.setattr(web_crawler.EvasionEngine, "apply_evasion_delay", no_delay)

    await web_crawler.crawl_targets(["http://h/"], stealth_level="paranoid")
    assert captured["permits"] == 10  # was hardcoded 100 before the fix

    await web_crawler.crawl_targets(["http://h/"], stealth_level="aggressive")
    assert captured["permits"] == 1000


# ── adaptive_intel: header posture now matches the level ───────────────────

@pytest.mark.asyncio
async def test_adaptive_intel_header_posture(monkeypatch):
    """AGGRESSIVE must NOT rotate the User-Agent; PARANOID must. The old bare
    profile always rotated, regardless of level."""
    from heaven.recon import adaptive_intel

    engine = adaptive_intel.AdaptiveIntelligence()

    class _Resp:
        status = 200
        headers: dict[str, str] = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def text(self):
            return "<html></html>"

    captured_ua: dict[str, str] = {}

    class _Session:
        def get(self, url, headers=None, timeout=None, **kw):
            captured_ua["ua"] = headers.get("User-Agent", "")
            return _Resp()

    async def fake_waf(self, session, url):
        return None

    monkeypatch.setattr(adaptive_intel.AdaptiveIntelligence, "fingerprint_waf", fake_waf)

    # Aggressive: the fixed, non-rotated first UA in the table.
    from heaven.recon.evasion_engine import USER_AGENTS
    await engine.profile_target(_Session(), "http://h/", stealth_level="aggressive")
    assert captured_ua["ua"] == USER_AGENTS[0]

    # Paranoid: rotation is on — UA is drawn from the pool (still a valid entry).
    await engine.profile_target(_Session(), "http://h/", stealth_level="paranoid")
    assert captured_ua["ua"] in USER_AGENTS


# ── web_fuzzer: 4 distinct levels, not a stealthy/loud binary ──────────────

@pytest.mark.asyncio
async def test_fuzz_targets_toggles_param_discovery(monkeypatch):
    from heaven.vulnscan import web_fuzzer

    seen: dict[str, bool] = {}

    async def fake_fuzz_url(url, aggressive=False):
        seen["aggressive"] = aggressive
        return {"findings": []}

    monkeypatch.setattr(web_fuzzer, "fuzz_url", fake_fuzz_url)

    await web_fuzzer.fuzz_targets(["http://h/a"], stealth_level="paranoid")
    assert seen["aggressive"] is False  # quiet: no parameter discovery

    await web_fuzzer.fuzz_targets(["http://h/a"], stealth_level="aggressive")
    assert seen["aggressive"] is True   # loud: parameter discovery on

    # An explicit aggressive= still wins over the level default.
    await web_fuzzer.fuzz_targets(["http://h/a"], aggressive=True, stealth_level="paranoid")
    assert seen["aggressive"] is True


@pytest.mark.asyncio
async def test_fuzz_targets_applies_inter_request_delay(monkeypatch):
    from heaven.vulnscan import web_fuzzer

    async def fake_fuzz_url(url, aggressive=False):
        return {"findings": []}

    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(web_fuzzer, "fuzz_url", fake_fuzz_url)
    monkeypatch.setattr(web_fuzzer.asyncio, "sleep", fake_sleep)

    await web_fuzzer.fuzz_targets(["http://h/a"], stealth_level="paranoid")
    assert slept and slept[0] == 1.0

    slept.clear()
    await web_fuzzer.fuzz_targets(["http://h/a"], stealth_level="aggressive")
    assert slept == []  # aggressive never sleeps


# ── idor / dir_fuzzer / injection: concurrency + delay threaded per level ──

@pytest.mark.asyncio
async def test_scan_for_idor_threads_concurrency_and_delay(monkeypatch):
    from heaven.vulnscan import idor_scanner

    captured: dict[str, float] = {}

    class FakeScanner:
        def __init__(self, concurrency=20, auth_headers=None,
                     alt_auth_headers=None, request_delay=0.0):
            captured["concurrency"] = concurrency
            captured["delay"] = request_delay

        async def scan(self, targets, forms_by_url=None):
            return {"findings": []}

    monkeypatch.setattr(idor_scanner, "IDORScanner", FakeScanner)

    await idor_scanner.scan_for_idor(["http://h/x?id=1"], stealth_level="paranoid")
    assert captured == {"concurrency": 5, "delay": 1.0}

    await idor_scanner.scan_for_idor(["http://h/x?id=1"], stealth_level="aggressive")
    assert captured == {"concurrency": 40, "delay": 0.0}


@pytest.mark.asyncio
async def test_fuzz_directories_threads_concurrency_and_delay(monkeypatch):
    from heaven.vulnscan import dir_fuzzer

    captured: dict[str, float] = {}

    class FakeFuzzer:
        def __init__(self, concurrency=30, request_delay=0.0, extensions=None):
            captured["concurrency"] = concurrency
            captured["delay"] = request_delay

        async def fuzz(self, targets):
            return {"findings": []}

    monkeypatch.setattr(dir_fuzzer, "DirectoryFuzzer", FakeFuzzer)

    await dir_fuzzer.fuzz_directories(["http://h/"], stealth_level="paranoid")
    assert captured == {"concurrency": 5, "delay": 1.5}

    await dir_fuzzer.fuzz_directories(["http://h/"], stealth_level="stealth")
    assert captured == {"concurrency": 15, "delay": 0.3}


@pytest.mark.asyncio
async def test_scan_for_injections_threads_concurrency_and_delay(monkeypatch):
    from heaven.vulnscan import injection_scanner

    captured: dict[str, float] = {}

    real_init = injection_scanner.InjectionScanner.__init__

    def spy_init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        captured["concurrency"] = self._sem._value
        captured["delay"] = self._delay

    async def fake_scan(self, *a, **kw):
        return {"findings": [], "vulnerabilities": []}

    monkeypatch.setattr(injection_scanner.InjectionScanner, "__init__", spy_init)
    monkeypatch.setattr(injection_scanner.InjectionScanner, "scan", fake_scan)

    await injection_scanner.scan_for_injections(["http://h/x?id=1"], stealth_level="paranoid")
    assert captured["delay"] > 0 and captured["concurrency"] <= 10

    await injection_scanner.scan_for_injections(["http://h/x?id=1"], stealth_level="aggressive")
    assert captured["delay"] == 0.0 and captured["concurrency"] >= 20
