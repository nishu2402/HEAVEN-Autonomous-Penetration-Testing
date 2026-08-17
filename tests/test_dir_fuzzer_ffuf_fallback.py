"""dir_fuzzer: ffuf delegation must never silently zero out discovery.

Live regression: on a host with an installed ffuf whose CLI dropped the
``-silent`` flag (ffuf 2.x), ``_run_ffuf`` aborted with "flag provided but not
defined", wrote no output, and returned zero — while the working native async
engine was skipped because ffuf was *present*. Net effect: directory brute-force
found nothing on a target that plainly had discoverable paths.

The fix: ``_run_ffuf`` returns ``None`` on any failure (missing binary, non-zero
exit, unparseable output) — distinct from ``[]`` ("ran, found nothing") — and
``fuzz`` falls back to the native engine for exactly those targets. HIT_CODES
already spans the 200/300/403 bands the report cares about.
"""
from __future__ import annotations

import pytest

from heaven.vulnscan import dir_fuzzer as DF
from heaven.vulnscan.dir_fuzzer import DirectoryFuzzer


def test_hit_codes_span_200_300_403_bands():
    codes = set(DF.HIT_CODES)
    assert any(200 <= c < 300 for c in codes)     # 200 band
    assert any(300 <= c < 400 for c in codes)     # 300 band
    assert 403 in codes                           # 403 explicitly
    # honest 404/410 are misses, never reported as hits
    assert 404 not in codes and 410 not in codes


@pytest.mark.asyncio
async def test_ffuf_never_passes_the_removed_silent_flag(monkeypatch):
    """The exact live bug: ffuf 2.x has no -silent flag; passing it aborts ffuf."""
    captured = {}

    class _Proc:
        returncode = 0
        async def communicate(self):
            return (b"", b"")

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _Proc()

    monkeypatch.setattr(DF.shutil, "which", lambda _b: "/usr/bin/ffuf")
    monkeypatch.setattr(DF.asyncio, "create_subprocess_exec", fake_exec)
    # ffuf "runs" but writes no results file → returns None (couldn't parse).
    fz = DirectoryFuzzer()
    await fz._run_ffuf("http://t/")
    assert "-silent" not in captured["cmd"], captured["cmd"]
    assert "-mc" in captured["cmd"] and "-ac" in captured["cmd"]


@pytest.mark.asyncio
async def test_ffuf_failure_falls_back_to_native(monkeypatch):
    """When ffuf can't run (returns None), fuzz must cover that target natively —
    not report zero."""
    monkeypatch.setattr(DF.shutil, "which", lambda _b: "/usr/bin/ffuf")

    fz = DirectoryFuzzer()

    async def broken_ffuf(url, timeout=300):
        return None  # simulate the -silent abort / non-zero exit

    native_hit = {
        "target": "http://t/admin", "vuln_type": "sensitive_file",
        "title": "admin", "severity": "high", "confidence": 0.9,
        "evidence": {"status_code": 403},
    }

    async def native(session, url):
        return [native_hit]

    monkeypatch.setattr(fz, "_run_ffuf", broken_ffuf)
    monkeypatch.setattr(fz, "_scan_target", native)

    result = await fz.fuzz(["http://t/"])
    assert result["error"] is None
    assert result["findings"] == [native_hit], "native fallback must cover ffuf failure"


@pytest.mark.asyncio
async def test_ffuf_success_is_trusted_no_double_scan(monkeypatch):
    """A target ffuf handled and simply found nothing on ([]) is NOT re-scanned."""
    monkeypatch.setattr(DF.shutil, "which", lambda _b: "/usr/bin/ffuf")
    fz = DirectoryFuzzer()

    async def empty_ffuf(url, timeout=300):
        return []  # ran fine, nothing found

    called = {"native": 0}

    async def native(session, url):
        called["native"] += 1
        return []

    monkeypatch.setattr(fz, "_run_ffuf", empty_ffuf)
    monkeypatch.setattr(fz, "_scan_target", native)

    result = await fz.fuzz(["http://t/"])
    assert result["error"] is None
    assert result["findings"] == []
    assert called["native"] == 0, "must not re-scan a target ffuf already covered"


def test_dedup_preserves_first_and_drops_repeat_targets():
    findings = [
        {"target": "http://t/a", "severity": "low"},
        {"target": "http://t/a", "severity": "high"},   # dup URL
        {"target": "http://t/b", "severity": "info"},
        {"target": "", "severity": "info"},              # empty dropped
    ]
    out = DirectoryFuzzer._dedup(findings)
    assert [f["target"] for f in out] == ["http://t/a", "http://t/b"]
