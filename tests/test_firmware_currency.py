"""Tests for the curated software/firmware currency dataset (`firmware_currency`).

Covers the OpenSSH case (a widely deployed daemon endoflife.date does not track)
and the honesty guarantees: a finding fires only on an observed version that is
genuinely behind the curated latest, never on a current/newer host, and the raw
SSH banner's *protocol* version ("SSH-2.0-...") is never mistaken for the software
version. Also exercises the integration path through `scan_eol_from_net`.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import eol_scanner as eol
from heaven.vulnscan.firmware_currency import (
    _OPENSSH_LATEST,
    _openssh_version,
    firmware_currency_finding,
)


def _run(coro):
    return asyncio.run(coro)


# ── version extraction ─────────────────────────────────────────────────────────

def test_openssh_version_ignores_protocol_version():
    # The "2.0" in "SSH-2.0-OpenSSH_8.2p1" is the transport protocol, NOT the
    # software version — the extractor must read 8.2, never 2.0.
    assert _openssh_version("ssh-2.0-openssh_8.2p1 ubuntu-4ubuntu0.11") == (8, 2)
    assert _openssh_version("openssh 9.6") == (9, 6)
    assert _openssh_version("openssh_7.4") == (7, 4)
    assert _openssh_version("no ssh here") is None


def test_openssh_latest_not_flagged():
    # A host on the current release (or newer) is never flagged.
    assert firmware_currency_finding("h:22", "OpenSSH", _OPENSSH_LATEST,
                                     f"OpenSSH {_OPENSSH_LATEST}") is None


def test_openssh_recent_release_below_age_floor():
    # 10.2 shipped < 12 months before the dataset date → below the age floor, so we
    # do not nag about being one train behind.
    assert firmware_currency_finding("h:22", "OpenSSH", "10.2", "OpenSSH 10.2") is None


def test_openssh_old_banner_flagged_low_with_caveat():
    f = firmware_currency_finding("h:22", "OpenSSH", "9.6", "OpenSSH 9.6")
    assert f is not None
    assert f["vuln_type"] == "outdated_patch_level"
    assert f["severity"] == "low"                    # backport caveat → low, never high
    assert f["evidence"]["detected_version"] == "9.6"
    assert f["evidence"]["latest_version"] == _OPENSSH_LATEST
    assert f["evidence"]["months_behind"] >= 12
    assert "backport" in f["description"].lower()    # honest caveat present
    assert "confirm" in f["description"].lower()


def test_openssh_raw_banner_flagged():
    f = firmware_currency_finding(
        "h:22", "", "", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11")
    assert f is not None
    assert f["evidence"]["detected_version"] == "8.2"


def test_non_openssh_product_no_finding():
    assert firmware_currency_finding("h:80", "nginx", "1.20", "nginx/1.20") is None


# ── integration through scan_eol_from_net ───────────────────────────────────────

@pytest.fixture(autouse=True)
def _enable_currency(monkeypatch):
    eol._EOL_CACHE.clear()
    # The curated currency layer honours the same passive-intel gate as the live
    # feed; enable it here (the feed itself is mocked empty, offline & deterministic).
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")

    async def _empty(slug, **kw):
        return []                                    # openssh → 404 in reality
    monkeypatch.setattr(eol, "_endoflife_lookup", _empty)
    yield
    eol._EOL_CACHE.clear()


def _net(product, version, banner, port=22):
    return {"hosts": [{"host": "45.33.32.156", "ip": "45.33.32.156",
                       "open_ports": [{"port": port, "product": product,
                                       "version": version, "banner": banner}]}]}


def test_scan_eol_surfaces_old_openssh():
    res = _run(eol.scan_eol_from_net(_net("OpenSSH", "8.2", "OpenSSH 8.2")))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "outdated_patch_level"
    assert f["evidence"]["product"] == "OpenSSH"


def test_scan_eol_silent_on_current_openssh():
    res = _run(eol.scan_eol_from_net(
        _net("OpenSSH", _OPENSSH_LATEST, f"OpenSSH {_OPENSSH_LATEST}")))
    assert res["total"] == 0


def test_scan_eol_currency_gated_off_when_passive_disabled(monkeypatch):
    # With passive intel off (as in the suite default), the curated currency layer
    # is silent — an old OpenSSH banner does not raise a finding.
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "1")
    res = _run(eol.scan_eol_from_net(_net("OpenSSH", "8.2", "OpenSSH 8.2")))
    assert res["total"] == 0
