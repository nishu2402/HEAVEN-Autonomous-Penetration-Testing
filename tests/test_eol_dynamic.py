"""Tests for the dynamic (endoflife.date) EOL layer in `eol_scanner.py`.

The static `_PRODUCT_EOL` table is curated but finite. The live endoflife.date
feed lets HEAVEN flag an end-of-life component that isn't in the hand-maintained
list — the "if it's on the target but not in our DB, don't miss it" case — while
still firing ONLY on a real, published EOL date (never a guess). The static table
remains the offline fallback.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.vulnscan import eol_scanner as eol


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    eol._EOL_CACHE.clear()
    # Re-enable the dynamic EOL feed (conftest disables it suite-wide); the feed
    # is mocked in every test here, so it stays deterministic and offline.
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "0")
    yield
    eol._EOL_CACHE.clear()


def _net(product, version, banner="", port=80):
    return {"hosts": [{"host": "45.33.32.156", "ip": "45.33.32.156",
                       "open_ports": [{"port": port, "product": product,
                                       "version": version, "banner": banner}]}]}


def _mock_feed(monkeypatch, cycles):
    async def fake(slug, **kw):
        return cycles
    monkeypatch.setattr(eol, "_endoflife_lookup", fake)


# ── cycle-matching units ──────────────────────────────────────────────────────

def test_cycle_status_variants():
    assert eol._cycle_status({"cycle": "1.0", "eol": True}) == ("", "1.0", True)
    assert eol._cycle_status({"cycle": "1.0", "eol": False}) == ("", "1.0", False)
    past = eol._cycle_status({"cycle": "1.20", "eol": "2000-01-01"})
    assert past == ("2000-01-01", "1.20", True)
    future = eol._cycle_status({"cycle": "9.9", "eol": "2999-01-01"})
    assert future == ("2999-01-01", "9.9", False)
    assert eol._cycle_status({"cycle": "1.0", "eol": None}) is None


def test_match_cycle_prefers_minor():
    cycles = [{"cycle": "1.20", "eol": "2000-01-01"},
              {"cycle": "1", "eol": True}]
    assert eol._match_cycle(cycles, (1, 20, 1))[1] == "1.20"


# ── dynamic gap-fill findings ─────────────────────────────────────────────────

def test_dynamic_flags_past_eol_product(monkeypatch):
    # nginx isn't in the static table → the live feed supplies the EOL fact.
    _mock_feed(monkeypatch, [{"cycle": "1.20", "eol": "2022-05-24"}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.20.1")))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "unsupported_software"
    assert "nginx" in f["title"].lower()
    assert f["evidence"]["eol_date"] == "2022-05-24"
    assert f["evidence"]["source_feed"] == "endoflife.date"


def test_dynamic_ignores_still_supported(monkeypatch):
    _mock_feed(monkeypatch, [{"cycle": "1.27", "eol": "2999-01-01"}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.27.0")))
    assert res["total"] == 0


def test_dynamic_offline_falls_back_to_static(monkeypatch):
    # Feed is unreachable → returns []. A product covered by the STATIC table
    # (MySQL 5.7 < 8.0) is still flagged; an uncovered product (nginx) is not.
    _mock_feed(monkeypatch, [])
    res_static = _run(eol.scan_eol_from_net(_net("mysql", "5.7.44", port=3306)))
    assert res_static["total"] == 1
    assert "MySQL" in res_static["findings"][0]["title"]

    res_gap = _run(eol.scan_eol_from_net(_net("nginx", "1.20.1")))
    assert res_gap["total"] == 0


def test_dynamic_respects_kill_switch(monkeypatch):
    monkeypatch.setenv("HEAVEN_NO_PASSIVE_INTEL", "1")
    # Even though the feed *would* report EOL, the kill-switch disables it.
    _mock_feed(monkeypatch, [{"cycle": "1.20", "eol": "2000-01-01"}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.20.1")))
    assert res["total"] == 0


def test_dynamic_can_be_turned_off_by_flag(monkeypatch):
    _mock_feed(monkeypatch, [{"cycle": "1.20", "eol": "2000-01-01"}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.20.1"), dynamic=False))
    assert res["total"] == 0


def _iso_months_ago(months: int) -> str:
    from datetime import date, timedelta
    return (date.today() - timedelta(days=months * 30 + 5)).isoformat()


def test_currency_flags_behind_latest(monkeypatch):
    # Supported cycle (eol far future) but the host runs 1.27.0 while the latest
    # patch 1.27.9 has been out ~8 months → outdated_patch_level, real month lag.
    _mock_feed(monkeypatch, [{
        "cycle": "1.27", "eol": "2999-01-01",
        "latest": "1.27.9", "latestReleaseDate": _iso_months_ago(8)}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.27.0")))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "outdated_patch_level"
    assert f["evidence"]["latest_version"] == "1.27.9"
    assert f["evidence"]["months_behind"] >= 6
    assert f["severity"] == "medium"          # >= 6 months
    assert "behind latest" in f["title"]


def test_currency_recent_release_below_threshold(monkeypatch):
    # Latest patch published only ~1 month ago → below the reporting threshold.
    _mock_feed(monkeypatch, [{
        "cycle": "1.27", "eol": "2999-01-01",
        "latest": "1.27.9", "latestReleaseDate": _iso_months_ago(1)}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.27.0")))
    assert res["total"] == 0


def test_currency_on_latest_no_finding(monkeypatch):
    _mock_feed(monkeypatch, [{
        "cycle": "1.27", "eol": "2999-01-01",
        "latest": "1.27.9", "latestReleaseDate": _iso_months_ago(8)}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.27.9")))
    assert res["total"] == 0


def test_eol_takes_priority_over_currency(monkeypatch):
    # A past-EOL cycle that also has a newer patch → reported as EOL, not currency.
    _mock_feed(monkeypatch, [{
        "cycle": "1.20", "eol": "2000-01-01",
        "latest": "1.20.9", "latestReleaseDate": _iso_months_ago(8)}])
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.20.1")))
    assert res["total"] == 1
    assert res["findings"][0]["vuln_type"] == "unsupported_software"


def test_currency_no_latest_field_no_finding(monkeypatch):
    # Feed lacks latest/latestReleaseDate (e.g. fortios) → no fabricated lag.
    _mock_feed(monkeypatch, [{"cycle": "7.4", "eol": "2999-01-01"}])
    res = _run(eol.scan_eol_from_net(_net("fortios", "7.4.1")))
    assert res["total"] == 0


def test_slug_detection():
    assert eol._endoflife_slug("nginx", "") == "nginx"
    assert eol._endoflife_slug("Apache", "httpd") == "apache"
    assert eol._endoflife_slug("PostgreSQL", "") == "postgresql"
    assert eol._endoflife_slug("some-random-appliance", "") == ""
    assert eol._endoflife_slug("FortiGate", "FortiOS 7.2.5") == "fortios"


# ── appliance release-line currency (endoflife.date, no `latest` field) ─────────
# FortiOS is tracked WITHOUT a `latest` field but WITH per-cycle release dates, so
# the release-line currency path uses live dates (nothing hard-coded). Structure
# mirrors the real endoflife.date/api/fortios.json response.
# Dates are RELATIVE to today (not fixed calendar dates) so the maturity and EOL
# relationships never drift into a false verdict as time passes: 8.0 stays "too new
# to demand" (< 12 months GA), 7.6/7.4/7.2 stay mature newer lines, and every cycle
# here stays supported (eol far in the future). Hard-coding the dates instead made
# this fixture a time-bomb (8.0 would cross the 12-month maturity floor, and 7.2's
# fixed eol would lapse, flipping the assertions below on a specific calendar day).
_FORTIOS = [
    {"cycle": "8.0", "releaseDate": _iso_months_ago(5), "eol": "2999-01-01",
     "support": "2999-01-01", "lts": False},
    {"cycle": "7.6", "releaseDate": _iso_months_ago(26), "eol": "2999-01-01",
     "support": "2999-01-01", "lts": False},
    {"cycle": "7.4", "releaseDate": _iso_months_ago(42), "eol": "2999-01-01",
     "support": "2999-01-01", "lts": False},
    {"cycle": "7.2", "releaseDate": _iso_months_ago(54), "eol": "2999-01-01",
     "support": "2999-01-01", "lts": False},
]


def test_fortios_behind_release_line(monkeypatch):
    # Host on 7.2 while 7.6 has been GA well over a year → release-line currency.
    # 8.0 is too recent to demand, so the "current line" reported is the mature 7.6.
    _mock_feed(monkeypatch, _FORTIOS)
    res = _run(eol.scan_eol_from_net(
        _net("FortiGate", "7.2.5", banner="FortiOS 7.2.5", port=443)))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "outdated_patch_level"
    assert f["severity"] == "low"
    assert f["evidence"]["newer_cycle"] == "7.6"
    assert f["evidence"]["months_behind"] >= 12
    assert f["evidence"]["source_feed"] == "endoflife.date"


def test_fortios_on_newest_mature_line_no_finding(monkeypatch):
    # Host on 7.6; the only newer line (8.0) is < 12 months old → not demanded.
    _mock_feed(monkeypatch, _FORTIOS)
    res = _run(eol.scan_eol_from_net(
        _net("FortiGate", "7.6.1", banner="FortiOS 7.6.1", port=443)))
    assert res["total"] == 0


def test_fortios_eol_line_takes_priority(monkeypatch):
    # A past-EOL FortiOS line is reported as unsupported, not merely behind.
    cycles = [{"cycle": "6.4", "releaseDate": _iso_months_ago(78),
               "eol": "2000-01-01"}] + _FORTIOS
    _mock_feed(monkeypatch, cycles)
    res = _run(eol.scan_eol_from_net(
        _net("FortiGate", "6.4.9", banner="FortiOS 6.4.9", port=443)))
    assert res["total"] == 1
    assert res["findings"][0]["vuln_type"] == "unsupported_software"
