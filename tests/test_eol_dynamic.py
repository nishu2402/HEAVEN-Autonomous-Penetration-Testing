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


# ── recently-superseded fast-cadence EOL vs genuine abandonment ───────────────
# A short-lived release branch (nginx-style) retired only because a newer line
# shipped, while that newer line is still supported, is a patch-currency gap — NOT
# the abandoned-software exposure that reconcile_severity escalates to High. Dates
# are relative to today so the support-lifetime / recency relationships never drift.

def test_recently_superseded_short_lived_branch_is_currency_not_abandoned(monkeypatch):
    from heaven.utils.cvss import reconcile_severity
    eol3 = _iso_months_ago(3)
    cycles = [
        {"cycle": "1.31", "releaseDate": _iso_months_ago(3), "eol": "2999-01-01"},
        {"cycle": "1.30", "releaseDate": _iso_months_ago(4), "eol": "2999-01-01"},
        # 1.29 lived ~11 months (14mo ago → EOL 3mo ago): a fast-cadence branch.
        {"cycle": "1.29", "releaseDate": _iso_months_ago(14), "eol": eol3},
    ]
    _mock_feed(monkeypatch, cycles)
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.29.8")))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "outdated_patch_level"
    assert f["severity"] == "medium"
    assert f["evidence"]["recently_superseded"] is True
    assert f["evidence"]["newer_cycle"] == "1.31"
    assert f["evidence"]["eol_date"] == eol3
    # The whole point of the fix: reconcile_severity must NOT escalate it to the
    # High unsupported_software band (class base 7.4) — it stays Medium.
    assert reconcile_severity(dict(f))["severity"] == "medium"


def test_recent_eol_long_support_line_stays_unsupported(monkeypatch):
    from heaven.utils.cvss import reconcile_severity
    # A multi-year support line (born ~70mo ago, EOL ~6mo ago — a genuine 5-year
    # end of support, PostgreSQL-style) is NOT softened even though newer supported
    # lines exist and the EOL is recent: that line is really abandoned now.
    cycles = [
        {"cycle": "18", "releaseDate": _iso_months_ago(1), "eol": "2999-01-01"},
        {"cycle": "17", "releaseDate": _iso_months_ago(13), "eol": "2999-01-01"},
        {"cycle": "13", "releaseDate": _iso_months_ago(70), "eol": _iso_months_ago(6)},
    ]
    _mock_feed(monkeypatch, cycles)
    res = _run(eol.scan_eol_from_net(_net("postgresql", "13.1", port=5432)))
    assert res["total"] == 1
    f = res["findings"][0]
    assert f["vuln_type"] == "unsupported_software"
    assert reconcile_severity(dict(f))["severity"] == "high"


def test_recent_short_lived_but_no_supported_successor_stays_unsupported(monkeypatch):
    # Short-lived branch, recent EOL, but every newer line is ALSO EOL (the product
    # itself is abandoned) → remains unsupported_software, never softened.
    cycles = [
        {"cycle": "1.29", "releaseDate": _iso_months_ago(14), "eol": _iso_months_ago(3)},
        {"cycle": "1.28", "releaseDate": _iso_months_ago(26), "eol": _iso_months_ago(15)},
    ]
    _mock_feed(monkeypatch, cycles)
    res = _run(eol.scan_eol_from_net(_net("nginx", "1.29.8")))
    assert res["total"] == 1
    assert res["findings"][0]["vuln_type"] == "unsupported_software"


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


# ── per-product version attribution (static table) ─────────────────────────────
# nmap reports a single Apache service as one line whose extrainfo names other
# products: "Apache httpd 2.4.58 ((Ubuntu) PHP/8.2.10)". The structured version
# (2.4.58) is Apache's; a secondary rule (PHP) that borrowed it invented a
# nonexistent "PHP 2.4.58" that always fell below the cutoff — a false positive.

def test_eol_secondary_product_does_not_borrow_primary_version():
    """A supported PHP in an Apache service's extrainfo must NOT be flagged EOL
    by reading the Apache version (the old `_parse_version(version)` bug)."""
    banner = "Apache httpd 2.4.58 ((Ubuntu) PHP/8.2.10)"
    out = eol._product_findings("10.0.0.1:80", "Apache httpd", "2.4.58", banner)
    assert out == [], [f["title"] for f in out]


def test_eol_secondary_product_reports_its_own_version():
    """When the secondary product really is EOL, the finding carries ITS version
    (PHP 5.5.9), never the primary Apache version."""
    banner = "Apache httpd 2.4.7 ((Ubuntu) PHP/5.5.9-1ubuntu4)"
    out = eol._product_findings("10.0.0.1:80", "Apache httpd", "2.4.7", banner)
    php = [f for f in out if f["evidence"]["product"] == "PHP"]
    assert len(php) == 1
    assert php[0]["evidence"]["detected_version"] == "5.5.9"
    assert "5.5.9" in php[0]["title"] and "2.4.7" not in php[0]["title"]


def test_eol_primary_product_still_fires_with_own_version():
    """Sanity: a genuinely old primary product still fires, with its version."""
    out = eol._product_findings("10.0.0.1:80", "Apache httpd", "2.2.8",
                                "Apache httpd 2.2.8 ((Debian))")
    apache = [f for f in out if f["evidence"]["product"] == "Apache HTTP Server"]
    assert len(apache) == 1
    assert apache[0]["evidence"]["detected_version"] == "2.2.8"
