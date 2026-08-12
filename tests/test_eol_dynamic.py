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


def test_slug_detection():
    assert eol._endoflife_slug("nginx", "") == "nginx"
    assert eol._endoflife_slug("Apache", "httpd") == "apache"
    assert eol._endoflife_slug("PostgreSQL", "") == "postgresql"
    assert eol._endoflife_slug("some-random-appliance", "") == ""
