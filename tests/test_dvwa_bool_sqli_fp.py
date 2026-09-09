"""Regression: the DVWA `index.php?option=` boolean-blind SQLi false positive.

Live evidence (tests/benchmarks/reports/dvwa_run1.db, the 100%-recall / 97.7%-
precision DVWA benchmark run): a single FALSE positive —

    vuln_type=sqli  technique=boolean_blind  param=option  severity=critical
    url=index.php?option=com_users
    baseline_len=6517  true_len=6517  false_len=6436   reproduced=True

`index.php` does not use an `option` parameter (captured live, all three bodies
are byte-identical — see the fixtures), so `1) AND (1=1)--` vs `1) AND (1=2)--`
must NOT read as a SQL oracle. The 81-byte TRUE/FALSE swing was a one-shot DVWA
session flash message (`dvwaMessage`) queued by a *concurrent* probe: the scanner
always fetches TRUE before FALSE, so the first read consumed the transient and
the second found it gone — TRUE tracked the baseline and FALSE looked "hidden",
a perfect fake oracle that even repeated because a fresh message kept arriving.

The fix (heaven/vulnscan/injection_scanner.py):
  * `_boolean_sqli_confirmed` now takes a `noise_floor` the TRUE/FALSE swing must
    exceed (the baseline's own request-to-request jitter), and
  * the reproduction round re-fetches a fresh baseline (to measure that jitter)
    and swaps the TRUE/FALSE fetch order, so a position-locked transient flips
    branches and collapses while a real, order-independent oracle holds.

These tests use the REAL captured DVWA bodies (tests/fixtures/dvwa_bool_sqli/)
and a fake session that models the flash-message queue, and assert:
  1. the ignored param produces NO finding (FP gone), while
  2. the real `/vulnerabilities/sqli_blind/` oracle is STILL confirmed (recall).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from heaven.vulnscan import injection_scanner as inj
from heaven.vulnscan.injection_scanner import (
    InjectionScanner,
    _baseline_noise,
    _boolean_sqli_confirmed,
)

FX = Path(__file__).parent / "fixtures" / "dvwa_bool_sqli"


def _load(name: str) -> str:
    return (FX / name).read_text(encoding="utf-8")


# A realistic DVWA one-shot flash element (rendered once, then consumed). Its
# exact bytes do not matter — only that it is an ~80-char transient unrelated to
# the injected condition, matching the live 81-byte baseline/true vs false swing.
_FLASH = ('<div class="message">You have been logged in as an administrator '
          'of DVWA.</div>')


def _param_value(url: str, param: str) -> str:
    return parse_qs(urlparse(url).query, keep_blank_values=True).get(param, [""])[0]


# ── Pure-oracle contract ──────────────────────────────────────────────────

def test_real_blind_oracle_still_confirmed():
    """The genuine DVWA blind oracle (row present vs 'MISSING') must confirm.
    This is the recall floor the FP fix must not lower."""
    base = _load("blind_baseline.html")
    bt = _load("blind_true.html")      # "User ID exists in the database."
    bf = _load("blind_false.html")     # "User ID is MISSING from the database."
    # The blind page is stable (measured live: noise 0), so the row difference
    # clears the floor.
    assert _baseline_noise(base, base) == 0
    assert _boolean_sqli_confirmed(base, bt, bf, "1' AND '1'='1'-- ",
                                   "1' AND '1'='2'-- ", noise_floor=0) is True


def test_ignored_param_clean_bodies_are_not_an_oracle():
    """With a quiet session the three bodies are identical → never an oracle."""
    base = _load("index_option_baseline.html")
    bt = _load("index_option_true.html")
    bf = _load("index_option_false.html")
    assert base == bt == bf
    assert _boolean_sqli_confirmed(base, bt, bf, "1) AND (1=1)-- ",
                                   "1) AND (1=2)-- ") is False


def test_flash_swing_is_rejected_once_it_no_longer_exceeds_jitter():
    """The exact live condition: baseline+TRUE carry the flash, FALSE does not.

    The OLD gate (noise_floor 0) would confirm — that was the bug. Once the
    baseline's own jitter is known (a re-fetch also carries the transient), the
    swing no longer exceeds it and the oracle is rejected."""
    clean = _load("index_option_baseline.html")
    flash = clean.replace("</body>", _FLASH + "</body>")
    # baseline & TRUE rendered the one-shot message; FALSE (fetched second) did not
    base, bt, bf = flash, flash, clean
    # OLD behaviour: a candidate (this is why it fired before the fix)
    assert _boolean_sqli_confirmed(base, bt, bf, "1) AND (1=1)-- ",
                                   "1) AND (1=2)-- ", noise_floor=0) is True
    # A second baseline read did NOT catch the one-shot flash → the page's own
    # jitter equals the whole swing, so the swing can no longer count as signal.
    noise = _baseline_noise(base, clean)
    assert noise >= len(_FLASH) - 20
    assert _boolean_sqli_confirmed(base, bt, bf, "1) AND (1=1)-- ",
                                   "1) AND (1=2)-- ", noise_floor=noise) is False


# ── Caller-level contract (models the concurrent flash-message queue) ──────

class _FlashSession:
    """Fake DVWA session for `index.php?option=`. `option` is ignored, so every
    body is the clean page — EXCEPT that a one-shot flash message is queued
    before each measurement round and consumed by the first index read of that
    round (exactly the concurrent-scan mechanism that produced the live FP)."""

    def __init__(self, clean: str):
        self.clean = clean
        self.flash = clean.replace("</body>", _FLASH + "</body>")
        self.calls = 0
        self.available = 0

    async def get(self, session, url, headers=None, timeout=8.0):
        # A concurrent probe queues a fresh flash at the start of round 1 (call 0)
        # and round 2 (call 2 == the baseline re-fetch).
        if self.calls in (0, 2):
            self.available = 1
        body = self.clean
        if self.available > 0 and "index.php" in url:
            body = self.flash
            self.available -= 1
        self.calls += 1
        return 200, body


class _BlindSession:
    """Fake DVWA blind endpoint: deterministic and order-independent — the row
    is present for the TRUE condition and 'MISSING' for the FALSE condition."""

    def __init__(self):
        self.base = _load("blind_baseline.html")
        self.t = _load("blind_true.html")
        self.f = _load("blind_false.html")

    async def get(self, session, url, headers=None, timeout=8.0):
        val = _param_value(url, "id")
        if "'='1'" in val:
            return 200, self.t
        if "'='2'" in val:
            return 200, self.f
        return 200, self.base


def _run_boolean(scanner, session_obj, url, param, baseline):
    async def _drive():
        return await scanner._test_sqli_boolean_param(session_obj, url, param, baseline)
    asyncio.run(_drive())


def test_caller_rejects_flash_message_fp(monkeypatch):
    clean = _load("index_option_baseline.html")
    fake = _FlashSession(clean)
    monkeypatch.setattr(inj, "_get", fake.get)
    scanner = InjectionScanner(concurrency=1)
    # baseline carried the flash (live baseline_len=6517), matching the round-1
    # firing condition where TRUE tracks the baseline.
    baseline = fake.flash
    _run_boolean(scanner, object(), "http://t/index.php?option=com_users",
                 "option", baseline)
    sqli = [f for f in scanner._findings if f["vuln_type"] == "sqli"]
    assert sqli == [], f"flash-message FP not suppressed: {sqli}"


def test_caller_confirms_real_blind_sqli(monkeypatch):
    fake = _BlindSession()
    monkeypatch.setattr(inj, "_get", fake.get)
    scanner = InjectionScanner(concurrency=1)
    _run_boolean(scanner, object(),
                 "http://t/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
                 "id", fake.base)
    sqli = [f for f in scanner._findings if f["vuln_type"] == "sqli"]
    assert len(sqli) == 1, f"real blind SQLi lost: {scanner._findings}"
    assert sqli[0]["evidence"]["technique"] == "boolean_blind"
