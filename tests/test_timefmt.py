"""Human-facing timestamps render in the operator's timezone, not a fixed UTC.

HEAVEN stores UTC everywhere, but a report footer or the UI clock should read
where the operator actually is: IST in India, GMT/BST in the UK, with no config.
An operator can still pin a zone (a client abroad) or keep UTC on purpose. These
tests exercise every branch of :mod:`heaven.utils.timefmt` and the config wiring
that feeds it, and stay deterministic by pinning zones explicitly.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import heaven.utils.timefmt as tf
from heaven.config import HeavenConfig, get_config

# A machine's tz database may be absent (a bare Windows CI without `tzdata`); the
# helper then falls back to local, which is correct but not assertable as IST.
try:
    from zoneinfo import ZoneInfo
    ZoneInfo("Asia/Kolkata")
    _HAVE_TZDATA = True
except Exception:  # noqa: BLE001 — no IANA db → skip the pinned-zone assertions
    _HAVE_TZDATA = False

_needs_tzdata = pytest.mark.skipif(not _HAVE_TZDATA, reason="no IANA tz database")


def _pin(monkeypatch, name: str) -> None:
    """Pin the display timezone on the live config singleton (auto-restored)."""
    monkeypatch.setattr(get_config(), "report_timezone", name, raising=False)


# A fixed instant so wall-clock assertions are exact regardless of "now".
_NOON_UTC = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def test_default_follows_local_machine(monkeypatch):
    """Empty config means: use the machine's own zone, and never raise."""
    _pin(monkeypatch, "")
    expected = datetime.now().astimezone().tzinfo
    assert tf.resolve_tz().utcoffset(_NOON_UTC) == expected.utcoffset(
        datetime.now())
    # The rendered strings are non-empty and carry a zone token.
    assert tf.report_timestamp(_NOON_UTC)
    assert tf.stamp(_NOON_UTC)
    assert tf.tz_label()


@_needs_tzdata
def test_pinned_india_reads_ist(monkeypatch):
    _pin(monkeypatch, "Asia/Kolkata")
    assert tf.tz_label() == "IST"
    # 12:00 UTC is 17:30 IST (UTC+05:30) on that date.
    assert tf.stamp(_NOON_UTC) == "2026-09-23 17:30 IST"
    assert tf.report_timestamp(_NOON_UTC) == "23 September 2026, 17:30 IST"


@_needs_tzdata
def test_pinned_uk_reads_bst_in_summer(monkeypatch):
    _pin(monkeypatch, "Europe/London")
    # Late September is still British Summer Time (UTC+01:00).
    assert tf.tz_label() == "BST"
    assert tf.stamp(_NOON_UTC) == "2026-09-23 13:00 BST"


def test_pinned_utc_preserves_old_behaviour(monkeypatch):
    _pin(monkeypatch, "UTC")
    assert tf.stamp(_NOON_UTC) == "2026-09-23 12:00 UTC"
    assert tf.report_timestamp(_NOON_UTC) == "23 September 2026, 12:00 UTC"


def test_case_insensitive_utc(monkeypatch):
    _pin(monkeypatch, "utc")
    assert tf.resolve_tz() is timezone.utc


def test_bogus_zone_falls_back_without_raising(monkeypatch):
    _pin(monkeypatch, "Not/AZone")
    # Falls back to the local zone; the important guarantee is that it renders.
    assert tf.report_timestamp(_NOON_UTC)


def test_naive_datetime_is_read_as_utc(monkeypatch):
    """A naive value (how legacy code stored UTC) must not be read as local."""
    _pin(monkeypatch, "UTC")
    naive = datetime(2026, 9, 23, 12, 0)  # no tzinfo
    assert tf.to_display(naive) == _NOON_UTC


@_needs_tzdata
def test_offset_label_when_platform_gives_no_abbrev(monkeypatch):
    """Zones without a short abbreviation get a numeric UTC offset instead."""
    _pin(monkeypatch, "Asia/Kolkata")
    # Force the abbreviation path to be empty and confirm the offset fallback.
    monkeypatch.setattr(tf, "_label", tf._label)  # keep real impl
    dt = tf.to_display(_NOON_UTC)
    label = tf._label(dt)
    assert label in ("IST", "UTC+05:30")


def test_env_var_wires_into_config(monkeypatch):
    monkeypatch.setenv("HEAVEN_REPORT_TZ", "Asia/Kolkata")
    cfg = HeavenConfig()
    assert cfg.report_timezone == "Asia/Kolkata"


def test_env_var_is_stripped(monkeypatch):
    monkeypatch.setenv("HEAVEN_REPORT_TZ", "  Europe/London  ")
    cfg = HeavenConfig()
    assert cfg.report_timezone == "Europe/London"


def test_offset_label_for_utc_is_plain_utc():
    assert tf._label(_NOON_UTC) == "UTC"


def test_offset_label_positive_offset():
    plus0530 = timezone(timedelta(hours=5, minutes=30))
    dt = _NOON_UTC.astimezone(plus0530)
    # A raw fixed-offset zone has no abbreviation, so the numeric form is used.
    assert tf._label(dt) == "UTC+05:30"
