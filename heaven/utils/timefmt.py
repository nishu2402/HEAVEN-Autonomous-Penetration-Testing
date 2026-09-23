"""Human-facing timestamps in the operator's own timezone.

HEAVEN stores every timestamp in UTC (the right choice for a database and an
audit trail), but a person reading a report or the UI clock should see the time
where they actually are. A pentester in India should read IST and one in the UK
should read GMT or BST, without touching a config file.

This module resolves a display timezone and formats a timestamp in it. The
resolution order is:

1. ``HEAVEN_REPORT_TZ`` / ``config.report_timezone`` when set to an IANA name
   (``Asia/Kolkata``, ``Europe/London``, ...) or the literal ``UTC``. This lets
   a team pin a client's zone, or keep the old UTC behaviour on purpose.
2. Otherwise the machine's own local timezone, so the common self-hosted case is
   correct with zero configuration.

Only human display uses this. Stored records, isoformat fields and machine
interchange stay UTC so nothing downstream has to guess an offset.
"""

from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from typing import Optional

# Long footer used across report generators: "23 September 2026, 18:30 IST".
LONG_FMT = "%d %B %Y, %H:%M %Z"
# Compact stamp used by the forensic / artifact reports: "2026-09-23 18:30 IST".
SHORT_FMT = "%Y-%m-%d %H:%M %Z"


def _configured_tz_name() -> str:
    """The pinned zone name, or an empty string to follow the local machine."""
    try:
        from heaven.config import get_config
        return (get_config().report_timezone or "").strip()
    except Exception:  # noqa: BLE001 — config must never break timestamp rendering
        return ""


def resolve_tz() -> tzinfo:
    """Return the timezone human-facing timestamps should be shown in.

    Falls back to the machine's local zone whenever a pinned name is empty,
    unknown, or the system has no IANA tz database available (e.g. a bare
    Windows install without ``tzdata``), so rendering can never raise.
    """
    name = _configured_tz_name()
    if not name or name.lower() in ("local", "auto", "system"):
        return _local_tz()
    if name.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 — unknown name / missing tzdata → local
        return _local_tz()


def _local_tz() -> tzinfo:
    """The machine's local timezone as a concrete tzinfo (never None)."""
    local = datetime.now().astimezone().tzinfo
    return local or timezone.utc


def now() -> datetime:
    """The current time as an aware datetime in the display timezone."""
    return datetime.now(tz=resolve_tz())


def to_display(dt: datetime) -> datetime:
    """Convert ``dt`` into the display timezone.

    A naive datetime is treated as UTC, matching how HEAVEN stores timestamps,
    so an old ``datetime.utcnow()``-style value still lands on the right wall
    clock instead of being read as local.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(resolve_tz())


def _label(dt: datetime) -> str:
    """A self-describing zone label, e.g. ``IST`` or, if the platform gives no
    abbreviation, a numeric offset like ``UTC+05:30``."""
    abbrev = dt.strftime("%Z").strip()
    if abbrev and not abbrev.startswith(("+", "-")) and not abbrev.isdigit():
        return abbrev
    offset = dt.utcoffset()
    if offset is None:
        return "UTC"
    total = int(offset.total_seconds())
    if total == 0:
        return "UTC"
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"UTC{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def _format(dt: Optional[datetime], fmt: str) -> str:
    shown = now() if dt is None else to_display(dt)
    # Some platforms return an empty %Z; substitute a computed label so the zone
    # is always visible and the timestamp stays unambiguous.
    if "%Z" in fmt and not shown.strftime("%Z").strip():
        return shown.strftime(fmt.replace("%Z", "")).rstrip() + f" {_label(shown)}"
    return shown.strftime(fmt)


def report_timestamp(dt: Optional[datetime] = None) -> str:
    """Long "Generated" footer in the display timezone (default: now)."""
    return _format(dt, LONG_FMT)


def stamp(dt: Optional[datetime] = None) -> str:
    """Compact ``YYYY-MM-DD HH:MM ZZZ`` stamp in the display timezone."""
    return _format(dt, SHORT_FMT)


def tz_label(dt: Optional[datetime] = None) -> str:
    """The active display-zone label on its own (for status lines / the UI)."""
    return _label(now() if dt is None else to_display(dt))
