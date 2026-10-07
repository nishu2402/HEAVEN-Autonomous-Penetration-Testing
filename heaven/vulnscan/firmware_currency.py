"""HEAVEN — curated software/firmware currency dataset.

`eol_scanner.py` flags software that is *end-of-life* (via a curated table) and
software that is *behind its latest patch* (via the live endoflife.date feed's
``latest`` field). Two honest gaps remain, and this module closes them:

1. **Products endoflife.date does not track at all.** The clearest example is
   **OpenSSH**: its version is reliably readable from the SSH banner, it is one of
   the most widely deployed daemons on the internet, yet endoflife.date returns a
   404 for it, so the dynamic layer never sees a "latest" to compare against.

2. **Products endoflife.date tracks without a ``latest`` field** (e.g. appliances
   such as FortiOS). Those are handled with *live* endoflife.date per-cycle release
   dates inside `eol_scanner` (see ``_release_line_currency_finding`` there), so no
   firmware version numbers are hard-coded and nothing goes stale into a false
   positive. This module is only for the case where a curated latest is required.

**Honesty guarantees (this is the whole point):**

- A finding fires **only when a concrete version is actually observed** on the wire
  (banner / recon inventory). No version, no finding.
- A finding fires **only when the observed version is older than the curated
  latest**. A host running something *newer* than this dataset knows about is never
  flagged, so a stale dataset degrades to a silent miss, never a false positive.
- Every finding is stamped with ``dataset_date`` and worded as "the latest release
  known to HEAVEN's curated dataset (compiled ...)", so the reader always knows the
  reference point and can re-verify.
- OpenSSH findings carry an explicit **backport caveat**: distributions routinely
  backport security fixes to the packaged OpenSSH without changing the banner, so
  the version string alone does not prove the host is unpatched. The finding is
  therefore low severity and framed as "confirm the effective patch level", which
  is exactly how a careful pentester reports an old service banner.

Refresh discipline: bump ``_DATASET_DATE`` and the ``latest`` / release-history
entries when this file is updated. Because of the "never flag a newer host" rule,
letting it drift only costs coverage, never accuracy.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Optional

from heaven.utils.logger import get_logger

# Reuse the version helpers from the EOL scanner. eol_scanner imports THIS module
# lazily (function-level), so importing its helpers here does not create a cycle.
from heaven.vulnscan.eol_scanner import (
    _finding,
    _lt,
    _parse_version,
)

logger = get_logger("vulnscan.firmware_currency")

# Month this dataset's "latest" facts were last verified against upstream.
_DATASET_DATE = "2026-09"
# Fixed reference day for every age calculation below. Ages are measured against the
# dataset compile date, never the wall-clock "today", so a frozen "latest" and a
# frozen set of release dates always yield the same verdict no matter when the scan
# runs. Measuring against a moving "today" while "latest" stays frozen would let a
# recent release silently cross the age floor and begin a false nag (exactly what
# OpenSSH 10.2 did once it passed 360 days old).
_DATASET_ANCHOR = f"{_DATASET_DATE}-01"

# A version banner this many months old (or older) is reportable, provided a newer
# release genuinely exists. Deliberately a full year: we never nag about being one
# release train behind, only about a genuinely stale banner, which keeps the
# low-severity finding defensible even on back-ported distro packages.
_MIN_AGE_MONTHS = 12


# ── OpenSSH release history ───────────────────────────────────────────────────
# version "major.minor" → first release date (portable). Used to state the real
# age of the advertised build. Verified against openssh.org/releasenotes.html for
# the recent line; the historical dates are the well-established upstream releases.
_OPENSSH_RELEASES: dict[str, str] = {
    "10.5": "2026-08-11", "10.4": "2026-07-06", "10.3": "2026-04-02",
    "10.2": "2025-10-10", "10.1": "2025-10-06", "10.0": "2025-04-09",
    "9.9": "2024-09-19", "9.8": "2024-07-01", "9.7": "2024-03-11",
    "9.6": "2023-12-18", "9.5": "2023-10-04", "9.4": "2023-08-10",
    "9.3": "2023-03-15", "9.2": "2023-02-02", "9.1": "2022-10-04",
    "9.0": "2022-04-08", "8.9": "2022-02-23", "8.8": "2021-09-26",
    "8.7": "2021-08-20", "8.6": "2021-04-19", "8.5": "2021-03-03",
    "8.4": "2020-09-27", "8.3": "2020-05-27", "8.2": "2020-02-14",
    "8.1": "2019-10-09", "8.0": "2019-04-17", "7.9": "2018-10-19",
    "7.8": "2018-08-24", "7.7": "2018-04-02", "7.6": "2017-10-03",
    "7.5": "2017-03-20", "7.4": "2016-12-19", "7.3": "2016-08-01",
    "7.2": "2016-02-29", "7.1": "2015-08-21", "7.0": "2015-08-11",
}
_OPENSSH_LATEST = "10.5"


def _openssh_version(hay: str) -> Optional[tuple[int, ...]]:
    """Extract the OpenSSH version from a product/banner string.

    Must NOT pick up the SSH *protocol* version: a raw banner is
    "SSH-2.0-OpenSSH_9.6p1", and a naive first-number scan would read "2.0". Anchor
    on the OpenSSH token instead.
    """
    m = re.search(r"openssh[_/ ]?v?(\d+\.\d+(?:\.\d+)?)", hay, re.I)
    if not m:
        return None
    return _parse_version(m.group(1))


def _fmt_age(months: int) -> str:
    if months >= 24:
        years = months // 12
        rem = months % 12
        tail = f" {rem} month{'s' if rem != 1 else ''}" if rem else ""
        return f"~{years} year{'s' if years != 1 else ''}{tail}"
    return f"~{months} month{'s' if months != 1 else ''}"


def _months_between(start_iso: str, end_iso: str) -> Optional[int]:
    """Whole months between two ISO dates (``end - start``), or None if unparseable.

    Mirrors ``eol_scanner._months_since`` (``days // 30``) but takes an explicit end
    date, so curated-dataset ages anchor to ``_DATASET_ANCHOR`` and never drift with
    the wall clock.
    """
    try:
        start = date.fromisoformat(start_iso)
        end = date.fromisoformat(end_iso)
    except (ValueError, TypeError):
        return None
    return max(0, (end - start).days // 30)


def _openssh_finding(target: str, obs: tuple[int, ...]) -> Optional[dict]:
    latest_v = _parse_version(_OPENSSH_LATEST)
    if not latest_v or not _lt(obs, latest_v):
        return None                              # current or newer → never flag
    obs_label = ".".join(str(x) for x in obs)
    obs_date = _OPENSSH_RELEASES.get(obs_label)
    if not obs_date:
        # Version older/newer than our history map — be conservative and skip
        # rather than invent an age.
        return None
    age = _months_between(obs_date, _DATASET_ANCHOR)
    if age is None or age < _MIN_AGE_MONTHS:
        return None
    latest_date = _OPENSSH_RELEASES.get(_OPENSSH_LATEST, "")
    age_txt = _fmt_age(age)
    return _finding(
        target, "outdated_patch_level", "low",
        f"Outdated SSH Version Banner: OpenSSH {obs_label} (current {_OPENSSH_LATEST})",
        f"The SSH service advertises OpenSSH {obs_label}, first released on "
        f"{obs_date}, {age_txt} before HEAVEN's currency dataset was compiled "
        f"({_DATASET_DATE}). The current OpenSSH release is "
        f"{_OPENSSH_LATEST} (published {latest_date}), so the advertised build is "
        f"well behind the maintained line. Note that Linux distributions frequently "
        "backport security fixes to the packaged OpenSSH without changing this "
        "banner, so the version string alone does not prove the host is unpatched, "
        "confirm the effective patch level. Regardless, an outdated version banner "
        "aids version-based targeting; update OpenSSH (or review the advertised "
        "banner) and verify the running build carries current security fixes.",
        0.8,
        {"product": "OpenSSH", "detected_version": obs_label,
         "detected_release_date": obs_date, "latest_version": _OPENSSH_LATEST,
         "latest_release_date": latest_date, "months_behind": age,
         "kind": "software_component", "cwe": "CWE-1104",
         "source_feed": f"heaven curated dataset ({_DATASET_DATE})",
         "note": "distros often backport fixes without bumping the banner; "
                 "confirm effective patch level"})


def firmware_currency_finding(target: str, product: str, version: str,
                              banner: str) -> Optional[dict]:
    """Return a curated-currency finding for products endoflife.date can't cover.

    Called by `eol_scanner` only when the static table and the endoflife.date feed
    both produced nothing for this product. Returns None unless a concrete observed
    version is genuinely behind the curated latest.
    """
    hay = f"{product} {version} {banner}".lower()
    if "openssh" in hay:
        obs = _openssh_version(hay) or _parse_version(version)
        if obs is not None:
            return _openssh_finding(target, obs)
    return None


__all__ = ["firmware_currency_finding", "_OPENSSH_RELEASES", "_DATASET_DATE"]
