"""HEAVEN: operating-profile overlay.

A :class:`~heaven.config.ScanMode` selects *which* scanners run. A
:class:`~heaven.config.Profile` tunes *how* the whole run behaves, independent
of the mode, so one deep scanner core serves both a classic authorised
engagement and a scope-constrained, internet-facing bug-bounty program.

This module holds the concrete knob values for each profile and the glue that
turns a profile + an engagement's stored scope into the ``targets`` dict and
config tweaks the orchestrator already understands. It deliberately contains no
scanner logic and touches no network: it only reshapes configuration, which
keeps it fully unit-testable.

Design notes:

* The profile never *widens* authorisation. For bug bounty it seeds targets from
  the engagement's own in-scope entries and carries the out-of-scope entries into
  an ``exclude`` bucket that ``feedback.ScopeGuard`` subtracts. Nothing here can
  authorise a host the operator did not already enter as scope.
* Politeness (a lower request budget) is applied by lowering
  ``config.security.rate_limit_rpm``; the adaptive per-host throttle in the
  scanners stays in force on top of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from heaven.config import Profile

if TYPE_CHECKING:  # avoid a runtime import cycle (config imports nothing here)
    from heaven.config import HeavenConfig
    from heaven.engagement import ScopeEntry


@dataclass(frozen=True)
class ProfileSettings:
    """The tunable knobs a profile sets. One instance per profile."""

    # Respect program rate rules: requests/minute ceiling applied to the run.
    # None leaves the configured default untouched (pentest).
    rate_limit_rpm: Optional[int] = None
    # Advertise a routable OOB collaborator so an internet target can call back
    # (bug bounty). False keeps the loopback-bound lab default.
    oob_routable: bool = False
    # Prefer breadth-first recon (subdomain enumeration within authorised scope).
    recon_breadth: bool = False
    # Enforce the engagement's scope strictly, including the out-of-scope list.
    strict_scope: bool = False
    # Default export format for `heaven findings export` under this profile.
    default_export_format: str = "markdown"


PROFILES: dict[Profile, ProfileSettings] = {
    # Historical behaviour: change nothing the operator did not ask for.
    Profile.PENTEST: ProfileSettings(),
    # Public program: polite, breadth-first within strict scope, routable OOB,
    # and a per-finding submission report by default.
    Profile.BUGBOUNTY: ProfileSettings(
        rate_limit_rpm=60,
        oob_routable=True,
        recon_breadth=True,
        strict_scope=True,
        default_export_format="bugbounty",
    ),
}


def settings_for(profile: Profile) -> ProfileSettings:
    """Return the knob set for ``profile`` (pentest baseline if unknown)."""
    return PROFILES.get(profile, PROFILES[Profile.PENTEST])


def apply_profile(config: "HeavenConfig", profile: Profile) -> ProfileSettings:
    """Mutate ``config`` in place for ``profile`` and return its settings.

    Only knobs the profile explicitly sets are touched, so a pentest run is a
    pure no-op and a bug-bounty run changes exactly the documented fields.
    """
    settings = settings_for(profile)
    config.profile = profile
    if settings.rate_limit_rpm is not None:
        config.security.rate_limit_rpm = settings.rate_limit_rpm
    return settings


# ─────────────────────────────────────────────────────────────────────────────
# Scope → targets
# ─────────────────────────────────────────────────────────────────────────────

def _host_of(value: str) -> str:
    """Bare lowercase host from a URL/host/wildcard entry (no scheme/port)."""
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    for pfx in ("*.", "."):
        if raw.startswith(pfx):
            raw = raw[len(pfx):]
            break
    return raw.split("/", 1)[0].split(":", 1)[0].strip("[]")


def _is_wildcard(value: str, kind: str) -> bool:
    v = (value or "").strip().lower()
    return kind == "domain" or v.startswith("*.") or v.startswith(".")


def scope_entries_to_targets(entries: "list[ScopeEntry]") -> dict[str, Any]:
    """Build a ``targets`` dict from stored engagement scope entries.

    In-scope entries populate the buckets the orchestrator reads:
      * a wildcard / ``domain`` entry goes into ``domains`` (so ScopeGuard grants
        subdomain-wide scope) AND is seeded as an ``https://`` URL so the deep
        recon phase actually enumerates that domain's subdomains;
      * a ``url`` entry goes into ``urls``; an ``ip``/``cidr`` into ``ips``;
      * a bare ``host`` becomes an ``https://`` URL so web scanners reach it.

    Out-of-scope entries populate ``exclude`` (host / wildcard strings), which
    ``feedback.ScopeGuard`` subtracts from everything it would otherwise allow.
    The result only ever contains hosts the operator already authorised.
    """
    ips: list[str] = []
    urls: list[str] = []
    domains: list[str] = []
    exclude: list[str] = []

    def _add_unique(bucket: list[str], value: str) -> None:
        if value and value not in bucket:
            bucket.append(value)

    for e in entries:
        target = (e.target or "").strip()
        if not target:
            continue
        if not e.in_scope:
            # Keep the wildcard form so ScopeGuard can exclude a whole subtree.
            _add_unique(exclude, target.lower())
            continue
        kind = (e.kind or "host").lower()
        if _is_wildcard(target, kind):
            host = _host_of(target)
            _add_unique(domains, host)
            _add_unique(urls, f"https://{host}")
        elif kind in ("ip", "cidr"):
            _add_unique(ips, target)
        elif kind == "url":
            _add_unique(urls, target)
        else:  # bare host
            host = _host_of(target)
            _add_unique(urls, f"https://{host}")

    return {"ips": ips, "urls": urls, "domains": domains, "exclude": exclude}
