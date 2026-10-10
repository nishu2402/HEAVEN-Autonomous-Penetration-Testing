"""HEAVEN — End-of-Life / unsupported software detector.

Professional infrastructure health-checks consistently flag *unsupported
software* as a high-risk finding (CWE-1104): operating systems and components
past their vendor end-of-life date receive no further security patches, so any
vulnerability discovered after that date stays permanently exploitable.

This module turns the discovered host/service inventory (product + version + OS,
as produced by network reconnaissance) into concrete EOL findings. It is
**deterministic and evidence-based**: a finding fires only on a positive product
match, and — for version-gated rules — only when the detected version is at or
below the last supported release. Every finding carries the vendor EOL date as
proof, never a guess. Products with no clean vendor EOL policy (rolling-release
servers, etc.) are deliberately excluded to avoid false positives; their risk is
handled by the CVE mapper instead.

EOL dates reflect published vendor lifecycles. They are conservative: where an
Extended Security Update (ESU) path exists, the finding says so.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Optional

from heaven.utils.logger import get_logger

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:  # pragma: no cover
    _AIOHTTP = False

logger = get_logger("vulnscan.eol")


def _finding(target: str, vuln_type: str, severity: str, title: str,
             description: str, confidence: float, evidence: dict) -> dict:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": confidence,
        "cve_id": "",
        "evidence": evidence,
        "source": "eol_scanner",
    }


def _parse_version(text: str) -> Optional[tuple[int, ...]]:
    """Extract the first dotted-numeric version from ``text`` as a tuple."""
    m = re.search(r"(\d+(?:\.\d+){0,3})", text or "")
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None


def _lt(version: tuple[int, ...], cutoff: tuple[int, ...]) -> bool:
    """version < cutoff with tuple padding (2.2 < 2.4, 8.0 < 8.1)."""
    n = max(len(version), len(cutoff))
    v = version + (0,) * (n - len(version))
    c = cutoff + (0,) * (n - len(cutoff))
    return v < c


def _version_adjacent(hay: str, pattern: str) -> Optional[tuple[int, ...]]:
    """The dotted-numeric version sitting next to the product token ``pattern``
    matches in ``hay``.

    ``hay`` is ``"{product} {version} {banner}"`` for ONE service, and a single
    nmap service line routinely names several products: an Apache port advertises
    ``Apache httpd 2.4.7 ((Ubuntu) PHP/5.5.9)``. The structured ``version`` field
    (2.4.7) belongs to the PRIMARY product, so reading it for a SECONDARY product
    matched in the banner (here PHP) invents a nonexistent "PHP 2.4.7" that is
    always below the cutoff. Taking the number that follows the matched token
    instead keeps each product's version its own. Returns None when no version
    sits beside the token, so a cutoff rule never fires on an unrelated number.
    """
    m = re.search(pattern, hay)
    if not m:
        return None
    # Start at the token (the ``apache/\d`` branch consumes the first version
    # digit, so starting after the match would drop it) and take the first
    # dotted-numeric run within a short window.
    return _parse_version(hay[m.start():m.start() + 40])


# ── OS end-of-life table (regex on the OS guess → date + note) ───────────────
# Ordered most-specific first; the first match wins.
_OS_EOL: list[tuple[str, str, str, str]] = [
    (r"windows\s+(?:nt\s+4|2000)", "2010-07-13", "high",
     "Windows 2000 / NT 4.0 has been unsupported since 2010."),
    (r"windows\s+xp", "2014-04-08", "high",
     "Windows XP has been unsupported since 2014."),
    (r"windows\s+vista", "2017-04-11", "high",
     "Windows Vista has been unsupported since 2017."),
    (r"windows\s+7", "2020-01-14", "high",
     "Windows 7 reached end of support on 2020-01-14 (ESU ended 2023)."),
    (r"windows\s+8(\.1)?", "2023-01-10", "high",
     "Windows 8/8.1 reached end of support on 2023-01-10."),
    (r"windows\s+10", "2025-10-14", "medium",
     "Windows 10 reached end of support on 2025-10-14. Move to Windows 11 or "
     "enrol eligible devices in Extended Security Updates (ESU)."),
    (r"windows\s+server\s+2003", "2015-07-14", "high",
     "Windows Server 2003 has been unsupported since 2015."),
    (r"windows\s+server\s+2008", "2020-01-14", "high",
     "Windows Server 2008/2008 R2 reached end of support on 2020-01-14."),
    (r"windows\s+server\s+2012", "2023-10-10", "high",
     "Windows Server 2012/2012 R2 reached end of support on 2023-10-10."),
    # macOS 10.0–10.15: every 10.x release is past Apple's ~3-year security
    # window (10.15 Catalina's last update shipped 2022). Requires the "10.x"
    # token so a supported macOS 11+ (Big Sur and later) never matches.
    (r"mac\s*os\s*x?\s*10\.(?:[0-9]|1[0-5])\b", "2022-09-12", "medium",
     "macOS 10.x (Catalina and earlier) no longer receives Apple security "
     "updates. Upgrade to a supported macOS release."),
]

# ── Product end-of-life table ────────────────────────────────────────────────
# Each rule: (display, product-regex, version_cutoff or None, eol_date, severity, note)
# version_cutoff None → the product is EOL regardless of version.
_PRODUCT_EOL: list[tuple[str, str, Optional[tuple[int, ...]], str, str, str]] = [
    ("Microsoft Silverlight", r"silverlight", None, "2021-10-12", "medium",
     "Microsoft Silverlight reached end of support on 2021-10-12 and receives no "
     "further updates."),
    ("Adobe Flash Player", r"flash\s*player|shockwave\s*flash", None, "2020-12-31",
     "high", "Adobe Flash Player reached end of life on 2020-12-31 and is blocked "
     "by modern browsers."),
    # Match Apache HTTP Server ONLY — require an explicit "apache" token (an
    # `apache httpd` / `Apache/<n>` context). This keeps the OTHER "Apache"
    # products (Tomcat, Jserv/AJP, Coyote, Traffic Server) from matching off their
    # PROTOCOL version (AJP 1.3, Coyote 1.1 are < 2.4 and used to fire a bogus
    # "Apache httpd 2.2" finding on Metasploitable's :8009 / :8180). A bare
    # `httpd` token is deliberately NOT matched: nmap fingerprints non-Apache
    # servers as "<vendor> httpd" too — a filtered Windows box answering on
    # 5357/wsdapi is "Microsoft HTTPAPI httpd 2.0", busybox is "busybox httpd" —
    # so a bare `httpd` matched them and mislabeled the host as EOL Apache 2.0.
    # Real Apache always carries the "apache" token in its banner. Display carries
    # no branch number so the detected version isn't doubled ("Apache httpd 2.2 2.2.8").
    ("Apache HTTP Server", r"apache[ /]?httpd|apache/\d", (2, 4),
     "2017-12-31", "medium",
     "Apache HTTP Server branches before 2.4 are end-of-life and receive no "
     "security fixes."),
    # Apache JServ / AJP connector. Version-less (cutoff None) on purpose: the
    # `jserv` token is unambiguous (no non-AJP service fingerprints as "Jserv"),
    # and the "1.3" in "Protocol v1.3" is the AJP PROTOCOL version, never a
    # software release — so we must NOT version-compare it (that is exactly the
    # bogus "Apache httpd 2.2" FP the rule above avoids). The finding is framed
    # as an exposure, which is correct for any AJP version: the connector must
    # never be network-reachable (it is the Ghostcat / CVE-2020-1938 surface),
    # and the original Apache JServ project has been retired since ~2000.
    ("Apache JServ / AJP connector (legacy)", r"\bjserv\b", None,
     "2000-12-31", "medium",
     "An Apache JServ / AJP connector is reachable over the network. The AJP "
     "connector is legacy middleware that must be bound to localhost or trusted "
     "reverse proxies only: a network-exposed AJP port is the Ghostcat "
     "(CVE-2020-1938) file-read/RCE attack surface, and the original Apache "
     "JServ project has been retired and unmaintained since ~2000. Disable the "
     "AJP connector or restrict it to trusted hosts."),
    ("PHP", r"\bphp\b", (8, 1), "2025-12-31", "medium",
     "PHP versions before 8.1 have reached end of security support. Upgrade to a "
     "supported 8.x branch."),
    ("MySQL", r"\bmysql\b", (8, 0), "2023-10-31", "medium",
     "MySQL branches before 8.0 (e.g. 5.7) reached end of life in 2023."),
    ("PostgreSQL", r"postgre", (13, 0), "2021-11-11", "medium",
     "PostgreSQL branches before 13 are end-of-life (9.6 reached EOL on "
     "2021-11-11) and receive no further security fixes."),
    ("ISC BIND", r"\bbind\b", (9, 18), "2023-03-31", "medium",
     "ISC BIND branches before 9.18 are end-of-life (the 9.16 branch reached EOL "
     "in 2023). Upgrade to a supported 9.18/9.20 branch."),
    ("OpenSSL", r"openssl", (3, 0), "2023-09-11", "medium",
     "OpenSSL 1.0.2/1.1.0/1.1.1 are all end-of-life; upgrade to the 3.x LTS line."),
    ("Microsoft IIS 6.0", r"iis[/ ]?6\b|microsoft-iis/6", None, "2015-07-14",
     "high", "IIS 6.0 shipped with Windows Server 2003 and is unsupported."),
]


def _os_finding(host: str, os_guess: str) -> Optional[dict]:
    low = os_guess.lower()
    for pattern, eol_date, severity, note in _OS_EOL:
        if re.search(pattern, low):
            return _finding(
                host, "unsupported_software", severity,
                f"Unsupported Operating System: {os_guess}",
                "The host is running an operating system that has passed its "
                f"vendor end-of-life date ({eol_date}). {note} End-of-life systems "
                "receive no security patches, so any newly disclosed vulnerability "
                "remains exploitable indefinitely. Plan decommissioning/upgrade, or "
                "purchase extended support and isolate the host in the interim.",
                0.85,
                {"product": os_guess, "kind": "operating_system",
                 "eol_date": eol_date, "cwe": "CWE-1104"})
    return None


def _product_findings(target: str, product: str, version: str,
                      banner: str) -> list[dict]:
    hay = f"{product} {version} {banner}".lower()
    out: list[dict] = []
    for display, pattern, cutoff, eol_date, severity, note in _PRODUCT_EOL:
        if not re.search(pattern, hay):
            continue
        detected_ver = ""
        if cutoff is not None:
            # Read the version that sits NEXT TO this product's token, so a banner
            # naming several products attributes each its own release (and a
            # secondary match like PHP in an Apache service's extrainfo never
            # borrows the primary product's version).
            v = _version_adjacent(hay, pattern)
            if v is None or not _lt(v, cutoff):
                continue
            detected_ver = ".".join(str(x) for x in v)
        out.append(_finding(
            target, "unsupported_software", severity,
            f"Unsupported / End-of-Life Software: {display}"
            + (f" {detected_ver}" if detected_ver else ""),
            f"{note} End-of-life software receives no security patches; treat this "
            "as a proof-of-concept for the wider estate and inventory/upgrade all "
            "affected instances.",
            0.8,
            {"product": display, "detected_version": detected_ver,
             "kind": "software_component", "eol_date": eol_date,
             "cwe": "CWE-1104"}))
    return out


# ── Dynamic EOL via the live endoflife.date feed ─────────────────────────────
# The static tables above are curated, offline and precise but finite. The live
# endoflife.date API (key-less) covers hundreds more products, so HEAVEN can flag
# an EOL component that isn't in the hand-maintained list — the "if it's on the
# target but not in our DB, don't miss it" case. A finding still fires ONLY on a
# real, published EOL date (or an explicit ``eol:true``); "still supported" and
# "unknown" never raise a finding. endoflife.date receives only a product SLUG
# (e.g. "mysql"), never anything identifying the target.
_EOL_API = "https://endoflife.date/api/{product}.json"
_EOL_CACHE: dict[str, list[dict]] = {}
_EOL_MAX_LOOKUPS = 16

# Detected product string (regex) → endoflife.date product slug.
_ENDOFLIFE_SLUGS: list[tuple[str, str]] = [
    (r"nginx", "nginx"),
    # "apache" alone matched the OTHER Apache products (Tomcat, Jserv/AJP,
    # Coyote), sending their PROTOCOL version to the Apache HTTP Server EOL feed
    # ("Apache Jserv 1.3" flagged EOL). Require an explicit "apache" token; a bare
    # `httpd` is NOT matched (it also fingerprints non-Apache servers such as
    # "Microsoft HTTPAPI httpd" / "busybox httpd"). Tomcat matches its own slug.
    (r"apache[ /]?httpd|apache/\d", "apache"),
    (r"tomcat", "tomcat"),
    (r"\bphp\b", "php"),
    (r"mariadb", "mariadb"),
    (r"\bmysql\b", "mysql"),
    (r"postgre", "postgresql"),
    (r"mongodb|mongod", "mongodb"),
    (r"\bredis\b", "redis"),
    (r"elasticsearch", "elasticsearch"),
    (r"\bbind\b|named", "bind"),
    (r"openssl", "openssl"),
    (r"openssh", "openssh"),
    (r"\bexim\b", "exim"),
    (r"postfix", "postfix"),
    (r"dovecot", "dovecot"),
    (r"proftpd", "proftpd"),
    (r"pure-ftpd", "pure-ftpd"),
    (r"varnish", "varnish"),
    (r"haproxy", "haproxy"),
    (r"node\.?js|nodejs", "nodejs"),
    (r"python", "python"),
    (r"\bperl\b", "perl"),
    (r"\bruby\b", "ruby"),
    (r"ubuntu", "ubuntu"),
    (r"debian", "debian"),
    (r"centos", "centos"),
    (r"red\s*hat|rhel", "rhel"),
    (r"almalinux", "almalinux"),
    (r"rocky", "rocky-linux"),
    # Edge/VPN appliances: endoflife.date tracks these but WITHOUT a `latest`
    # field, so the patch-level check below never fires for them. They are handled
    # by the release-line currency path instead (see _NON_LTS_CURRENCY_SLUGS).
    (r"fortios|fortigate|fortinet", "fortios"),
    (r"fortiproxy", "fortiproxy"),
]

# endoflife.date slugs where being on an older *release line* genuinely means
# missing fixes (appliances that do not run a long-term-support back-port model
# the way Ubuntu/Debian/RHEL/Node LTS do). Only these get the release-line
# currency check, so a supported LTS distro is never flagged just for not being on
# the newest cycle. Live per-cycle release dates are used, so nothing is hard-coded
# and nothing goes stale.
_NON_LTS_CURRENCY_SLUGS = {"fortios", "fortiproxy"}

# A newer release LINE must have been generally available at least this long before
# a release-line-behind finding fires — appliances are often deliberately kept on
# the previous mature branch for a while, so this avoids flagging a recent major.
_RELEASE_LINE_MIN_MONTHS = 12


def _endoflife_slug(product: str, banner: str) -> str:
    hay = f"{product} {banner}".lower()
    for pattern, slug in _ENDOFLIFE_SLUGS:
        if re.search(pattern, hay):
            return slug
    return ""


async def _endoflife_lookup(slug: str, *, session: Any = None,
                            timeout: float = 8.0) -> list[dict]:
    """Return endoflife.date release cycles for *slug*, cached; ``[]`` on error."""
    if not _AIOHTTP or not slug:
        return []
    if slug in _EOL_CACHE:
        return _EOL_CACHE[slug]
    url = _EOL_API.format(product=slug)
    cycles: list[dict] = []
    own = session is None
    try:
        sess = session or aiohttp.ClientSession()
        try:
            async with sess.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        cycles = [c for c in data if isinstance(c, dict)]
        finally:
            if own:
                await sess.close()
    except Exception as e:  # noqa: BLE001 - dynamic EOL is best-effort
        logger.debug("endoflife.date lookup failed for %s: %s", slug, e)
        cycles = []
    _EOL_CACHE[slug] = cycles
    return cycles


def _cycle_status(cycle: dict) -> Optional[tuple[str, str, bool]]:
    """(eol_date, cycle_label, is_eol) for one release cycle; None if unknown."""
    label = str(cycle.get("cycle", ""))
    eol = cycle.get("eol")
    if eol is True:
        return ("", label, True)
    if eol is False:
        return ("", label, False)
    if isinstance(eol, str) and eol:
        try:
            d = date.fromisoformat(eol)
        except ValueError:
            return None
        return (eol, label, d < date.today())
    return None


def _match_cycle(cycles: list[dict],
                 version: tuple[int, ...]) -> Optional[tuple[str, str, bool]]:
    """Find the release cycle covering *version* (e.g. 5.7.44 → cycle '5.7')."""
    cand = _find_cycle(cycles, version)
    return _cycle_status(cand) if cand else None


def _find_cycle(cycles: list[dict],
                version: tuple[int, ...]) -> Optional[dict]:
    """Return the release-cycle dict covering *version* (e.g. 5.7.44 → '5.7')."""
    cands: list[str] = []
    if len(version) >= 2:
        cands.append(f"{version[0]}.{version[1]}")
    cands.append(f"{version[0]}")
    for cand in cands:
        for c in cycles:
            if str(c.get("cycle", "")) == cand:
                return c
    return None


def _months_since(iso_date: str) -> Optional[int]:
    """Whole months between an ISO date and today, or None if unparseable."""
    try:
        d = date.fromisoformat(iso_date)
    except (ValueError, TypeError):
        return None
    return max(0, (date.today() - d).days // 30)


# A newer patch must have been available at least this long before the lag is
# reported — avoids flagging a release that came out days ago.
_CURRENCY_MIN_MONTHS = 3


def _release_line_currency_finding(target: str, display: str, slug: str,
                                   detected: str, obs_cycle: str,
                                   cycles: list[dict]) -> Optional[dict]:
    """Flag a non-LTS appliance running an older release LINE.

    For appliance slugs on ``_NON_LTS_CURRENCY_SLUGS`` (where endoflife.date has no
    ``latest`` field but does carry per-cycle ``releaseDate``), find the newest
    already-released, non-EOL cycle that is strictly newer than the host's line. If
    it has been generally available long enough, report the host as behind. Uses
    only live feed dates — no firmware version numbers are hard-coded, so it cannot
    go stale into a false positive.
    """
    if slug not in _NON_LTS_CURRENCY_SLUGS:
        return None
    obs_ver = _parse_version(obs_cycle)
    if obs_ver is None:
        return None
    # Among release lines strictly newer than the host's, that are already GA, not
    # EOL, AND have been available long enough to be considered mature, pick the
    # NEWEST. We deliberately do not demand the host be on a brand-new major that
    # only shipped a few months ago, only on a mature newer line.
    best: Optional[tuple[tuple[int, ...], str, str, int]] = None
    for c in cycles:
        label = str(c.get("cycle", ""))
        cv = _parse_version(label)
        if cv is None or not _lt(obs_ver, cv):   # not newer than the host's line
            continue
        st = _cycle_status(c)
        if st and st[2]:                          # newer line already EOL — skip
            continue
        rd = str(c.get("releaseDate") or "")
        try:
            rdd = date.fromisoformat(rd)
        except (ValueError, TypeError):
            continue
        if rdd > date.today():                    # not generally available yet
            continue
        months_ga = _months_since(rd)
        if months_ga is None or months_ga < _RELEASE_LINE_MIN_MONTHS:
            continue                              # too new to demand the host be on it
        if best is None or cv > best[0]:
            best = (cv, label, rd, months_ga)
    if not best:
        return None
    _cv, newer_label, newer_date, months = best
    age = f"~{months} month{'s' if months != 1 else ''}"
    return _finding(
        target, "outdated_patch_level", "low",
        f"Outdated Release Line: {display} {obs_cycle} (current line {newer_label})",
        f"{display} is running the {obs_cycle} release line. The newer {newer_label} "
        f"line has been generally available since {newer_date} ({age} ago) according "
        "to endoflife.date. Appliances left on a superseded release line miss fixes "
        "and hardening delivered only to the current train, confirm the running "
        f"branch still receives vendor security backports and plan an upgrade to the "
        f"{newer_label} line.",
        0.75,
        {"product": display, "detected_version": detected,
         "detected_cycle": obs_cycle, "newer_cycle": newer_label,
         "newer_cycle_release_date": newer_date, "months_behind": months,
         "kind": "software_component", "cwe": "CWE-1104",
         "source_feed": "endoflife.date"})


# ── Recently-superseded (fast-cadence) EOL vs genuine abandonment ────────────
# Some products ship release *lines* on a fast cadence and mark a branch
# end-of-life the moment a newer branch supersedes it — nginx is the archetype:
# branch 1.29 (shipped 2025-06, EOL 2026-05 after ~11 months) was retired simply
# because 1.31 shipped, while 1.30/1.31 remain supported. A branch like that is a
# *patch-currency* gap (move to the supported line) rather than the abandoned,
# no-patches-ever exposure that CWE-1104 ``unsupported_software`` describes (Flash,
# Windows XP, a decade-dead Apache 2.2). Reporting the former as
# ``unsupported_software`` lets reconcile_severity escalate it to the full
# abandoned-software band (class base 7.4 → High), over-stating a server that is
# only a line or two behind a current release. We keep it honest: a recently
# superseded, short-lived branch in a still-maintained product is reported as
# ``outdated_patch_level`` (medium); everything else stays ``unsupported_software``.
_RECENT_EOL_MONTHS = 18        # EOL older than this is treated as real abandonment
_SHORT_SUPPORT_MONTHS = 15     # a branch supported longer than this is a real LTS line


def _recently_superseded(cycle: dict, detected_cycle: str, eol_date: str,
                         cycles: list[dict]) -> Optional[tuple[str, str]]:
    """When an EOL branch was *recently superseded* by a still-supported newer
    line in a fast-cadence product, return that ``(newer_cycle, newer_release)``;
    otherwise ``None``. All three conditions must hold, so nothing genuinely
    abandoned is ever softened:

      1. the branch's EOL date is real and within ``_RECENT_EOL_MONTHS`` (a
         vendor-marked ``eol: true`` with no date, or a long-past EOL, never
         qualifies — those are abandonment);
      2. the branch had a *short* support lifetime (``eol - releaseDate`` ≤
         ``_SHORT_SUPPORT_MONTHS``) — a fast-cadence release line, not a multi-year
         long-term-support line (a PostgreSQL major, an OS/appliance line) that
         reached a genuine end of support; and
      3. the product is still actively maintained — a non-EOL cycle strictly newer
         than the host's branch exists (a product with no supported line left is
         itself abandoned).
    """
    months = _months_since(eol_date)
    if months is None or months > _RECENT_EOL_MONTHS:
        return None
    try:
        born = date.fromisoformat(str(cycle.get("releaseDate") or ""))
        died = date.fromisoformat(eol_date)
    except (ValueError, TypeError):
        return None                                   # no reliable support lifetime
    if (died - born).days > _SHORT_SUPPORT_MONTHS * 30:
        return None                                   # a real long-term-support line
    dv = _parse_version(detected_cycle)
    if dv is None:
        return None
    best: Optional[tuple[tuple[int, ...], str, str]] = None
    for c in cycles:
        st = _cycle_status(c)
        if st is None or st[2]:                       # unknown status or itself EOL
            continue
        cv = _parse_version(str(c.get("cycle", "")))
        if cv is None or not _lt(dv, cv):             # must be a line newer than host's
            continue
        if best is None or cv > best[0]:
            best = (cv, str(c.get("cycle", "")), str(c.get("releaseDate") or ""))
    return (best[1], best[2]) if best else None


async def _dynamic_eol_finding(target: str, product: str, version: str,
                               banner: str) -> Optional[dict]:
    """Flag an EOL *or* out-of-date component via endoflife.date.

    Priority: a genuinely end-of-life release is reported as unsupported_software;
    otherwise a still-supported release that is behind the latest patch (for long
    enough to matter) is reported as outdated_patch_level with the real month lag.
    Returns None when the version is current or the feed lacks the data — never a
    guess.
    """
    slug = _endoflife_slug(product, banner)
    if not slug:
        return None
    v = _parse_version(version) or _parse_version(banner)
    if v is None:
        return None
    cycles = await _endoflife_lookup(slug)
    if not cycles:
        return None
    cycle = _find_cycle(cycles, v)
    if not cycle:
        return None
    display = (product or slug).strip() or slug
    detected = ".".join(str(x) for x in v)

    # 1) End-of-life takes priority (no further patches at all).
    status = _cycle_status(cycle)
    if status and status[2]:                       # is_eol
        eol_date, cycle_label, _ = status
        # A short-lived branch that was recently superseded by a still-supported
        # newer line (fast-cadence products such as nginx) is a patch-currency gap,
        # not abandoned software — report it as such (medium) so reconcile_severity
        # does not escalate it to the full unsupported_software band. Genuine
        # abandonment (vendor-marked EOL, a long-past EOL, a multi-year support line,
        # or no supported successor) falls through to the finding below.
        recent = _recently_superseded(cycle, cycle_label, eol_date, cycles)
        if recent:
            newer_label, newer_date = recent
            months = _months_since(eol_date) or 0
            age = f"~{months} month{'s' if months != 1 else ''}"
            return _finding(
                target, "outdated_patch_level", "medium",
                f"Outdated Release Line: {display} {cycle_label} "
                f"(end-of-life, current line {newer_label})",
                f"{display} release line {cycle_label} reached end-of-life on "
                f"{eol_date} ({age} ago) according to endoflife.date and was "
                f"superseded by the still-supported {newer_label} line. {display} "
                "retires release lines on a fast cadence, so a recently superseded "
                "branch is a patch-currency gap rather than abandoned software: move "
                f"it to a vendor-supported line ({newer_label}) to keep receiving "
                "security fixes.",
                0.8,
                {"product": display, "detected_version": detected,
                 "detected_cycle": cycle_label, "newer_cycle": newer_label,
                 "newer_cycle_release_date": newer_date, "eol_date": eol_date,
                 "recently_superseded": True, "months_since_eol": months,
                 "kind": "software_component", "cwe": "CWE-1104",
                 "source_feed": "endoflife.date"})
        when = f" on {eol_date}" if eol_date else ""
        return _finding(
            target, "unsupported_software", "medium",
            f"Unsupported / End-of-Life Software: {display} {cycle_label}".rstrip(),
            f"{display} release {cycle_label} reached end-of-life{when} according to "
            "endoflife.date and receives no further security patches. End-of-life "
            "software leaves any newly disclosed vulnerability permanently "
            "exploitable, inventory and upgrade all affected instances to a "
            "vendor-supported release.",
            0.8,
            {"product": display, "detected_version": detected,
             "kind": "software_component", "eol_date": eol_date or "vendor-marked EOL",
             "cwe": "CWE-1104", "source_feed": "endoflife.date"})

    # 2) Supported but behind the latest patch → currency finding with real lag.
    latest = str(cycle.get("latest") or "")
    latest_date = str(cycle.get("latestReleaseDate") or "")
    lv = _parse_version(latest)
    if latest and lv and _lt(v, lv):
        months = _months_since(latest_date)
        if months is not None and months >= _CURRENCY_MIN_MONTHS:
            sev = "medium" if months >= 6 else "low"
            age = f"~{months} month{'s' if months != 1 else ''}"
            return _finding(
                target, "outdated_patch_level", sev,
                f"Outdated Patch Level: {display} {detected} ({age} behind latest)",
                f"{display} {detected} is behind the latest patch {latest} for this "
                f"release line, which endoflife.date records as published on "
                f"{latest_date} ({age} ago). The host is therefore missing {age} of "
                f"security and stability fixes. Upgrade {display} to {latest} "
                "(or newer) and adopt a regular patch cadence.",
                0.8,
                {"product": display, "detected_version": detected,
                 "latest_version": latest, "latest_release_date": latest_date,
                 "months_behind": months, "kind": "software_component",
                 "cwe": "CWE-1104", "source_feed": "endoflife.date"})

    # 3) No `latest` field (typical for appliances). For non-LTS appliance slugs,
    #    fall back to release-LINE currency using the feed's per-cycle dates.
    rl = _release_line_currency_finding(
        target, display, slug, detected, str(cycle.get("cycle", "")), cycles)
    if rl:
        return rl
    return None


async def scan_eol_from_net(net_data: dict, *, dynamic: bool = True) -> dict:
    """Analyse a network-recon result for end-of-life OS and software.

    ``net_data`` is the ``scan_network`` dict (``{"hosts": [...]}``). The static
    tables above are checked first (curated, offline, precise); for any product
    they don't cover, the live endoflife.date feed is consulted so a supported
    fact-based EOL finding is still raised — never a guess. Returns the standard
    scanner result shape.
    """
    from heaven.recon.passive_intel import passive_intel_enabled

    hosts = net_data.get("hosts", []) if isinstance(net_data, dict) else []
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    use_dynamic = dynamic and _AIOHTTP and passive_intel_enabled()
    live_used = 0

    for host in hosts:
        ip = host.get("ip") or host.get("host") or ""
        if not ip:
            continue
        os_guess = str(host.get("os_guess") or "")
        if os_guess:
            osf = _os_finding(ip, os_guess)
            if osf:
                key = (ip, "os", os_guess.lower())
                if key not in seen:
                    seen.add(key)
                    findings.append(osf)
        for p in host.get("open_ports", []):
            port = p.get("port", "")
            product = str(p.get("product") or "")
            version = str(p.get("version") or "")
            banner = str(p.get("banner") or "")
            if not (product or banner):
                continue
            target = f"{ip}:{port}"
            static_hits = _product_findings(target, product, version, banner)
            if static_hits:
                for f in static_hits:
                    prod = f["evidence"]["product"]
                    key = (ip, prod.lower(), f["evidence"].get("detected_version", ""))
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
                continue
            # Gap-fill: nothing in the static table matched this product — ask the
            # live feed (bounded per scan; cache dedups repeat products).
            dyn = None
            if use_dynamic and live_used < _EOL_MAX_LOOKUPS and product:
                live_used += 1
                dyn = await _dynamic_eol_finding(target, product, version, banner)
            if dyn:
                prod = dyn["evidence"]["product"]
                key = (ip, prod.lower(), dyn["evidence"].get("detected_version", ""))
                if key not in seen:
                    seen.add(key)
                    findings.append(dyn)
                continue
            # Curated currency dataset (offline) for products endoflife.date does
            # not cover (e.g. OpenSSH). It is part of the currency layer, so it
            # honours the same passive-intel gate as the live feed — off in the
            # test suite, on by default in production.
            if use_dynamic and (product or banner):
                from heaven.vulnscan.firmware_currency import (
                    firmware_currency_finding,
                )
                fc = firmware_currency_finding(target, product, version, banner)
                if fc:
                    prod = fc["evidence"]["product"]
                    key = (ip, prod.lower(),
                           fc["evidence"].get("detected_version", ""))
                    if key not in seen:
                        seen.add(key)
                        findings.append(fc)

    logger.info("EOL scan → %d unsupported-software finding(s) across %d host(s)",
                len(findings), len(hosts))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
