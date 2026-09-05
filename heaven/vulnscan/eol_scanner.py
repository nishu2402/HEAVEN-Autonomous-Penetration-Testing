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
            # Prefer the structured version field, fall back to the banner text.
            v = _parse_version(version) or _parse_version(banner)
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
]


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
    cands: list[str] = []
    if len(version) >= 2:
        cands.append(f"{version[0]}.{version[1]}")
    cands.append(f"{version[0]}")
    for cand in cands:
        for c in cycles:
            if str(c.get("cycle", "")) == cand:
                return _cycle_status(c)
    return None


async def _dynamic_eol_finding(target: str, product: str, version: str,
                               banner: str) -> Optional[dict]:
    """Flag an EOL component via endoflife.date; None unless it's genuinely EOL."""
    slug = _endoflife_slug(product, banner)
    if not slug:
        return None
    v = _parse_version(version) or _parse_version(banner)
    if v is None:
        return None
    cycles = await _endoflife_lookup(slug)
    if not cycles:
        return None
    match = _match_cycle(cycles, v)
    if not match:
        return None
    eol_date, cycle_label, is_eol = match
    if not is_eol:
        return None
    display = (product or slug).strip() or slug
    detected = ".".join(str(x) for x in v)
    when = f" on {eol_date}" if eol_date else ""
    return _finding(
        target, "unsupported_software", "medium",
        f"Unsupported / End-of-Life Software: {display} {cycle_label}".rstrip(),
        f"{display} release {cycle_label} reached end-of-life{when} according to "
        "endoflife.date and receives no further security patches. End-of-life "
        "software leaves any newly disclosed vulnerability permanently "
        "exploitable — inventory and upgrade all affected instances to a "
        "vendor-supported release.",
        0.8,
        {"product": display, "detected_version": detected,
         "kind": "software_component", "eol_date": eol_date or "vendor-marked EOL",
         "cwe": "CWE-1104", "source_feed": "endoflife.date"})


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
            if use_dynamic and live_used < _EOL_MAX_LOOKUPS and product:
                live_used += 1
                dyn = await _dynamic_eol_finding(target, product, version, banner)
                if dyn:
                    prod = dyn["evidence"]["product"]
                    key = (ip, prod.lower(), dyn["evidence"].get("detected_version", ""))
                    if key not in seen:
                        seen.add(key)
                        findings.append(dyn)

    logger.info("EOL scan → %d unsupported-software finding(s) across %d host(s)",
                len(findings), len(hosts))
    return {"findings": findings, "vulnerabilities": findings, "total": len(findings)}
