"""Domain-name helpers shared across the scanner.

The single source of truth for ``registered_domain`` (eTLD+1 extraction). It used
to live as two hand-synced copies in ``heaven.orchestrator`` and
``heaven.vulnscan.auth_scanner``; those drifted (one gained a CIDR guard the other
lacked), so the logic is consolidated here and both import it.

The registered domain is what a DNS/email-posture check (SPF, DMARC, DKIM, DNSSEC)
must run against, and what a redirect-scope check compares. Getting it wrong is not
cosmetic: a bad extraction fires guaranteed-false "record missing" findings at a
target that is not a domain at all, and those then surface in Combined Risk.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

# Multi-part public suffixes where the registrable domain is the last THREE
# labels, not two. A naive ``split('.')[-2:]`` collapses ``nehemiah.co.uk`` to the
# bare suffix ``co.uk`` and then reports SPF/DMARC "missing" against ``co.uk`` (a
# public suffix nobody can send mail as), while never checking the real domain.
#
# This is a curated subset of the Public Suffix List covering the second-level
# ccTLD registries a real engagement actually hits. It is deliberately NOT the
# full PSL: the full list is ~15k entries that need a bundled data file and a
# periodic network refresh, which this dependency-free helper avoids. Anything not
# listed falls back to the standard last-two-labels rule, so a miss degrades to
# the old behaviour for that one suffix rather than breaking.
_MULTI_PART_SUFFIXES = frozenset({
    # United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "mod.uk", "nhs.uk", "police.uk", "nic.uk",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "geek.nz", "school.nz",
    # South Africa
    "co.za", "org.za", "web.za", "gov.za", "ac.za", "net.za",
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "gov.in", "ac.in",
    # South Korea
    "co.kr", "or.kr", "ne.kr", "go.kr", "re.kr",
    # Mexico
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    # Singapore / Hong Kong / Taiwan
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.hk", "edu.hk", "gov.hk", "net.hk", "org.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    # Israel / Turkey / Ukraine
    "co.il", "org.il", "gov.il", "ac.il", "net.il",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.ua", "net.ua", "org.ua", "gov.ua",
    # Argentina
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    # Indonesia / Malaysia / Philippines
    "co.id", "or.id", "go.id", "ac.id", "web.id", "net.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    # Pakistan / Egypt / Saudi Arabia
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    # Thailand / Vietnam
    "co.th", "in.th", "go.th", "ac.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
})


def registered_domain(host: str) -> Optional[str]:
    """Best-effort registered domain (eTLD+1) for a *hostname*, or ``None``.

    Returns ``None`` for anything that is not a public domain name, so callers can
    skip domain-level DNS/email checks instead of firing false positives:

      * IP literals (v4/v6) and CIDR / network ranges (``127.0.0.1``,
        ``192.168.2.0/24``) — a naive ``split('.')[-2:]`` would mangle these into
        ``0.1`` / ``2.0`` and check a domain that does not exist;
      * ``localhost`` and bare single-label intranet names;
      * a bare public suffix (``co.uk``) that has no registrable domain of its own.

    For a genuine hostname it returns the registrable domain, honouring common
    multi-part ccTLD suffixes (``a.b.nehemiah.co.uk`` -> ``nehemiah.co.uk``) and
    normalising case, a trailing dot, and a stray port.
    """
    host = (host or "").strip().rstrip(".").lower()
    if not host or host == "localhost":
        return None
    # A CIDR / slash-bearing token is a network range, never a hostname; reject it
    # before the eTLD+1 fallback. ip_address() does not recognise CIDR notation,
    # so test the network form too rather than relying only on the slash.
    if "/" in host:
        return None
    try:
        ipaddress.ip_network(host, strict=False)
        return None  # bare network address — no domain to check
    except ValueError:
        pass
    # Strip a port if one slipped through (e.g. "example.com:8443").
    if host.count(":") == 1 and "]" not in host:
        host = host.split(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return None  # IPv4/IPv6 literal — no domain to check
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return None  # single-label host (intranet name) — not a public domain
    # Multi-part public suffix (co.uk, com.au, ...): the registrable domain is the
    # last three labels. A host that IS exactly the bare suffix has none.
    if ".".join(parts[-2:]) in _MULTI_PART_SUFFIXES:
        if len(parts) < 3:
            return None
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
