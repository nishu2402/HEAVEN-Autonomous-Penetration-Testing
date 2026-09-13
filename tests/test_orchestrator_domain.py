"""Regression tests for orchestrator domain extraction (`_registered_domain`).

A live web-mode scan against ``http://127.0.0.1:8890`` used to emit
``spf_missing`` / ``dmarc_missing`` / ``dkim_not_found`` / ``dnssec_missing``
findings whose target was the string ``"0.1"`` — a bare IP mangled by a naive
``host.split(".")[-2:]`` (``127.0.0.1`` → ``["0", "1"]`` → ``"0.1"``). Those
DNS/email-posture checks are domain-level record lookups and are meaningless
against an IP literal, so they are pure false positives.

The same mangling bit internal-network engagements scanned by CIDR: a target
like ``192.168.2.0/24`` is not an IP *address* (``ipaddress.ip_address`` rejects
CIDR notation), so it fell through to the eTLD+1 fallback and became the fake
domain ``"2.0/24"`` -> ``"2.0"``. That produced phantom ``spf_missing`` /
``dmarc_missing`` / ``dkim_not_found`` / ``dnssec_missing`` findings whose target
was ``"2.0"`` (``10.0.0.0/8`` -> ``"0.0"``), which then surfaced in Combined Risk
as a nonsense host. A network range is even less of a domain than a single IP.

These tests lock in that the shared helper returns ``None`` for IPs / CIDRs /
localhost / single-label hosts (so the DNS + email phases skip them) while still
returning the registered domain for genuine hostnames.
"""
from __future__ import annotations

import pytest

from heaven.orchestrator import _registered_domain, _scan_domains


@pytest.mark.parametrize("host", [
    "127.0.0.1",       # loopback IPv4 — used to become "0.1"
    "192.168.1.10",    # private IPv4
    "10.0.0.1",
    "8.8.8.8",         # public IPv4 is still an IP, not a domain
    "::1",             # IPv6 loopback
    "2606:4700:4700::1111",
    "192.168.2.0/24",  # CIDR — used to become "2.0/24" -> "2.0"
    "10.0.0.0/8",      # CIDR — used to become "0.0"
    "127.0.0.1/32",
    "2001:db8::/32",   # IPv6 CIDR
    "localhost",
    "intranet",        # single-label host, no public domain
    "",
    None,              # defensive: never blows up on a missing hostname
])
def test_no_domain_for_ip_or_bare_host(host):
    assert _registered_domain(host) is None


@pytest.mark.parametrize("host,expected", [
    ("example.com", "example.com"),
    ("www.example.com", "example.com"),
    ("a.b.c.example.org", "example.org"),
    ("EXAMPLE.COM.", "example.com"),          # case + trailing dot normalised
    ("example.com:8443", "example.com"),      # stray port stripped
])
def test_registered_domain_for_real_hosts(host, expected):
    assert _registered_domain(host) == expected


def test_scan_domains_drops_cidr_but_keeps_real_domain():
    """An internal-network engagement scanned by CIDR must contribute NO
    domain-level DNS/email targets (else it fires phantom SPF/DMARC findings),
    while a real domain in the same run still enumerates."""
    # Pure internal CIDR + host IP: nothing to run domain checks against.
    assert _scan_domains({"ips": ["192.168.2.0/24", "192.168.2.153"]}) == []
    assert _scan_domains({"ips": ["10.0.0.0/8"]}) == []
    # A genuine domain survives even when a CIDR shares the target bucket.
    assert _scan_domains(
        {"domains": ["example.com"], "ips": ["192.168.2.0/24"]}
    ) == ["example.com"]
