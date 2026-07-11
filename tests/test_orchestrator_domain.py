"""Regression tests for orchestrator domain extraction (`_registered_domain`).

A live web-mode scan against ``http://127.0.0.1:8890`` used to emit
``spf_missing`` / ``dmarc_missing`` / ``dkim_not_found`` / ``dnssec_not_enabled``
findings whose target was the string ``"0.1"`` — a bare IP mangled by a naive
``host.split(".")[-2:]`` (``127.0.0.1`` → ``["0", "1"]`` → ``"0.1"``). Those
DNS/email-posture checks are domain-level record lookups and are meaningless
against an IP literal, so they are pure false positives.

These tests lock in that the shared helper returns ``None`` for IPs / localhost /
single-label hosts (so the DNS + email phases skip them) while still returning
the registered domain for genuine hostnames.
"""
from __future__ import annotations

import pytest

from heaven.orchestrator import _registered_domain


@pytest.mark.parametrize("host", [
    "127.0.0.1",       # loopback IPv4 — used to become "0.1"
    "192.168.1.10",    # private IPv4
    "10.0.0.1",
    "8.8.8.8",         # public IPv4 is still an IP, not a domain
    "::1",             # IPv6 loopback
    "2606:4700:4700::1111",
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
