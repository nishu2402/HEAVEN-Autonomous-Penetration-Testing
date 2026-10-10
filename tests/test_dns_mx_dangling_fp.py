"""Regression: a 'Dangling MX Record' (HIGH) must fire only when the MX host
PROVABLY does not exist (NXDOMAIN).

``_analyze_mx`` used to flag dangling MX on an empty ``_resolve(mx_host, "A")``,
but ``_resolve`` swallows every DNS error to ``[]`` — so an IPv6-only MX host
(exists, AAAA only, ``NoAnswer`` on A) and a transient ``SERVFAIL``/timeout both
produced a HIGH "attacker registers the host and receives all email" finding,
and the text even claimed it had checked A/AAAA while looking only at A. The fix
routes the decision through ``_host_is_nxdomain``, which flags only a provably
non-existent (registerable) name.

See heaven/recon/dns_recon.py (_host_is_nxdomain, _analyze_mx).
"""
from __future__ import annotations

import pytest

import heaven.recon.dns_recon as dr


def _mx_only(name, rtype, nameservers=None, timeout=5.0):
    # The domain advertises one MX host; nothing else is asked of _resolve here
    # because the dangling decision now goes through _host_is_nxdomain.
    if rtype == "MX":
        return ["10 mail.example.com."]
    return []


def test_dangling_mx_not_flagged_when_host_exists(monkeypatch):
    monkeypatch.setattr(dr, "_resolve", _mx_only)
    monkeypatch.setattr(dr, "_host_is_nxdomain", lambda *_a, **_k: False)
    findings = dr._analyze_mx("example.com")
    assert [f for f in findings if f["vuln_type"] == "mx_dangling"] == []


def test_dangling_mx_not_flagged_for_ipv6_only_or_transient(monkeypatch):
    # _host_is_nxdomain already collapses NoAnswer (AAAA-only) and SERVFAIL/timeout
    # to False; this pins that _analyze_mx raises nothing in that case.
    monkeypatch.setattr(dr, "_resolve", _mx_only)
    monkeypatch.setattr(dr, "_host_is_nxdomain", lambda *_a, **_k: False)
    assert dr._analyze_mx("example.com") == []


def test_dangling_mx_flagged_only_on_nxdomain(monkeypatch):
    monkeypatch.setattr(dr, "_resolve", _mx_only)
    monkeypatch.setattr(dr, "_host_is_nxdomain", lambda *_a, **_k: True)
    findings = dr._analyze_mx("example.com")
    dangling = [f for f in findings if f["vuln_type"] == "mx_dangling"]
    assert len(dangling) == 1
    assert dangling[0]["severity"] == "high"
    assert dangling[0]["evidence"]["dns_state"] == "NXDOMAIN"
    assert "mail.example.com" in dangling[0]["evidence"]["unresolvable_host"]


@pytest.mark.skipif(not dr.HAS_DNSPYTHON, reason="dnspython not installed")
def test_host_is_nxdomain_discriminates_dns_states(monkeypatch):
    import dns.resolver

    class _FakeResolver:
        mode = "ok"

        def __init__(self):
            self.lifetime = 0.0

        def resolve(self, name, rtype):
            if _FakeResolver.mode == "ok":
                return ["1.2.3.4"]
            cls = {
                "noanswer": dns.resolver.NoAnswer,
                "nxdomain": dns.resolver.NXDOMAIN,
                "timeout": Exception,
            }[_FakeResolver.mode]
            # Build the exception without invoking its (version-specific) __init__.
            raise cls.__new__(cls)

    monkeypatch.setattr(dns.resolver, "Resolver", _FakeResolver)

    _FakeResolver.mode = "ok"
    assert dr._host_is_nxdomain("mail.example.com") is False      # resolves → exists
    _FakeResolver.mode = "noanswer"
    assert dr._host_is_nxdomain("mail.example.com") is False      # AAAA-only / other records
    _FakeResolver.mode = "timeout"
    assert dr._host_is_nxdomain("mail.example.com") is False      # transient → cannot prove
    _FakeResolver.mode = "nxdomain"
    assert dr._host_is_nxdomain("mail.example.com") is True       # registerable
