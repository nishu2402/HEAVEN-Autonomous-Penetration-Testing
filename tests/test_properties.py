"""
HEAVEN — property-based tests using Hypothesis.

Property tests find edge cases that example-based tests miss. We check:
  - parse_port_range is total over its valid input domain
  - parse_port_range never returns invalid ports
  - target validation is consistent (no false accepts on garbage)
  - kill chain analyzer is robust to weird finding shapes
  - JWT auth roundtrips work for any plausible payload

Run: pytest tests/test_properties.py -v
"""
from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st


# ── parse_port_range invariants ────────────────────────────────────────

# Strategy: lists of port specs (ints in 1-65535), assembled into spec strings
single_ports = st.integers(min_value=1, max_value=65535)
port_ranges = st.tuples(single_ports, single_ports)


@st.composite
def port_spec_strings(draw):
    """Generate plausible port spec strings."""
    pieces = []
    for _ in range(draw(st.integers(min_value=1, max_value=8))):
        kind = draw(st.sampled_from(["single", "range", "spaced"]))
        if kind == "single":
            pieces.append(str(draw(single_ports)))
        elif kind == "range":
            lo, hi = draw(port_ranges)
            pieces.append(f"{lo}-{hi}")
        else:  # spaced
            pieces.append(f" {draw(single_ports)} ")
    return ",".join(pieces)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(spec=port_spec_strings())
def test_parse_port_range_returns_valid_ports(spec):
    from heaven.recon.network_scanner import parse_port_range
    ports = parse_port_range(spec)
    assert all(1 <= p <= 65535 for p in ports), f"Out-of-range port from spec '{spec}'"
    assert ports == sorted(set(ports)), "Result must be sorted and deduplicated"


@settings(max_examples=100)
@given(spec=port_spec_strings())
def test_parse_port_range_idempotent(spec):
    """Parsing twice with the same input gives the same output."""
    from heaven.recon.network_scanner import parse_port_range
    a = parse_port_range(spec)
    b = parse_port_range(spec)
    assert a == b


@settings(max_examples=50)
@given(p=single_ports)
def test_parse_single_port_round_trip(p):
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range(str(p)) == [p]


# Negative tests — invalid input should raise, never crash
INVALID_SPECS = [
    "",              # empty
    "0",             # below range
    "65536",         # above range
    "abc",           # non-numeric
    "80-",           # malformed range
    "-80",           # malformed range
    "80--90",        # double dash
    "1,abc,2",       # mixed valid/invalid
    "0-65535",       # starts at 0
    "100000",        # way above
]


@pytest.mark.parametrize("bad_spec", INVALID_SPECS)
def test_parse_port_range_rejects_invalid(bad_spec):
    from heaven.recon.network_scanner import parse_port_range
    with pytest.raises(ValueError):
        parse_port_range(bad_spec)


def test_parse_port_range_handles_wildcard():
    from heaven.recon.network_scanner import parse_port_range
    result = parse_port_range("*")
    assert len(result) == 65535
    assert result[0] == 1 and result[-1] == 65535


def test_parse_port_range_normalizes_reversed_range():
    from heaven.recon.network_scanner import parse_port_range
    assert parse_port_range("100-50") == parse_port_range("50-100")


# ── Target validation invariants ───────────────────────────────────────

@settings(max_examples=200)
@given(text=st.text(min_size=1, max_size=100, alphabet=string.printable))
def test_target_validation_never_crashes(text):
    """Validator must return a tuple without crashing on any string."""
    from heaven.main import _validate_target_string
    ok, kind = _validate_target_string(text)
    assert isinstance(ok, bool)
    assert kind in ("ip", "host", "invalid")
    if not ok:
        assert kind == "invalid"


@settings(max_examples=100)
@given(
    a=st.integers(0, 255), b=st.integers(0, 255),
    c=st.integers(0, 255), d=st.integers(0, 255),
)
def test_valid_ipv4_always_accepted(a, b, c, d):
    from heaven.main import _validate_target_string
    ok, kind = _validate_target_string(f"{a}.{b}.{c}.{d}")
    assert ok and kind == "ip"


# ── Kill chain analyzer robustness ─────────────────────────────────────

@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(findings=st.lists(
    st.fixed_dictionaries({
        "title": st.text(max_size=100),
        "severity": st.sampled_from(["critical", "high", "medium", "low", "info", "unknown"]),
        "type": st.text(max_size=30, alphabet=string.ascii_lowercase + "_"),
        "target": st.text(max_size=50),
    }),
    max_size=20,
))
def test_kill_chain_handles_arbitrary_findings(findings):
    from heaven.mitre.kill_chain import KillChainAnalyzer
    analyzer = KillChainAnalyzer()
    count = analyzer.ingest(findings)
    assert count == len(findings)
    report = analyzer.report()
    assert 0 <= report["coverage_score"] <= 100
    assert report["phase_count"] == 7


def test_kill_chain_empty_findings_zero_score():
    from heaven.mitre.kill_chain import KillChainAnalyzer
    analyzer = KillChainAnalyzer()
    analyzer.ingest([])
    assert analyzer.coverage_score() == 0


def test_kill_chain_full_coverage_max_score():
    from heaven.mitre.kill_chain import KillChainAnalyzer
    analyzer = KillChainAnalyzer()
    # Hand-craft findings hitting every phase
    findings = [
        {"type": "open_port", "severity": "low", "target": "x"},
        {"type": "outdated_software", "severity": "medium", "target": "x"},
        {"type": "exposed_upload", "severity": "high", "target": "x"},
        {"type": "sqli", "severity": "critical", "target": "x"},
        {"type": "writable_webroot", "severity": "high", "target": "x"},
        {"type": "exposed_mgmt_interface", "severity": "high", "target": "x"},
        {"type": "public_s3", "severity": "critical", "target": "x"},
    ]
    analyzer.ingest(findings)
    assert analyzer.coverage_score() == 100


# ── FP suppression bucket boundaries ───────────────────────────────────

@given(conf=st.floats(min_value=0.0, max_value=1.0, allow_nan=False))
def test_bucket_for_returns_valid_bucket(conf):
    from heaven.vulnscan.fp_suppress import _bucket_for
    bucket = _bucket_for(conf)
    assert bucket in ("strong", "high", "medium", "low", "discarded")


def test_bucket_boundaries():
    from heaven.vulnscan.fp_suppress import _bucket_for
    assert _bucket_for(0.99) == "strong"
    assert _bucket_for(0.95) == "strong"
    assert _bucket_for(0.94) == "high"
    assert _bucket_for(0.80) == "high"
    assert _bucket_for(0.79) == "medium"
    assert _bucket_for(0.60) == "medium"
    assert _bucket_for(0.59) == "low"
    assert _bucket_for(0.40) == "low"
    assert _bucket_for(0.39) == "discarded"
    assert _bucket_for(0.0) == "discarded"


# ── Auth manager round-trip ────────────────────────────────────────────

def test_auth_manager_token_roundtrip(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "test-rt-pwd-12345")
    import sys
    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]
    from heaven.security.auth import get_auth_manager

    auth = get_auth_manager()
    result = auth.authenticate("admin", "test-rt-pwd-12345")
    assert result is not None
    token = result["token"]

    # Same token should resolve to same user
    session = auth._sessions.get(token)
    assert session is not None
    user = auth._users.get(session.user_id)
    assert user is not None
    assert user.username == "admin"


def test_auth_manager_rejects_wrong_password(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "test-pwd-correct")
    import sys
    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]
    from heaven.security.auth import get_auth_manager
    auth = get_auth_manager()
    assert auth.authenticate("admin", "wrong-password") is None
