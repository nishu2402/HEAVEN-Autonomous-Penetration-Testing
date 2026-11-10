"""Remediation economics: effort classification, ROI priority, quick wins."""

from __future__ import annotations

from heaven.devsecops import remediation_economics as econ


def _f(vuln_type="x", severity="medium", cwe="", **extra):
    d = {"vuln_type": vuln_type, "severity": severity, "cwe": cwe, "evidence": {}}
    d.update(extra)
    return d


def test_effort_classes_by_weakness():
    assert econ.remediation_effort(_f("sql_injection", cwe="CWE-89")) == "high"
    assert econ.remediation_effort(_f("business_logic_abuse", cwe="CWE-840")) == "high"
    assert econ.remediation_effort(_f("idor", cwe="CWE-639")) == "high"
    assert econ.remediation_effort(_f("outdated_software", cwe="CWE-1104")) == "medium"
    assert econ.remediation_effort(_f("weak_credentials", cwe="CWE-521")) == "medium"
    assert econ.remediation_effort(_f("missing_security_header")) == "low"
    assert econ.remediation_effort(_f("tls_weak_cipher")) == "low"
    assert econ.remediation_effort(_f("spf_record_missing")) == "low"
    # Unknown class → medium default.
    assert econ.remediation_effort(_f("totally_unknown_class_zzz")) == "medium"


def test_cwe_drives_effort_when_type_is_opaque():
    # A finding whose type doesn't match a keyword but whose CWE is injection.
    assert econ.remediation_effort(_f("app_flaw_1234", cwe="CWE-79")) == "high"


def test_exploit_signals_lift_risk():
    base = econ.risk_weight(_f("x", "high"))
    kev = econ.risk_weight(_f("x", "high", in_kev=True))
    assert kev > base
    expl = econ.risk_weight(_f("x", "high", exploit_available=True))
    assert expl > base
    # Bounded.
    both = _f("x", "high", in_kev=True, exploit_available=True)
    both["epss_score"] = 0.9
    assert econ.risk_weight(both) <= econ._SEV_WEIGHT["high"] * 1.6 + 1e-9


def test_priority_rewards_low_effort_for_same_risk():
    header = _f("missing_header", "high")          # low effort
    sqli = _f("sql_injection", "high", cwe="CWE-89")  # high effort
    econ.annotate([header, sqli])
    assert header["priority_score"] > sqli["priority_score"]


def test_quick_win_requires_impact_and_low_effort():
    assert econ.is_quick_win(_f("missing_header", "high")) is True
    assert econ.is_quick_win(_f("missing_header", "critical")) is True
    # Low severity + low effort is not a "quick win" headline item.
    assert econ.is_quick_win(_f("missing_header", "low")) is False
    # High severity but high effort is not a quick win.
    assert econ.is_quick_win(_f("sql_injection", "high", cwe="CWE-89")) is False
    # A lifted medium (KEV) low-effort item qualifies.
    assert econ.is_quick_win(_f("tls_weak_cipher", "medium", in_kev=True)) is True
    assert econ.is_quick_win(_f("tls_weak_cipher", "medium")) is False


def test_annotate_stamps_all_three_fields():
    f = _f("missing_header", "high")
    econ.annotate([f])
    assert f["remediation_effort"] == "low"
    assert isinstance(f["priority_score"], float)
    assert f["quick_win"] is True


def test_prioritise_is_deterministic_and_nonmutating():
    findings = [
        _f("sql_injection", "high", cwe="CWE-89"),
        _f("missing_header", "high"),
        _f("tls_weak_cipher", "medium"),
    ]
    original_order = list(findings)
    out = econ.prioritise(findings)
    assert findings == original_order  # input not mutated
    # Low-effort high-severity header leads.
    assert out[0]["vuln_type"] == "missing_header"
    # Stable across calls.
    assert [x["vuln_type"] for x in out] == [x["vuln_type"] for x in econ.prioritise(findings)]


def test_quick_wins_and_markdown():
    findings = [
        _f("missing_header", "high", target="https://a.example.com"),
        _f("sql_injection", "high", cwe="CWE-89", target="https://a.example.com"),
    ]
    wins = econ.quick_wins(findings)
    assert len(wins) == 1
    md = econ.render_quick_wins_markdown(findings)
    assert "Quick wins" in md
    assert "missing_header" in md or "Finding" in md


def test_quick_wins_markdown_empty_when_none():
    assert econ.render_quick_wins_markdown([_f("sql_injection", "high", cwe="CWE-89")]) == ""


def test_effort_summary_counts():
    findings = [
        _f("missing_header", "high"),
        _f("tls_weak_cipher", "low"),
        _f("sql_injection", "high", cwe="CWE-89"),
    ]
    s = econ.effort_summary(findings)
    assert s["low"] == 2
    assert s["high"] == 1


def test_kb_effort_override_wins(monkeypatch):
    # A curated KB override beats the class heuristic.
    import heaven.devsecops.remediation_economics as m
    monkeypatch.setattr(m, "_kb_effort", lambda vt: "low")
    assert m.remediation_effort(_f("sql_injection", cwe="CWE-89")) == "low"
