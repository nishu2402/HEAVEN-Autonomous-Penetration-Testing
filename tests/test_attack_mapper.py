"""Regression tests for the MITRE ATT&CK mapper (FP Audit 16).

The vuln_type fallback used a bare ``vtype in vuln_type`` substring test. The key
``rce`` is a substring of ``source`` / ``resource`` / ``force``, so a finding with
no mapped CWE and ``vuln_type="source_code_disclosure"`` was mislabeled as
T1059 Command and Scripting Interpreter (Execution) and given a 1.5x risk
multiplier in the ATT&CK heatmap. The boundary-aware match keeps real
underscore-separated variants matching while dropping the collisions.
"""

from __future__ import annotations

from heaven.mitre.attack_mapper import MITREAttackMapper, _vtype_matches


def _techs(vuln_type: str, **extra):
    m = MITREAttackMapper()
    mp = m.map_finding({"id": "x", "title": vuln_type, "vuln_type": vuln_type, **extra})
    return [t.technique_id for t in mp.techniques], mp.risk_multiplier


def test_rce_substring_does_not_mislabel_source_disclosure():
    techs, rmult = _techs("source_code_disclosure")
    assert techs == [], f"source_code_disclosure wrongly mapped: {techs}"
    assert rmult == 1.0


def test_rce_substring_does_not_mislabel_resource_exhaustion():
    techs, rmult = _techs("resource_exhaustion")
    assert techs == []
    assert rmult == 1.0


def test_real_rce_still_maps_to_execution():
    techs, rmult = _techs("rce")
    assert techs == ["T1059"]
    assert rmult == 1.5
    # token-bounded variant still matches
    assert _techs("confirmed_rce")[0] == ["T1059"]


def test_underscore_separated_variants_still_match():
    assert _techs("blind_sqli")[0] == ["T1190", "T1059"]
    assert _techs("stored_xss")[0] == ["T1189", "T1185"]
    assert _techs("http_request_smuggling")[0] == ["T1190", "T1557"]
    assert _techs("graphql_introspection_enabled")[0] == ["T1082"]


def test_cwe_path_is_authoritative_over_vuln_type():
    # A finding carrying a mapped CWE uses the exact CWE lookup, never the
    # substring fallback, so there is no collision risk on that path.
    m = MITREAttackMapper()
    mp = m.map_finding({"id": "x", "title": "t", "vuln_type": "source_code_disclosure",
                        "cwe": "CWE-200"})
    assert [t.technique_id for t in mp.techniques] == ["T1082", "T1083"]


def test_vtype_matches_helper():
    assert _vtype_matches("rce", "rce")
    assert _vtype_matches("rce", "confirmed_rce")
    assert _vtype_matches("rce", "rce_via_upload")
    assert not _vtype_matches("rce", "source_code_disclosure")
    assert not _vtype_matches("rce", "resource_exhaustion")
    assert _vtype_matches("xss", "stored_xss")
