"""Taxonomy coverage: every *real* finding must show CWE/OWASP/MITRE/CVSS-vector,
never the blank cells the user reported. Covers three layers:

1. Curated aliases/entries for detector-emitted classes that were previously
   uncovered (the OPTIONS-methods finding from the screenshot, cookies, CSRF,
   session, SMTP relay, DNS zone transfer, network-device exposures, AD types).
2. The dynamic keyword fallback for an uncurated class.
3. The severity-based CVSS-vector fallback so the vector cell is never blank.
4. Positive/informational posture stays intentionally blank (not fabricated).
"""
from __future__ import annotations

import re

import pytest

from heaven.devsecops import vuln_kb as kb


# ── 1) Previously-blank detector classes now resolve to real taxonomy ────────
@pytest.mark.parametrize("vuln_type,cwe", [
    ("dangerous_methods_allowed", "CWE-650"),   # the screenshot finding
    ("method_override_accepted", "CWE-650"),
    ("xst_trace_enabled", "CWE-650"),
    ("cookie_no_secure", "CWE-1004"),
    ("cookie_no_samesite", "CWE-1004"),
    ("csp_unsafe_eval", "CWE-693"),
    ("csrf_missing_token", "CWE-352"),
    ("oauth_state_reflected", "CWE-352"),
    ("session_fixation", "CWE-384"),
    ("weak_session_id", "CWE-331"),
    ("host_header_injection", "CWE-644"),
    ("http_parameter_pollution", "CWE-235"),
    ("cache_poisoning_unkeyed_header", "CWE-444"),
    ("web_cache_deception", "CWE-525"),
    ("weak_login_credentials", "CWE-1392"),
    ("weak_http_auth_credentials", "CWE-1392"),
    ("no_account_lockout", "CWE-307"),
    ("weak_password_policy", "CWE-521"),
    ("smtp_open_relay", "CWE-269"),
    ("mta_sts_missing", "CWE-319"),
    ("spf_soft_fail", "CWE-16"),
    ("dmarc_policy_none", "CWE-16"),
    ("zone_transfer", "CWE-200"),
    ("technology_disclosure", "CWE-200"),
    ("http_smuggling_te_obfuscation", "CWE-444"),
    ("xxe_entity_expansion", "CWE-611"),
    # network-device exposures (the Cisco case)
    ("cleartext_service", "CWE-319"),
    ("snmp_exposed", "CWE-200"),
    ("snmp_default_community", "CWE-1188"),
    ("cisco_smart_install", "CWE-284"),
    ("ipmi_exposed", "CWE-284"),
    # Active Directory
    ("smb_signing_not_required", "CWE-522"),
    ("smbv1_enabled", "CWE-522"),
    ("kerberoasting", "CWE-522"),
])
def test_detector_class_has_full_taxonomy(vuln_type, cwe):
    f = kb.enrich_finding({"vuln_type": vuln_type, "title": vuln_type,
                           "severity": "medium"})
    assert f.get("cwe") == cwe, f"{vuln_type} → {f.get('cwe')} (expected {cwe})"
    assert f.get("owasp"), f"{vuln_type} missing OWASP"
    assert f.get("mitre_technique"), f"{vuln_type} missing MITRE"
    assert f.get("cvss_vector", "").startswith("CVSS:3.1/"), f"{vuln_type} no vector"


# ── 2) Dynamic keyword fallback for an uncurated class ───────────────────────
def test_uncurated_class_keyword_fallback():
    # A brand-new detector type not in the KB, but the title names the class.
    f = kb.enrich_finding({"vuln_type": "brand_new_detector_2027",
                           "title": "Reflected SQL injection in id param",
                           "severity": "critical"})
    assert f["cwe"] == "CWE-89"
    assert "Injection" in f["owasp"]
    assert f["cvss_vector"].startswith("CVSS:3.1/")


# ── 3) Even a totally-unknown class gets a severity-based CVSS vector ─────────
def test_unknown_class_still_gets_severity_vector():
    f = kb.enrich_finding({"vuln_type": "zzz_no_keywords_here_9999",
                           "title": "opaque thing", "severity": "high"})
    # No keyword → CWE/OWASP left blank (not guessed) …
    assert not f.get("cwe")
    # … but the vector cell is never blank.
    assert f["cvss_vector"].startswith("CVSS:3.1/")


# ── 4) Positive/informational posture is intentionally blank, not fabricated ──
@pytest.mark.parametrize("vuln_type", [
    "dnssec_enabled", "mta_sts_enabled", "tls_rpt_enabled",
])
def test_positive_posture_not_given_a_weakness_cwe(vuln_type):
    f = kb.enrich_finding({"vuln_type": vuln_type, "title": vuln_type,
                           "severity": "info"})
    assert not f.get("cwe")      # a correctly-configured control is not a weakness
    assert not f.get("owasp")


# ── 5) Regression: every emitted vuln_type literal resolves somewhere ─────────
def test_no_real_emitted_type_is_uncovered():
    """A curated allowlist of the vuln_types HEAVEN detectors actually emit — each
    must resolve to a KB entry or alias (the fix for the 46 previously-blank)."""
    emitted = [
        "dangerous_methods_allowed", "method_override_accepted", "xst_trace_enabled",
        "cookie_no_secure", "cookie_no_samesite", "csp_unsafe_eval",
        "csrf_missing_token", "session_fixation", "weak_session_id",
        "host_header_injection", "http_parameter_pollution",
        "cache_poisoning_unkeyed_header", "web_cache_deception",
        "content_type_confusion", "hidden_parameter_discovered",
        "weak_login_credentials", "weak_http_auth_credentials",
        "no_account_lockout", "weak_password_policy", "technology_disclosure",
        "smtp_open_relay", "mta_sts_missing", "spf_open_relay", "spf_soft_fail",
        "spf_too_many_lookups", "dmarc_policy_none", "dmarc_partial_rollout",
        "zone_transfer", "dnssec_zone_walking", "dns_wildcard",
        "ptr_records_discovered", "mx_dangling", "dns_version_disclosure",
        "http_smuggling_te_obfuscation", "xxe_entity_expansion", "oauth_open_redirect",
        "oauth_state_reflected",
    ]
    uncovered = []
    for vt in emitted:
        key = kb.normalize_key(vt)
        if key not in kb._KB and key not in kb._ALIASES:
            uncovered.append(vt)
    assert not uncovered, f"still-blank detector types: {uncovered}"


def test_dangerous_methods_matches_mitre_id_regex_is_not_true():
    """The screenshot finding must NOT be mistaken for an attack-plan artifact
    (bare MITRE id). It's a real finding."""
    from heaven.engagement import is_attack_plan_artifact
    assert not is_attack_plan_artifact(
        {"vuln_type": "dangerous_methods_allowed", "title": "OPTIONS"})
    # sanity: the vector table is internally consistent CVSS 3.1
    for vt in ("cleartext_service", "snmp_default_community", "csrf"):
        vec = kb.cvss_vector_for(vt)
        assert re.match(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/", vec)
