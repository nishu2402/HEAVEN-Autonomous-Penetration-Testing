"""The in-house remediation knowledge base must cover every detected class and
give real guidance with no LLM configured (HEAVEN's default, offline path)."""
from __future__ import annotations

import pytest

from heaven.devsecops import vuln_kb as kb


@pytest.mark.parametrize("emitted,canonical_title", [
    ("sqli", "SQL Injection"),
    ("sqli_confirmed", "SQL Injection"),
    ("cmdi", "OS Command Injection"),
    ("lfi", "File Inclusion (LFI/RFI)"),
    ("rfi", "File Inclusion (LFI/RFI)"),
    ("cors", "CORS Misconfiguration"),
    ("cors_misconfig", "CORS Misconfiguration"),
    ("security_headers", "Missing Security Headers"),
    ("jwt_alg_none", "JWT Accepts alg:none"),
    ("jwt_weak_secret", "JWT Signed With a Weak Secret"),
    ("xxe", "XML External Entity (XXE) Injection"),
    ("insecure_cookie", "Insecure Session Cookie"),
    ("open_redirect", "Open Redirect"),
    ("ssrf", "Server-Side Request Forgery"),
])
def test_every_detected_type_resolves(emitted, canonical_title):
    entry = kb.lookup(emitted)
    assert entry.get("title") == canonical_title
    # a real entry always carries actionable remediation + a reference
    assert entry.get("remediation")
    assert entry.get("references")


# Every vuln_type a detector can emit must enrich to a full CWE/OWASP/CVSS
# taxonomy, or the report's taxonomy columns silently go blank for that class.
# This list is the real emitted set across heaven/vulnscan + heaven/recon
# (SSL/TLS scanner, misconfig, injection, headers, DNS/email posture, infra).
# A small set is intentionally informational-only (recon, ML heuristics) and is
# allowed to carry no CWE.
_INFO_ONLY = {"dkim_found", "mx_enumeration", "anomalous_behavior", "zero_day_heuristic"}

_EMITTED_TYPES = [
    # SSL/TLS scanner (heaven/vulnscan/ssl_scanner.py)
    "heartbleed", "drown", "poodle", "freak", "logjam", "beast", "weak_cipher",
    "tls10_only", "tls11_deprecated", "no_forward_secrecy", "no_hsts",
    "hsts_short_maxage", "cert_expired", "cert_expiring_soon", "self_signed_cert",
    "sha1_signature",
    # misconfig / injection / headers
    "jwt_alg_none", "jwt_weak_secret", "cors_misconfig", "insecure_cookie",
    "missing_security_headers", "security_headers", "open_redirect", "sqli",
    "sqli_confirmed", "cmdi", "lfi", "rfi", "xss", "ssrf", "ssti", "xxe", "idor",
    "bola", "path_traversal", "crlf_injection", "request_smuggling",
    "default_credentials", "api_key_leakage", "no_rate_limit", "sensitive_file",
    "directory_listing", "mass_assignment", "race_condition", "subdomain_takeover",
    "graphql_introspection", "graphql_dos", "graphql_batching", "graphql_complexity",
    # DNS / email posture (heaven/recon)
    "spf_missing", "spf_analysis", "dmarc_missing", "dmarc_analysis", "dkim_missing",
    "dkim_weak_key", "dnssec_not_enabled",
    # containers / kubernetes / infra
    "docker_socket_exposed", "docker_api_exposed", "etcd_exposed", "kubelet_exposed",
    "k8s_anon_auth", "k8s_rbac_overprivileged", "k8s_secrets_exposed",
    "privileged_container", "dangerous_mount", "smtp_no_starttls", "ssh_hardening",
    "exposed_database", "exposed_db",
    # posture header spellings
    "csp_unsafe_inline", "oauth_pkce_not_enforced", "xml_accepted",
    "dangerous_http_method",
]


@pytest.mark.parametrize("vt", _EMITTED_TYPES)
def test_every_emitted_type_has_full_taxonomy(vt):
    """No detector-emitted class may render blank CWE/OWASP/CVSS in a report."""
    out = kb.enrich_finding({"vuln_type": vt, "severity": "high", "target": "https://x"})
    ev = out.get("evidence", {})
    cwe = out.get("cwe") or ev.get("cwe")
    owasp = out.get("owasp") or ev.get("owasp")
    vec = out.get("cvss_vector") or ev.get("cvss_vector")
    assert cwe and owasp, f"{vt}: blank CWE/OWASP taxonomy"
    assert vec, f"{vt}: blank CVSS vector"


@pytest.mark.parametrize("vt", sorted(_INFO_ONLY))
def test_info_only_types_resolve_without_error(vt):
    """Informational recon/heuristic classes must not crash enrichment."""
    out = kb.enrich_finding({"vuln_type": vt, "severity": "info"})
    assert isinstance(out, dict) and out.get("evidence") is not None


def test_remediation_text_is_structured_and_specific():
    txt = kb.remediation_text({
        "vuln_type": "jwt_weak_secret", "target": "http://h/login",
        "title": "JWT signed with a weak secret",
    })
    assert "## How to fix it" in txt
    assert "## Impact" in txt
    assert "http://h/login" in txt
    assert "asymmetric" in txt.lower()  # a concrete, class-specific instruction


def test_remediation_text_unknown_class_still_actionable():
    txt = kb.remediation_text({"vuln_type": "some_novel_thing", "severity": "high"})
    # not a bare one-liner — the standard drill with numbered steps
    assert "1." in txt and "2." in txt
    assert "Apply standard security patches for this vulnerability." not in txt


def test_ai_remediation_offline_uses_kb_not_generic_string():
    from heaven.devsecops.ai_remediation import AIRemediationEngine
    eng = AIRemediationEngine()
    eng.available = False  # force the in-house (no-LLM) path deterministically
    out = eng.generate_patch({"vuln_type": "xxe", "target": "http://h/x", "title": "XXE"})
    assert "## How to fix it" in out
    assert "external entity" in out.lower()
    assert out != "Apply standard security patches for this vulnerability."
