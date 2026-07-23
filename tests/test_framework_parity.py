"""Framework-coverage parity: OWASP API Top 10 in reports + Coverage self-grade,
the new per-domain detectors' taxonomy, and the wireless-posture surrogate.

Deterministic (no network): scanner network behaviour is verified separately;
here we lock the report/grader/KB wiring that must never silently drift.
"""

import json
from types import SimpleNamespace as NS

from heaven.ai.coverage_grader import grade_engagement_rule_based
from heaven.config import ScanMode
from heaven.devsecops.compliance_report import ComplianceReportGenerator
from heaven.devsecops.pdf_report import PDFReportGenerator
from heaven.devsecops.vuln_kb import enrich_finding
from heaven.recon import wireless_posture as wp

_GEN = ComplianceReportGenerator()

_MIXED = [
    {"title": "SQL Injection", "vuln_type": "sqli", "severity": "high",
     "target": "http://app/login", "owasp": "A03:2021 Injection"},
    {"title": "BOLA", "vuln_type": "bola", "severity": "high", "target": "http://app/api",
     "owasp_api": "API1:2023 Broken Object Level Authorization"},
    {"title": "Swagger exposed", "vuln_type": "api_docs_exposed", "severity": "medium",
     "target": "http://app", "owasp_api": "API9:2023 Improper Inventory Management"},
    {"title": "IoT default creds", "vuln_type": "iot_default_credentials", "severity": "critical",
     "target": "10.0.0.5", "owasp_iot": "I1:2018 Weak, Guessable, or Hardcoded Passwords"},
    {"title": "Modbus exposed", "vuln_type": "ics_modbus_exposed", "severity": "high",
     "target": "10.0.0.9", "protocol": "modbus", "iec62443": "FR1 Identification & Authentication Control"},
]


# ── HTML report ──────────────────────────────────────────────────────────────

def test_report_renders_all_four_matrices():
    html = _GEN.generate_html_report(_MIXED, engagement_name="Parity")
    for needle in ("OWASP Top 10 (2021) Coverage",
                   "OWASP API Security Top 10 (2023) Coverage",
                   "OWASP IoT Top 10 (2018) Coverage",
                   "OT / ICS Security Coverage (IEC 62443)"):
        assert needle in html, needle


def test_report_hides_api_matrix_when_no_api_findings():
    web_only = [{"title": "XSS", "vuln_type": "xss", "severity": "medium", "target": "http://a"}]
    html = _GEN.generate_html_report(web_only, engagement_name="WebOnly")
    assert "OWASP API Security Top 10" not in html
    assert "OWASP IoT Top 10" not in html
    assert "OT / ICS Security Coverage" not in html


def test_web_matrix_excludes_api_iot_ot():
    """The web OWASP-2021 matrix must count only the SQLi — API/IoT/OT findings
    are scored in their own matrices, never double-counted here."""
    web = {cid: 0 for cid, _ in _GEN.OWASP_2021}
    for f in _MIXED:
        cid = _GEN._owasp_category_id(f)
        if cid in web:
            web[cid] += 1
    assert web["A03:2021"] == 1
    assert sum(web.values()) == 1  # nothing else leaked into the web matrix


def test_api_category_bucketing():
    api = {cid: 0 for cid, _ in _GEN.OWASP_API_2023}
    for f in _MIXED:
        cid = _GEN._api_category_id(f)
        if cid in api:
            api[cid] += 1
    assert api["API1"] == 1 and api["API9"] == 1
    assert sum(api.values()) == 2


def test_pdf_generates_with_mixed_findings(tmp_path):
    out = tmp_path / "parity.pdf"
    ok = PDFReportGenerator().generate({"engagement": "Parity", "findings": _MIXED}, str(out))
    assert ok and out.exists() and out.stat().st_size > 2000


# ── Coverage self-grade ──────────────────────────────────────────────────────

def _fake_store(findings):
    def F(f):
        return NS(vuln_type=f["vuln_type"], title=f["title"], target=f["target"],
                  evidence={k: v for k, v in f.items()
                            if k in ("owasp", "owasp_api", "owasp_iot", "iec62443")})
    objs = [F(f) for f in findings]
    return NS(
        get_engagement=lambda: NS(name="Parity", notes=""),
        list_scope=lambda in_scope_only=True: [NS(target="http://app")],
        list_findings=lambda limit=10000: objs,
        list_all_scans=lambda: [],
    )


def test_coverage_grader_scores_domain_frameworks():
    rep = grade_engagement_rule_based(_fake_store(_MIXED)).to_dict()
    web = {c["code"]: c["findings"] for c in rep["owasp_top10"] if c["findings"]}
    api = {c["code"]: c["findings"] for c in rep["owasp_api_top10"] if c["findings"]}
    iot = {c["code"]: c["findings"] for c in rep["owasp_iot"] if c["findings"]}
    ot = {c["code"]: c["findings"] for c in rep["ot_ics"] if c["findings"]}
    # web matrix must exclude API/IoT/OT — only the SQLi remains
    assert web == {"A03_2021": 1}
    assert api == {"API1": 1, "API9": 1}
    assert iot == {"I1": 1}
    assert ot == {"FR1": 1}


def test_coverage_grader_web_only_has_no_domain_lists():
    rep = grade_engagement_rule_based(_fake_store(
        [{"title": "XSS", "vuln_type": "xss", "target": "http://a"}])).to_dict()
    assert rep["owasp_iot"] == [] and rep["ot_ics"] == []
    assert not any(c["findings"] for c in rep["owasp_api_top10"])


# ── Taxonomy for the new detector vuln_types ─────────────────────────────────

def test_new_vuln_types_have_complete_taxonomy():
    for vt in ("api_docs_exposed", "api_actuator_exposed", "api_broken_auth",
               "k8s_insecure_port", "cadvisor_exposed", "registry_exposed",
               "wireless_mgmt_exposed", "wireless_mgmt_unauthenticated",
               "anonymous_ldap_enumeration", "azure_ad_tenant_exposed"):
        e = enrich_finding({"vuln_type": vt, "title": vt, "severity": "high", "target": "x"})
        assert e.get("cwe"), vt
        assert e.get("owasp"), vt
        assert e.get("mitre_technique"), vt
        assert e.get("cvss_vector"), vt


# ── Wireless surrogate ───────────────────────────────────────────────────────

def test_wireless_mode_exists():
    assert ScanMode("wireless") is ScanMode.WIRELESS


def test_wireless_vendor_fingerprint():
    assert wp._match_vendor(["UniFi Network", "nginx", ""])  # controller title
    assert wp._match_vendor(["", "MikroTik RouterOS", ""])   # server header
    assert wp._match_vendor(["Acme Store", "nginx", "welcome"]) is None  # benign


# ── Azure AD / M365 tenant recon (credential-free, deterministic parsers) ─────

import asyncio  # noqa: E402

from heaven.recon import azure_tenant as az  # noqa: E402

_REALM_MANAGED = json.dumps({
    "NameSpaceType": "Managed", "DomainName": "contoso.com",
    "CloudInstanceName": "microsoftonline.com"})
_REALM_FEDERATED = json.dumps({
    "NameSpaceType": "Federated", "DomainName": "corp.example.com",
    "AuthURL": "https://sts.corp.example.com/adfs/ls/",
    "FederationBrandName": "Corp"})
_REALM_UNKNOWN = json.dumps({"NameSpaceType": "Unknown"})
_OIDC_OK = json.dumps({
    "issuer": "https://login.microsoftonline.com/"
              "72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
    "token_endpoint": "https://login.microsoftonline.com/"
                      "72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
    "tenant_region_scope": "WW"})
_OIDC_ERR = json.dumps({"error": "invalid_tenant",
                        "error_description": "AADSTS90002: Tenant not found"})


def test_azure_userrealm_parse():
    m = az.parse_userrealm(_REALM_MANAGED)
    assert m["is_tenant"] and m["namespace_type"] == "Managed"
    f = az.parse_userrealm(_REALM_FEDERATED)
    assert f["is_federated"] and "adfs" in f["federation_auth_url"]
    assert az.parse_userrealm(_REALM_UNKNOWN) == {}   # not a tenant → no data
    assert az.parse_userrealm("not json") == {}


def test_azure_openid_parse():
    oc = az.parse_openid_config(_OIDC_OK)
    assert oc["tenant_id"] == "72f988bf-86f1-41af-91ab-2d7cd011db47"
    assert oc["tenant_region"] == "WW"
    assert az.parse_openid_config(_OIDC_ERR) == {}    # AAD error → no tenant
    assert az.parse_openid_config("{}") == {}         # no GUID → no tenant


def test_azure_tenant_finding_only_when_confirmed():
    f = az.tenant_finding("contoso.com", az.parse_userrealm(_REALM_MANAGED),
                          az.parse_openid_config(_OIDC_OK))
    assert f and f["vuln_type"] == "azure_ad_tenant_exposed"
    assert f["severity"] == "info"                    # recon, not a vuln
    assert "72f988bf" in f["title"]
    assert f["evidence"]["tenant_id"].startswith("72f988bf")
    # Nothing confirmed → no finding (never fabricated).
    assert az.tenant_finding("nope.example", {}, {}) is None


def test_azure_is_queryable_domain():
    assert az.is_queryable_domain("contoso.com")
    assert not az.is_queryable_domain("10.0.0.1")     # IP literal
    assert not az.is_queryable_domain("localhost")
    assert not az.is_queryable_domain("intranet")     # single label


def test_azure_recon_skips_non_domains_offline():
    # No queryable domains → clean empty summary, no network, never raises.
    out = asyncio.run(az.recon_azure_tenants(["127.0.0.1", "localhost", ""]))
    assert out == {"domains_checked": 0, "tenants_found": 0, "findings": []}


# ── AD anonymous-enumeration surrogate ───────────────────────────────────────

def test_ad_anonymous_enum_type_exists():
    from heaven.recon.ad_scanner import ADAttackType
    assert ADAttackType.ANON_LDAP_ENUM.value == "anonymous_ldap_enumeration"
