"""IoT / OT security-framework taxonomy + report coverage matrices.

Verifies that consumer-IoT and industrial-OT findings are scored against the
*right* standard (OWASP IoT Top 10 (2018) / IEC 62443) rather than the web
OWASP Top 10 (2021), and that the professional report renders the matching
coverage matrices without polluting the web matrix.
"""

from __future__ import annotations

from heaven.devsecops import frameworks as fw
from heaven.devsecops.compliance_report import ComplianceReportGenerator
from heaven.devsecops.vuln_kb import enrich_finding


# ── classifier ──────────────────────────────────────────────────────────────

def test_ics_protocols_map_to_iec62443_not_web_owasp():
    modbus = fw.tag_iot_ot_finding({
        "protocol": "Modbus TCP", "severity": "critical",
        "title": "Modbus TCP unauthenticated access on 10.0.0.5:502",
    })
    assert modbus["device_class"] == "ot"
    assert modbus["iec62443"].startswith("FR1")
    assert "modbus" in modbus["vuln_type"]
    assert "T0855" in modbus["mitre_technique"]  # ATT&CK for ICS, not enterprise
    assert not modbus.get("owasp_iot")


def test_s7_and_dnp3_are_ics_exposed_service():
    for proto, title in (("Siemens S7comm", "Siemens S7comm ICS service reachable"),
                         ("DNP3", "DNP3 ICS service reachable")):
        t = fw.tag_iot_ot_finding({"protocol": proto, "title": title,
                                   "severity": "high"})
        assert t["iec62443"].startswith("FR1")
        assert fw.ot_category_id(t) == "FR1"


def test_unconfirmed_ics_port_is_restricted_data_flow():
    t = fw.tag_iot_ot_finding({
        "protocol": "OPC-UA", "severity": "info",
        "title": "Port 4840 open on host (OPC-UA default port)",
        "description": "the OPC-UA handshake did not confirm the protocol",
    })
    assert t["iec62443"].startswith("FR5")
    assert fw.ot_category_id(t) == "FR5"


def test_consumer_iot_protocols_map_to_owasp_iot():
    cases = {
        "iot_default_credentials": {
            "protocol": "HTTP", "title": "Hikvision panel accepts default credentials"},
        "iot_default_snmp_community": {
            "protocol": "SNMP", "title": "SNMP default community 'public' on host"},
        "iot_cleartext_protocol": {
            "protocol": "CoAP", "title": "CoAP service exposed on host:5683"},
        "iot_exposed_mgmt_interface": {
            "protocol": "HTTP", "title": "Dahua device web panel detected on host"},
        "iot_insecure_network_service": {
            "protocol": "MQTT", "title": "MQTT broker allows anonymous access"},
    }
    for expected_vt, raw in cases.items():
        raw["severity"] = "high"
        t = fw.tag_iot_ot_finding(raw)
        assert t["vuln_type"] == expected_vt, raw
        assert t["device_class"] == "iot"
        assert t["owasp_iot"] and not t.get("iec62443")


def test_category_ids_extract_cleanly():
    iot = fw.tag_iot_ot_finding({"protocol": "MQTT", "title": "anonymous access",
                                 "severity": "high"})
    assert fw.iot_category_id(iot) == "I2"
    assert fw.ot_category_id(iot) == ""
    assert fw.has_iot_ot_tag(iot)


def test_default_credentials_is_I1():
    t = fw.tag_iot_ot_finding({"protocol": "HTTP", "severity": "critical",
                               "title": "Axis panel accepts default credentials"})
    assert fw.iot_category_id(t) == "I1"


# ── enrichment must not force a web OWASP category ────────────────────────────

def test_enrich_never_assigns_web_owasp_to_iot_ot():
    # The Modbus title contains "unauthenticated", which the keyword taxonomy
    # would otherwise bucket into A01 Broken Access Control — must be suppressed.
    modbus = fw.tag_iot_ot_finding({
        "protocol": "Modbus TCP", "severity": "critical",
        "title": "Modbus TCP unauthenticated access", "cwe": "CWE-306"})
    enriched = enrich_finding(dict(modbus))
    assert not enriched.get("owasp")  # no web A0x category
    assert enriched.get("iec62443", "").startswith("FR1")


# ── report coverage matrices ──────────────────────────────────────────────────

def _mixed_findings():
    raw = [
        {"target": "10.0.0.5", "protocol": "Modbus TCP", "severity": "critical",
         "port": 502, "title": "Modbus TCP unauthenticated access", "cwe": "CWE-306"},
        {"target": "10.0.0.6", "protocol": "MQTT", "severity": "critical",
         "port": 1883, "title": "MQTT broker allows anonymous access", "cwe": "CWE-306"},
        {"target": "cam", "protocol": "HTTP", "severity": "critical", "port": 80,
         "title": "Hikvision panel accepts default credentials", "cwe": "CWE-798"},
    ]
    iot_ot = [fw.tag_iot_ot_finding(f) for f in raw]
    web = [{"target": "app", "protocol": "HTTP", "severity": "high",
            "vuln_type": "xss", "title": "Reflected XSS", "cwe": "CWE-79",
            "owasp": "A03:2021 Injection"}]
    return iot_ot + web


def test_report_renders_all_three_matrices():
    html = ComplianceReportGenerator().generate_html_report(
        _mixed_findings(), engagement_name="Mixed")
    assert "OWASP Top 10 (2021) Coverage" in html
    assert "OWASP IoT Top 10 (2018) Coverage" in html
    assert "OT / ICS Security Coverage (IEC 62443)" in html
    # IoT + OT categories that should be present
    assert "Weak, Guessable, or Hardcoded Passwords" in html
    assert "Insecure Network Services" in html
    assert "Identification &amp; Authentication Control" in html


def test_iot_ot_matrices_hidden_for_pure_web_scan():
    web_only = [{"target": "app", "severity": "high", "vuln_type": "xss",
                 "title": "Reflected XSS", "owasp": "A03:2021 Injection"}]
    html = ComplianceReportGenerator().generate_html_report(
        web_only, engagement_name="Web")
    assert "OWASP Top 10 (2021) Coverage" in html
    assert "OWASP IoT Top 10 (2018)" not in html
    assert "OT / ICS Security Coverage" not in html


def test_web_owasp_matrix_not_polluted_by_ics_findings():
    gen = ComplianceReportGenerator()
    # Only ICS findings whose titles contain web keywords ("unauthenticated").
    ics = [fw.tag_iot_ot_finding({
        "target": "plc", "protocol": "Modbus TCP", "severity": "critical",
        "title": "Modbus TCP unauthenticated access", "cwe": "CWE-306"})]
    # Every web category must bucket to zero findings.
    for f in ics:
        assert gen._owasp_category_id(f) == ""
