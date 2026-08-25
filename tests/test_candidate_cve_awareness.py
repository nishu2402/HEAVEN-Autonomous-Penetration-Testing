"""Regression tests for the candidate-CVE awareness table on the
version-undetermined ``potential_vulnerable_service`` finding.

When a service (e.g. Bluehost's ``Server: Apache``) advertises a product but no
version, HEAVEN must NOT assert every product CVE as a confirmed Critical — it
collapses them to one honest low finding. This enhancement makes that finding
*useful*: it now names every candidate CVE with its published score, severity,
the affected-version range it REQUIRES, CWE, exploit flag, and a reference — full
awareness of what the service *might* be vulnerable to, without asserting any as
present. These tests lock in that the awareness data is produced and that it
renders in the Markdown / HTML / PDF report paths and the API/UI evidence package.
"""
import asyncio
import copy

from heaven.devsecops.evidence import package_finding
from heaven.utils.cvss import reconcile_severity
from heaven.vulnscan import cve_mapper as cm


def _potential_finding(product="Apache httpd", banner="Apache", version=""):
    host = {"host": "www.certifiedhacker.com", "ip": "162.241.216.11",
            "open_ports": [{"port": 80, "service": "http",
                            "banner": banner, "product": product, "version": version}]}
    vulns = asyncio.run(cm.map_vulnerabilities([host], nvd_client=None))
    matches = [v for v in vulns if v["vuln_type"] == "potential_vulnerable_service"]
    assert matches, "expected a potential_vulnerable_service finding"
    return matches[0]


def test_candidate_details_are_structured_and_ranked():
    """Each candidate row carries the CVE id, published CVSS, severity, the
    affected-version range it requires, CWE, exploit flag and a reference — and
    the rows are ordered richest (highest CVSS) first."""
    f = _potential_finding()
    ev = f["evidence"]
    rows = ev["candidate_details"]
    assert rows and len(rows) == ev["candidate_cve_count"]
    # ranked by CVSS descending
    scores = [r["cvss"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    # every row is fully populated
    for r in rows:
        assert r["cve"].startswith("CVE-")
        assert isinstance(r["cvss"], (int, float))
        assert r["severity"] in {"critical", "high", "medium", "low", "info"}
        assert r["affected_versions"]           # the version each CVE needs
        assert "cwe" in r and "exploit_available" in r and r["reference"]
    # the notorious version-specific Apache CVE is present as a CANDIDATE and
    # correctly names the ONLY version it applies to.
    by_id = {r["cve"]: r for r in rows}
    assert "CVE-2021-41773" in by_id
    assert by_id["CVE-2021-41773"]["affected_versions"] == "2.4.49"
    assert by_id["CVE-2021-41773"]["exploit_available"] is True


def test_finding_stays_low_and_survives_reconcile():
    """The candidate table must NOT inflate the finding: it is still low and
    stays low after severity reconciliation (nothing is asserted as present)."""
    f = _potential_finding()
    assert f["severity"] == "low"
    assert reconcile_severity(copy.deepcopy(f))["severity"] == "low"


def test_how_to_confirm_is_product_specific():
    """The finding carries a one-line, product-appropriate version-confirmation
    hint (the honest next step), with the concrete host/port filled in."""
    f = _potential_finding()
    hint = f["evidence"]["how_to_confirm"]
    assert "nmap -sV" in hint and "www.certifiedhacker.com" in hint
    # SSH gets its own banner-reading guidance rather than the Apache text
    # (product identified but version undetermined → version-less path).
    ssh = _potential_finding(product="OpenSSH", banner="", version="")
    assert "banner" in ssh["evidence"]["how_to_confirm"].lower()


def test_candidate_table_renders_in_markdown_and_hides_raw_dump():
    """to_markdown() (CLI export + report path) renders the candidate CVEs as a
    table, and does not spill the raw ``candidate_details`` list into the flat
    Observed key/value block."""
    md = package_finding(_potential_finding()).to_markdown()
    assert "Candidate CVEs (UNVERIFIED" in md
    assert "| CVE-2021-41773 |" in md and "2.4.49" in md
    assert "How to confirm the version" in md
    # the raw python list repr must never leak into the report
    assert "candidate_details" not in md
    assert "'cve':" not in md and "{'cve'" not in md


def test_candidate_table_renders_in_html_report():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    html = ComplianceReportGenerator().generate_html_report(
        [_potential_finding()], engagement_name="t")
    assert "Candidate CVEs" in html
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" in html
    assert "How to confirm the version" in html
    assert "tablewrap" in html          # wrapped for horizontal scroll safety


def test_candidate_data_reaches_api_ui_evidence_package():
    d = package_finding(_potential_finding()).to_dict()
    ed = d["evidence_data"]
    assert ed["candidate_details"][0]["cve"].startswith("CVE-")
    assert ed["how_to_confirm"]
