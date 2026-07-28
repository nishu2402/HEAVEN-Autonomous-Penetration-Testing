"""Regression guard: a CVE finding's CVSS is genuinely per-finding end-to-end.

Root cause this locks down: ``upsert_finding`` never persisted the real
per-CVE base score (the findings table has no cvss column), so after the DB
round-trip the report resolver fell back to the ``vulnerable_component`` class
"typical" constant and EVERY CVE — regardless of its true score — rendered as a
flat 7.5. Two OpenSSH/Apache/Dovecot CVEs with published scores of 9.8, 8.1 and
5.9 must show those three numbers, and their severity band must follow the
score (a curated "critical/8.1" is corrected to the high band).
"""
from __future__ import annotations

import asyncio

from heaven.devsecops.compliance_report import ComplianceReportGenerator
from heaven.devsecops.vuln_kb import enrich_finding
from heaven.engagement import EngagementStore
from heaven.utils.cvss import objective_base_score, severity_from_score
from heaven.vulnscan.cve_mapper import _score_and_severity, map_vulnerabilities


def test_score_and_severity_derives_band_from_score():
    # A curated "critical/8.1" (regreSSHion) is corrected to the high band so the
    # report never shows an inconsistent "Critical / 8.1" row.
    score, sev = _score_and_severity(8.1, "critical")
    assert score == 8.1
    assert sev == severity_from_score(8.1) == "high"
    # A genuine 9.8 stays critical; a 5.9 stays medium.
    assert _score_and_severity(9.8, "high") == (9.8, "critical")
    assert _score_and_severity(5.9, "critical") == (5.9, "medium")
    # No usable score → keep the caller's curated severity, base score 0.0.
    assert _score_and_severity(0.0, "high") == (0.0, "high")
    assert _score_and_severity(None, "medium") == (0.0, "medium")


def test_cve_findings_carry_real_per_cve_cvss_base():
    host_results = [{
        "host": "example.test",
        "open_ports": [
            {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6",
             "version": "9.6"},
            {"port": 80, "service": "http", "banner": "Apache/2.4.49",
             "version": "2.4.49"},
        ],
    }]
    findings = asyncio.run(map_vulnerabilities(host_results))
    by_cve = {f["cve"]: f for f in findings}

    # regreSSHion: real NVD score 8.1, band corrected critical→high.
    reg = by_cve["CVE-2024-6387"]
    assert reg["cvss_base"] == 8.1
    assert reg["severity"] == "high"

    # Apache path-traversal RCE: real 9.8, stays critical.
    apache = by_cve["CVE-2021-41773"]
    assert apache["cvss_base"] == 9.8
    assert apache["severity"] == "critical"

    # The two do NOT share one flat number — the collapse is gone.
    assert reg["cvss_base"] != apache["cvss_base"]


def test_real_cvss_survives_db_round_trip_and_report(tmp_path):
    db = tmp_path / "eng.db"
    store = EngagementStore(db)
    store.record_scan_start("s1", name="t")

    # Two different CVE classes with distinct published scores.
    raw = [
        {"host": "h", "port": 22, "target": "h:22", "vuln_type": "vulnerable_service",
         "cve": "CVE-2024-6387", "title": "regreSSHion", "severity": "high",
         "cvss": 8.1, "cvss_base": 8.1, "confidence": 0.9},
        {"host": "h", "port": 110, "target": "h:110", "vuln_type": "vulnerable_service",
         "cve": "CVE-2021-33515", "title": "Dovecot STARTTLS injection",
         "severity": "medium", "cvss": 5.9, "cvss_base": 5.9, "confidence": 0.9},
    ]
    for f in raw:
        store.upsert_finding("s1", f)

    rows = {r.cve_id: r for r in store.list_findings(limit=50)}
    # The real base score survived persistence (stashed in evidence, since the
    # findings table has no cvss column).
    assert rows["CVE-2024-6387"].evidence.get("cvss_base") == 8.1
    assert rows["CVE-2021-33515"].evidence.get("cvss_base") == 5.9

    # The report resolver shows each finding's real score — not a flat constant.
    gen = ComplianceReportGenerator()
    shown = {}
    for cve, r in rows.items():
        d = enrich_finding({
            "target": r.target, "vuln_type": r.vuln_type, "title": r.title,
            "severity": r.severity, "cve_id": r.cve_id, "risk_score": r.risk_score,
            "predicted_cvss_score": r.risk_score, "evidence": r.evidence,
        })
        shown[cve] = gen._finding_cvss(d)
    assert shown["CVE-2024-6387"] == "8.1"
    assert shown["CVE-2021-33515"] == "5.9"
    assert shown["CVE-2024-6387"] != shown["CVE-2021-33515"]

    # objective_base_score reads the persisted evidence.cvss_base directly too.
    assert objective_base_score({"vuln_type": "vulnerable_service",
                                 "evidence": {"cvss_base": 5.9}}) == 5.9


def test_contextual_score_is_dynamic_within_a_class():
    # Two findings of the SAME class differ in their contextual score when their
    # per-finding evidence (here: detection confidence) differs — the base score
    # alone would collapse them onto one number.
    from heaven.utils.cvss import contextual_score, objective_base_score
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    hi = {"vuln_type": "reflected_xss", "cvss_vector": vec, "confidence": 0.95}
    lo = {"vuln_type": "reflected_xss", "cvss_vector": vec, "confidence": 0.55}
    base = objective_base_score(hi)
    assert contextual_score(hi) != contextual_score(lo)
    # Both stay within the CVSS range and never exceed the (medium-criticality) base.
    for f in (hi, lo):
        s = contextual_score(f)
        assert 0.0 < s <= 10.0
        assert s <= base


def test_contextual_score_reflects_exploit_maturity():
    # Exploit Code Maturity is a real per-finding signal: a high EPSS / a public
    # exploit / a CISA-KEV listing pushes the contextual score up toward the base.
    from heaven.utils.cvss import contextual_score
    cve = {"vuln_type": "vulnerable_service", "cve": "CVE-2024-6387", "cvss_base": 8.1,
           "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "confidence": 0.9}
    hot = dict(cve, epss=0.85)
    cold = dict(cve, epss=0.01)
    assert contextual_score(hot) > contextual_score(cold)
    # A KEV listing is treated as actively-exploited (E=High), at least as urgent
    # as a merely-high EPSS.
    kev = dict(cve, in_kev=True)
    assert contextual_score(kev) >= contextual_score(hot)


def test_contextual_score_reflects_asset_criticality():
    # The Environmental group makes the same finding score higher on a crown-jewel
    # asset than on a low-value one — genuinely per-asset, standards-based.
    from heaven.utils.cvss import contextual_score
    f = {"vuln_type": "reflected_xss",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "confidence": 0.9}
    low = contextual_score(f, criticality="low")
    med = contextual_score(f, criticality="medium")
    crown = contextual_score(f, criticality="crown_jewel")
    assert low < med < crown
    assert all(0.0 < s <= 10.0 for s in (low, med, crown))


def test_contextual_degrades_to_base_without_signals():
    # A finding carrying NO temporal/environmental signals must return exactly its
    # base score — never a fabricated jitter.
    from heaven.utils.cvss import contextual_score, objective_base_score
    f = {"vuln_type": "missing_security_headers"}
    assert contextual_score(f) == objective_base_score(f) > 0


def test_report_renders_both_base_and_contextual_columns():
    # The professional report shows BOTH the class base score and the per-finding
    # contextual score, and for a CVE with exploit signals they are not identical.
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    f = {"target": "h:22", "vuln_type": "vulnerable_service", "title": "regreSSHion",
         "severity": "high", "cve_id": "CVE-2024-6387", "cvss_base": 8.1,
         "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "confidence": 0.9, "evidence": {"epss": 0.6}}
    base = gen._finding_cvss(f)
    ctx = gen._finding_contextual_cvss(f)
    assert base == "8.1"
    assert ctx not in ("—", base)  # genuinely adjusted, still a real number
    html = gen.generate_html_report([f], engagement_name="t")
    assert ">Contextual</th>" in html  # the second column header is present


def test_inline_db_records_have_consistent_score_and_severity():
    # Every inline CVE record, when normalised, has a severity band that matches
    # its objective CVSS score — no more "critical" labels on high-band scores.
    from heaven.vulnscan.cve_mapper import INLINE_CVE_DB
    mismatches = []
    for _product, records in INLINE_CVE_DB.items():
        for rec in records:
            # NB: no isinstance(rec, CVERecord) check — another test in the suite
            # nukes sys.modules['heaven*'] and re-imports, so the DB's records can
            # be instances of a different CVERecord class object than the one this
            # module imported. Duck-type on the attributes instead.
            score, sev = _score_and_severity(rec.cvss, rec.severity)
            if score and sev != severity_from_score(score):
                mismatches.append((rec.cve_id, score, sev))
    assert not mismatches, mismatches
