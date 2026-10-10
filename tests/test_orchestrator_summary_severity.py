"""The scan summary must carry the SAME canonical severity every other surface shows.

A live audit of two real targets surfaced a cross-surface drift: the orchestrator
summary (the ``-o json`` export and the live C/H/M/L/I tally) counted and emitted
the RAW detector ``severity``, while the engagement store, the ``heaven findings``
list and the report all show the CVSS-reconciled ``canonical_severity``. The same
finding therefore read, e.g., ``High`` in the scan JSON but ``Medium`` in the saved
report (and an end-of-life ``unsupported_software`` finding read Medium in the JSON
but High everywhere that loaded the DB). These tests pin that ``run()`` reconciles
every finding's severity — and the tally — to the authoritative band, in BOTH
directions, before returning the summary.
"""
from __future__ import annotations

from heaven.devsecops.vuln_kb import canonical_severity
from heaven.orchestrator import ScanOrchestrator, ScanPhase


async def _run_with_findings(findings: list[dict]) -> dict:
    orch = ScanOrchestrator()

    async def _emit() -> dict:
        return {"findings": [dict(f) for f in findings]}

    orch.add_task("emit findings", _emit, phase=ScanPhase.VULN_SCAN)
    return await orch.run()


async def test_summary_demotes_over_stated_severity_to_canonical():
    # ssh_weak_host_key_algo: the detector hands it High, but its no-CVE class
    # base sits in the Medium band — canonical_severity demotes it. The summary
    # must show Medium (not the raw High) and count it as Medium.
    raw = {"vuln_type": "ssh_weak_host_key_algo", "severity": "high",
           "predicted_cvss_score": 4.9, "cvss_model": "vector",
           "target": "host:22", "confidence": 0.97,
           "title": "SSH Server Offers Weak Host-Key Algorithms"}
    expected = canonical_severity(raw)
    assert expected == "medium", "fixture no longer drifts — pick another case"

    summary = await _run_with_findings([raw])
    assert summary["findings"], "the finding was dropped by the pipeline"
    f = summary["findings"][0]
    assert f["severity"] == expected          # reconciled, not the raw 'high'
    assert summary["high"] == 0               # tally uses the reconciled band
    assert summary["medium"] >= 1


async def test_summary_escalates_under_stated_severity_to_canonical():
    # An end-of-life component is emitted Medium by the detector, but the
    # unsupported-software class base escalates it to High — the direction the
    # raw JSON used to under-report. The summary must agree with the DB/report.
    raw = {"vuln_type": "unsupported_software", "severity": "medium",
           "target": "host", "confidence": 0.9,
           "title": "Unsupported Software: example 1.0 (end-of-life)",
           "evidence": {"product": "example", "kind": "software_component"}}
    expected = canonical_severity(raw)
    assert expected == "high", "fixture no longer drifts — pick another case"

    summary = await _run_with_findings([raw])
    assert summary["findings"], "the finding was dropped by the pipeline"
    f = summary["findings"][0]
    assert f["severity"] == expected          # escalated to High, not raw Medium
    assert summary["high"] >= 1


async def test_summary_severity_equals_canonical_for_every_finding():
    # The invariant, stated directly: no finding in the returned summary may show
    # a severity that disagrees with its own canonical_severity.
    raws = [
        {"vuln_type": "ssh_weak_host_key_algo", "severity": "high",
         "predicted_cvss_score": 4.9, "cvss_model": "vector",
         "target": "h:22", "confidence": 0.97, "title": "weak host key"},
        {"vuln_type": "dmarc_missing", "severity": "high",
         "predicted_cvss_score": 6.1, "cvss_model": "vector",
         "target": "example.com", "confidence": 0.99, "title": "DMARC Record Missing"},
        {"vuln_type": "soa_admin_email", "severity": "info",
         "predicted_cvss_score": 3.9, "cvss_model": "vector",
         "target": "example.com", "confidence": 0.95, "title": "DNS Zone Admin Email"},
    ]
    summary = await _run_with_findings(raws)
    for f in summary["findings"]:
        assert f["severity"] == canonical_severity(f), (
            f"{f.get('vuln_type')} shows {f['severity']} but canonical is "
            f"{canonical_severity(f)}")


async def test_summary_cvss_base_matches_the_reconciled_band():
    # The summary feeds the report JSON and the aggregator SARIF/HTML directly,
    # all of which read the CVSS number via objective_base_score. So the base must
    # be reconciled too, not just the label: an unconfirmed indicator capped to Low
    # must not keep its raw class base of 7.5 (which the CVSS column would show
    # beside a Low badge, and a SARIF security-severity GitHub re-buckets as High).
    from heaven.utils.cvss import objective_base_score, severity_from_score
    raw = {"vuln_type": "potential_vulnerable_service", "severity": "low",
           "confidence": 0.3, "target": "http://h/x",
           "title": "Potential Vulnerable Service (nginx)",
           "evidence": {"product": "nginx"}}
    # Pre-reconciliation the class base is High — that is the drift being pinned.
    assert severity_from_score(objective_base_score(raw)) == "high"

    summary = await _run_with_findings([raw])
    f = summary["findings"][0]
    assert f["severity"] == "low"
    base = objective_base_score(f)
    assert base <= 3.9, f"summary base {base} escapes the Low band"
    assert severity_from_score(base) == "low"
