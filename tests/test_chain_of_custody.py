"""Evidence integrity / chain-of-custody tests.

Covers the SHA-256 proof digest, stamping (idempotent + batch), tamper
detection, the manifest, and the end-to-end surfacing of the integrity record
through the evidence packager and the Markdown report.
"""

from __future__ import annotations

from heaven.devsecops import chain_of_custody as coc


def _finding() -> dict:
    return {
        "id": "f1",
        "target": "https://app.example.com/login",
        "vuln_type": "sql_injection",
        "severity": "high",
        "confidence": 0.9,
        "cve_id": "",
        "cwe": "CWE-89",
        "evidence": {
            "technique": "error_based_sqli",
            "method": "POST",
            "request_url": "https://app.example.com/login",
            "payload": "' OR '1'='1",
            "status": 200,
            "response_body": "SQL syntax error near ''1''",
        },
    }


def test_digest_is_deterministic_and_content_sensitive():
    f1 = _finding()
    f2 = _finding()
    assert coc.evidence_digest(f1) == coc.evidence_digest(f2)
    # Changing the proof changes the digest.
    f2["evidence"]["payload"] = "' OR '2'='2"
    assert coc.evidence_digest(f1) != coc.evidence_digest(f2)
    # Digest is a full-length sha256 hex string.
    assert len(coc.evidence_digest(f1)) == 64
    int(coc.evidence_digest(f1), 16)  # parses as hex


def test_stamp_is_idempotent_and_forceable():
    f = _finding()
    assert coc.stamp_finding(f) is True
    rec = coc.get_record(f)
    assert rec["algorithm"] == "sha256"
    assert rec["tool"] == "HEAVEN"
    assert rec["sha256"] == coc.evidence_digest(f)
    assert rec["collection_method"] == "error_based_sqli"
    # Second stamp is a no-op (record already present).
    assert coc.stamp_finding(f) is False
    # force=True re-stamps.
    assert coc.stamp_finding(f, force=True) is True


def test_digest_excludes_its_own_record():
    """Stamping must not change the digest it stored (it hashes proof, not stamp)."""
    f = _finding()
    pre = coc.evidence_digest(f)
    coc.stamp_finding(f)
    post = coc.evidence_digest(f)
    assert pre == post
    assert coc.verify_finding_integrity(f) is True


def test_verify_detects_tampering():
    f = _finding()
    coc.stamp_finding(f)
    assert coc.verify_finding_integrity(f) is True
    # Alter the proof after collection → integrity check fails.
    f["evidence"]["response_body"] = "edited after the fact"
    assert coc.verify_finding_integrity(f) is False


def test_verify_none_when_unstamped():
    assert coc.verify_finding_integrity(_finding()) is None


def test_stamp_all_shares_one_collection_time():
    findings = [_finding(), _finding(), _finding()]
    findings[1]["evidence"]["payload"] = "x"
    findings[2]["evidence"]["payload"] = "y"
    n = coc.stamp_all(findings)
    assert n == 3
    times = {coc.get_record(f)["collected_at"] for f in findings}
    assert len(times) == 1  # one shared collection time for the run
    # Each keeps its own content digest.
    digests = {coc.get_record(f)["sha256"] for f in findings}
    assert len(digests) == 3


def test_collection_method_precedence():
    # active_verification technique used when no top-level technique.
    f = {"evidence": {"active_verification": {"technique": "shellshock_env_injection"}}}
    assert coc.collection_method(f) == "active_verification:shellshock_env_injection"
    # source used when no technique at all.
    f = {"source": "nuclei", "evidence": {}}
    assert coc.collection_method(f) == "nuclei"
    # generic fallback.
    assert coc.collection_method({"evidence": {}}) == "heaven-scan"


def test_manifest_complete_even_when_unstamped():
    findings = [_finding(), _finding()]
    rows = coc.manifest(findings)
    assert len(rows) == 2
    for r in rows:
        assert len(r["sha256"]) == 64
        assert r["collection_method"]


def test_render_manifest_markdown_has_digests():
    findings = [_finding()]
    coc.stamp_all(findings)
    md = coc.render_manifest_markdown(findings)
    assert "Evidence integrity manifest" in md
    assert "SHA-256" in md
    # Short digest appears in the table.
    short = coc.get_record(findings[0])["sha256"][:16]
    assert short in md


def test_render_manifest_markdown_empty_for_no_findings():
    assert coc.render_manifest_markdown([]) == ""


def test_packager_surfaces_integrity_line():
    from heaven.devsecops.evidence import package_finding
    f = _finding()
    coc.stamp_all(f and [f])
    pkg = package_finding(f)
    assert pkg.evidence_sha256 == coc.get_record(f)["sha256"]
    assert pkg.collection_method == "error_based_sqli"
    md = pkg.to_markdown()
    assert "Evidence SHA-256" in md


def test_packager_computes_digest_when_unstamped():
    from heaven.devsecops.evidence import package_finding
    f = _finding()  # no chain_of_custody record
    pkg = package_finding(f)
    assert len(pkg.evidence_sha256) == 64
    assert pkg.evidence_sha256 == coc.evidence_digest(f)


def test_markdown_report_includes_manifest():
    from heaven.devsecops.evidence import export_findings_markdown
    findings = [_finding()]
    coc.stamp_all(findings)
    report = export_findings_markdown(findings, engagement_name="Acme")
    assert "Evidence integrity manifest" in report
