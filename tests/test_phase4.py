import json


def test_compliance_report_owasp():
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    findings = [
        {"vuln_type": "sqli", "severity": "critical", "target": "10.0.0.1",
         "title": "SQL Injection", "confidence": 0.95, "risk_score": 9.1},
        {"vuln_type": "xss", "severity": "high", "target": "10.0.0.2",
         "title": "Reflected XSS", "confidence": 0.87, "risk_score": 6.5},
    ]
    gen = ComplianceReportGenerator()
    html = gen.generate_html_report(findings, engagement_name="test")
    assert "A03:2021" in html
    assert "SQL Injection" in html
    assert "CRITICAL" in html
    assert len(html) > 1000


def test_engagement_store_pause(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(tmp_path / "test.db")
    store.create_engagement("test_eng")
    store.record_scan_start("scan-001", name="test scan", mode="full", config={})
    result = store.pause_scan("scan-001")
    assert result is True
    state = store.get_scan_state("scan-001")
    assert state["status"] == "paused"


def test_nvd_pipeline_parse(tmp_path):
    from heaven.ml.nvd_pipeline import NVDPipeline
    fixture = {"cve": {
        "published": "2023-01-01T00:00:00.000",
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 8.5,
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "NONE",
        }}]}
    }}
    jsonl = tmp_path / "test.jsonl"
    jsonl.write_text(json.dumps(fixture) + "\n")
    pipeline = NVDPipeline()
    X, y, features = pipeline.parse_dataset(jsonl)
    assert len(y) == 1
    assert abs(y[0] - 8.5) < 0.01
    assert X.shape[1] == len(features)
