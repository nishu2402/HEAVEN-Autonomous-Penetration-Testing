"""Tests for pass-4 features: FP suppression integration, Burp export, scan resume."""
from __future__ import annotations

import asyncio
import base64

import pytest


# ── Burp Suite XML export ──────────────────────────────────────────────

class TestBurpExport:

    def test_xml_is_well_formed(self):
        from heaven.devsecops.burp_export import export_burp_xml
        import xml.etree.ElementTree as ET
        findings = [{
            "id": "abc123", "target": "https://app.example/login",
            "vuln_type": "sqli", "severity": "critical", "confidence": 0.94,
            "method": "POST", "param": "username",
            "evidence": {
                "payload": "' OR 1=1--",
                "status": 200,
                "response_body": "Welcome",
                "request_headers": {"Cookie": "session=abc"},
            },
        }]
        xml = export_burp_xml(findings)
        # Should parse cleanly as XML
        root = ET.fromstring(xml)
        assert root.tag == "items"
        items = root.findall("item")
        assert len(items) == 1
        item = items[0]
        # Check core fields
        assert item.find("url").text == "https://app.example/login"
        assert item.find("host").text == "app.example"
        assert item.find("port").text == "443"
        assert item.find("protocol").text == "https"
        # Method is in CDATA
        assert "POST" in (item.find("method").text or "")

    def test_request_is_base64_encoded(self):
        from heaven.devsecops.burp_export import export_burp_xml
        import xml.etree.ElementTree as ET
        findings = [{
            "id": "abc", "target": "http://api.test/users",
            "vuln_type": "xss", "severity": "high",
            "method": "GET", "param": "q",
            "evidence": {"payload": "<svg onload=alert(1)>", "status": 200,
                          "response_body": "OK"},
        }]
        xml = export_burp_xml(findings)
        root = ET.fromstring(xml)
        request_b64 = root.find(".//request").text.strip()
        decoded = base64.b64decode(request_b64).decode()
        # Raw HTTP/1.1 request should contain method, path, host
        assert decoded.startswith("GET ")
        assert "Host: api.test" in decoded
        # Payload was URL-encoded into the request line
        assert "q=" in decoded

    def test_post_payload_in_body_not_url(self):
        from heaven.devsecops.burp_export import export_burp_xml
        import xml.etree.ElementTree as ET
        findings = [{
            "id": "x", "target": "https://x.test/login",
            "vuln_type": "sqli", "severity": "critical",
            "method": "POST", "param": "username",
            "evidence": {"payload": "admin'--", "status": 500, "response_body": ""},
        }]
        xml = export_burp_xml(findings)
        root = ET.fromstring(xml)
        request = base64.b64decode(root.find(".//request").text.strip()).decode()
        # Method line should NOT include the payload
        first_line = request.split("\r\n")[0]
        assert "username=" not in first_line
        # Body (after blank line) should
        body_section = request.split("\r\n\r\n", 1)[1]
        assert "username=" in body_section

    def test_skips_findings_without_url(self):
        """Findings on raw IPs without scheme can't be Burp-imported."""
        from heaven.devsecops.burp_export import export_burp_xml
        import xml.etree.ElementTree as ET
        findings = [
            {"id": "1", "target": "10.0.0.5", "vuln_type": "open_port",
             "severity": "info", "evidence": {}},
            {"id": "2", "target": "https://x.test/", "vuln_type": "xss",
             "severity": "high", "method": "GET", "evidence": {"status": 200}},
        ]
        xml = export_burp_xml(findings)
        root = ET.fromstring(xml)
        # Only one item (the URL one)
        assert len(root.findall("item")) == 1

    def test_proxy_jsonl_format(self):
        from heaven.devsecops.burp_export import export_proxy_history_jsonl
        import json as _json
        findings = [{
            "id": "x", "target": "https://x.test/", "vuln_type": "sqli",
            "severity": "critical", "confidence": 0.9,
            "method": "GET", "param": "id",
            "evidence": {"payload": "' OR 1=1--", "status": 500,
                          "response_body": "SQL syntax error"},
        }]
        jsonl = export_proxy_history_jsonl(findings)
        # Each line is valid JSON
        lines = [l for l in jsonl.splitlines() if l]
        assert len(lines) == 1
        rec = _json.loads(lines[0])
        assert rec["finding_id"] == "x"
        assert rec["request"]["method"] == "GET"
        assert rec["response"]["status"] == 500


# ── Scan resume / checkpointing ────────────────────────────────────────

class TestScanResume:

    def test_checkpoint_persistence(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "resume.db")
        store.record_scan_start("scan-A", name="test")
        store.checkpoint_task("scan-A", "task-1", "Network Recon", "completed",
                               result={"hosts_up": 5})
        store.checkpoint_task("scan-A", "task-2", "Web Crawl", "failed",
                               result={"error": "timeout"})

        cps = store.load_checkpoints("scan-A")
        assert len(cps) == 2
        assert cps["task-1"]["state"] == "completed"
        # Result is whatever was passed in (no wrapping by this method)
        assert cps["task-1"]["result"]["hosts_up"] == 5
        assert cps["task-2"]["state"] == "failed"
        assert cps["task-2"]["result"]["error"] == "timeout"

    def test_find_resumable_returns_unfinished(self, tmp_path):
        from heaven.engagement import EngagementStore
        store = EngagementStore(tmp_path / "resume.db")
        store.record_scan_start("scan-running", name="r", mode="full",
                                 config={"targets": {"urls": ["https://a"]}})
        store.record_scan_start("scan-done", name="d", mode="full",
                                 config={"targets": {"urls": ["https://b"]}})
        store.record_scan_complete("scan-done", {"summary": "ok"})
        unfinished = store.find_resumable_scans()
        assert len(unfinished) == 1
        assert unfinished[0]["id"] == "scan-running"

    def test_orchestrator_skips_resumed_completed_task(self, tmp_path):
        """If a task is checkpointed as completed, orchestrator skips it on resume."""
        from heaven.engagement import EngagementStore
        from heaven.orchestrator import ScanOrchestrator, ScanPhase

        store = EngagementStore(tmp_path / "resume.db")
        scan_id = "test-resume-1"
        store.record_scan_start(scan_id, name="test")

        # Task A "ran" before the crash
        store.checkpoint_task(scan_id, "task_A", "Task A", "completed",
                               result={"data": {"value": 42}, "duration_ms": 100})

        orch = ScanOrchestrator(checkpoint_store=store, resume_scan_id=scan_id)

        ran_again = []

        async def task_A_factory():
            ran_again.append("A")
            return {"value": 999}

        async def task_B_factory():
            return {"value": 7}

        orch.add_task("Task A", task_A_factory, phase=ScanPhase.RECON)
        # Override generated id to match checkpoint
        a_task = list(orch.tasks.values())[0]
        del orch.tasks[a_task.id]
        a_task.id = "task_A"
        orch.tasks["task_A"] = a_task
        orch._task_done_events["task_A"] = asyncio.Event()

        orch.add_task("Task B", task_B_factory, phase=ScanPhase.RECON)

        async def go():
            await orch.run()

        asyncio.run(go())

        # Task A should not have re-run
        assert "A" not in ran_again, "task A re-executed despite being checkpointed completed"
        # Result for A should be the checkpointed one
        a_result = orch.results["task_A"]
        assert a_result.state.value == "completed"


# ── FP suppression wired into validator ────────────────────────────────

class TestFPSuppressionIntegration:

    @pytest.mark.asyncio
    async def test_validator_calls_fp_suppressor(self, monkeypatch):
        """Ensure validate_all_findings calls suppress_finding for confirmed findings."""
        import heaven.vulnscan.fp_suppress as fp_mod
        called = []

        original_suppress = fp_mod.suppress_finding

        async def mock_suppress(session, finding):
            called.append(finding["vuln_type"])
            return fp_mod.SuppressionVerdict(
                keep=True, final_confidence=0.85, bucket="high",
                reasons=["mock_test_reason"],
            )

        monkeypatch.setattr(fp_mod, "suppress_finding", mock_suppress)

        # Patch validate_sqli to return a confirmed finding without network IO
        from heaven.vulnscan import safe_validator
        from heaven.vulnscan.safe_validator import ValidationResult

        async def fake_validate_sqli(session, url, param, method="GET", timeout=10.0):
            return ValidationResult(
                vuln_type="sqli", target_url=url, param=param, method=method,
                result="confirmed", confidence=0.92,
                evidence={"technique": "boolean_inference", "length_diff": 500},
            )

        monkeypatch.setattr(safe_validator, "validate_sqli", fake_validate_sqli)

        # Stub aiohttp
        try:
            import aiohttp
        except ImportError:
            pytest.skip("aiohttp not available")

        async with aiohttp.ClientSession() as session:
            findings = [{"type": "sqli", "target": "https://x.test",
                         "param": "id", "method": "GET"}]
            result = await safe_validator.validate_findings(findings=findings)

        # The suppressor should have been called for the confirmed sqli
        assert "sqli" in called, f"FP suppressor never called: {called}"

        # The validated finding should now carry confidence_bucket etc.
        validated = result.get("validated_findings", [])
        assert len(validated) == 1
        assert "confidence_bucket" in validated[0]
        assert validated[0]["confidence_bucket"] == "high"
        assert "fp_check_reasons" in validated[0]


# ── Export integration via CLI module ──────────────────────────────────

def test_burp_export_via_cli_module(tmp_path):
    """End-to-end: store finding → export burp → parse XML → verify content."""
    import xml.etree.ElementTree as ET
    from heaven.engagement import EngagementStore
    from heaven.devsecops.burp_export import export_burp_xml

    store = EngagementStore(tmp_path / "engage.db")
    store.create_engagement("burp-test")
    store.upsert_finding("scan-1", {
        "target": "https://target.example/api/users",
        "vuln_type": "sqli", "severity": "critical", "confidence": 0.94,
        "method": "POST", "param": "id", "title": "SQLi in /api/users",
        "evidence": {"payload": "1' OR '1'='1", "technique": "error_based",
                     "status": 500, "response_body": "MySQL error"},
    })

    findings = [{
        "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
        "title": f.title, "severity": f.severity, "confidence": f.confidence,
        "evidence": f.evidence,
    } for f in store.list_findings()]

    xml = export_burp_xml(findings)
    root = ET.fromstring(xml)
    assert len(root.findall("item")) == 1
    item = root.findall("item")[0]
    comment = item.find("comment").text
    assert "sqli" in comment
    assert "critical" in comment
