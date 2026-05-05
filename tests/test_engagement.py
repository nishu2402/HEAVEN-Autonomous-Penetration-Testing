"""Tests for engagement workflow: scope, dedup, status, evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


@pytest.fixture
def store(tmp_path):
    from heaven.engagement import EngagementStore
    return EngagementStore(tmp_path / "test_engagement.db")


# ── Engagement metadata ────────────────────────────────────────────────

class TestEngagementMetadata:

    def test_create_engagement(self, store):
        eng = store.create_engagement("acme-2026-q2", client="ACME Corp",
                                       statement_of_work="SOW-001")
        assert eng.name == "acme-2026-q2"
        assert eng.client == "ACME Corp"
        assert eng.created_at

    def test_create_idempotent(self, store):
        store.create_engagement("dup", client="A")
        second = store.create_engagement("dup", client="B")  # should not overwrite
        eng = store.get_engagement()
        assert eng.client == "A"   # original wins, no overwrite
        assert second.name == "dup"

    def test_get_engagement_when_empty(self, store):
        assert store.get_engagement() is None


# ── Scope management ───────────────────────────────────────────────────

class TestScope:

    def test_add_and_list(self, store):
        store.add_scope("10.0.0.1", kind="ip")
        store.add_scope("example.com", kind="host")
        entries = store.list_scope()
        assert len(entries) == 2
        assert {e.target for e in entries} == {"10.0.0.1", "example.com"}

    def test_is_in_scope(self, store):
        store.add_scope("10.0.0.1")
        assert store.is_in_scope("10.0.0.1")
        assert not store.is_in_scope("10.0.0.99")

    def test_out_of_scope_target_rejected(self, store):
        store.add_scope("10.0.0.1", in_scope=False)
        assert not store.is_in_scope("10.0.0.1")
        # By default, list_scope hides out-of-scope entries
        assert not store.list_scope()
        assert len(store.list_scope(in_scope_only=False)) == 1

    def test_remove_scope(self, store):
        store.add_scope("temp.example")
        assert store.remove_scope("temp.example")
        assert not store.is_in_scope("temp.example")
        assert not store.remove_scope("never-existed")

    def test_import_scope_file(self, store, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text(
            "# Engagement scope - ACME Q2\n"
            "10.0.0.0/24\n"
            "https://api.acme.example\n"
            "intranet.acme.example\n"
            "\n"
            "# explicitly excluded:\n"
            "  10.0.0.5\n"
        )
        n = store.import_scope_file(scope_file)
        assert n == 4
        assert store.is_in_scope("10.0.0.0/24")
        assert store.is_in_scope("https://api.acme.example")
        # Kind detection
        scope = {e.target: e.kind for e in store.list_scope()}
        assert scope["https://api.acme.example"] == "url"
        assert scope["10.0.0.0/24"] == "cidr"


# ── Findings dedup ─────────────────────────────────────────────────────

class TestFindingDedup:

    def test_same_finding_dedups(self, store):
        finding = {
            "target": "https://app.example",
            "vuln_type": "sqli",
            "param": "id", "endpoint": "/login",
            "severity": "critical", "confidence": 0.92,
        }
        id1 = store.upsert_finding("scan-1", finding)
        id2 = store.upsert_finding("scan-2", finding)
        assert id1 == id2
        f = store.get_finding(id1)
        assert f.seen_count == 2
        # Latest scan_id wins
        assert f.scan_id == "scan-2"

    def test_different_param_dedups_separately(self, store):
        f1 = {"target": "x", "vuln_type": "sqli", "param": "id",
              "severity": "high", "confidence": 0.8}
        f2 = {"target": "x", "vuln_type": "sqli", "param": "search",
              "severity": "high", "confidence": 0.8}
        id1 = store.upsert_finding("s1", f1)
        id2 = store.upsert_finding("s1", f2)
        assert id1 != id2

    def test_dedup_preserves_operator_status(self, store):
        finding = {"target": "x", "vuln_type": "sqli", "param": "id",
                   "severity": "high", "confidence": 0.8}
        fid = store.upsert_finding("s1", finding)
        # Operator marks as false positive
        store.update_finding_status(fid, "false_positive", notes="not exploitable")
        # Re-scan finds it again
        store.upsert_finding("s2", finding)
        f = store.get_finding(fid)
        # Status & notes preserved across re-scan
        assert f.status == "false_positive"
        assert f.operator_notes == "not exploitable"


# ── Status workflow ────────────────────────────────────────────────────

class TestFindingStatus:

    def test_invalid_status_rejected(self, store):
        finding = {"target": "x", "vuln_type": "sqli", "severity": "high"}
        fid = store.upsert_finding("s1", finding)
        with pytest.raises(ValueError):
            store.update_finding_status(fid, "exploitable")  # not a valid status

    def test_valid_status_transitions(self, store):
        finding = {"target": "x", "vuln_type": "xss", "severity": "high"}
        fid = store.upsert_finding("s1", finding)
        for status in ("verified", "false_positive", "accepted_risk", "fixed", "open"):
            assert store.update_finding_status(fid, status, notes=f"set to {status}")
            assert store.get_finding(fid).status == status

    def test_update_nonexistent_returns_false(self, store):
        assert not store.update_finding_status("does-not-exist", "verified")


# ── Filtering / search ─────────────────────────────────────────────────

class TestFindingFilters:

    @pytest.fixture
    def populated_store(self, store):
        findings = [
            {"target": "host1", "vuln_type": "sqli", "param": "id",
             "severity": "critical", "confidence": 0.95},
            {"target": "host1", "vuln_type": "xss", "param": "q",
             "severity": "high", "confidence": 0.88},
            {"target": "host2", "vuln_type": "sqli", "param": "user",
             "severity": "medium", "confidence": 0.65},
            {"target": "host3", "vuln_type": "ssrf", "param": "url",
             "severity": "low", "confidence": 0.45},
            {"target": "host3", "vuln_type": "ssrf", "param": "callback",
             "severity": "info", "confidence": 0.35},
        ]
        for f in findings:
            store.upsert_finding("scan-1", f)
        return store

    def test_severity_filter(self, populated_store):
        criticals = populated_store.list_findings(severity="critical")
        assert len(criticals) == 1
        assert criticals[0].vuln_type == "sqli"

    def test_target_filter(self, populated_store):
        host3 = populated_store.list_findings(target="host3")
        assert len(host3) == 2
        assert all(f.target == "host3" for f in host3)

    def test_min_confidence_filter(self, populated_store):
        # Only critical (.95) and high (.88) pass 0.85 threshold
        high_conf = populated_store.list_findings(min_confidence=0.85)
        assert len(high_conf) == 2

    def test_results_sorted_by_severity_then_confidence(self, populated_store):
        results = populated_store.list_findings()
        sevs = [f.severity for f in results]
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [sev_rank[s] for s in sevs]
        assert ranks == sorted(ranks), "results not severity-sorted"

    def test_status_filter(self, populated_store):
        # Mark one as verified
        first = populated_store.list_findings()[0]
        populated_store.update_finding_status(first.id, "verified")
        verified = populated_store.list_findings(status="verified")
        assert len(verified) == 1
        assert verified[0].id == first.id

    def test_stats(self, populated_store):
        stats = populated_store.stats()
        assert stats["total_findings"] == 5
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_status"]["open"] == 5


# ── Evidence package ───────────────────────────────────────────────────

class TestEvidencePackage:

    def test_package_finding_basic(self):
        from heaven.devsecops.evidence import package_finding
        finding = {
            "id": "abc123",
            "target": "https://app.example/api/login",
            "vuln_type": "sqli",
            "severity": "critical",
            "confidence": 0.92,
            "method": "POST",
            "param": "username",
            "evidence": {
                "technique": "boolean_inference",
                "payload": "' OR 1=1--",
                "status": 200,
                "response_body": "Welcome admin!",
            },
        }
        pkg = package_finding(finding)
        assert pkg.vuln_type == "sqli"
        assert pkg.confidence == 0.92
        assert pkg.payload == "' OR 1=1--"
        assert "curl" in pkg.curl_command
        # Curl must shell-escape the payload
        assert "'" in pkg.curl_command

    def test_curl_handles_shell_metas_safely(self):
        from heaven.devsecops.evidence import build_curl
        cmd = build_curl(
            method="POST", url="https://x/api",
            headers={"Content-Type": "application/json"},
            body='{"q": "SELECT * FROM users WHERE id=\'1\' OR 1=1; --"}',
        )
        # Should be safe to paste — no unquoted shell execution
        # Body is wrapped in single quotes via shlex.quote
        assert "--data" in cmd
        # The dangerous chars (;, ', ") should all be inside the quoted string
        # not be exposed as shell tokens
        import shlex
        # If shlex parses without error, the cmd is safe to paste
        try:
            tokens = shlex.split(cmd)
            assert "curl" in tokens
        except ValueError as e:
            pytest.fail(f"curl command not safely shell-escaped: {e}")

    def test_markdown_render_includes_proof(self):
        from heaven.devsecops.evidence import package_finding
        finding = {
            "target": "x",
            "vuln_type": "xss",
            "severity": "high",
            "confidence": 0.85,
            "evidence": {
                "technique": "html_tag",
                "payload": "<script>alert(1)</script>",
                "status": 200,
                "response_body": "<html>...<script>alert(1)</script>...</html>",
            },
        }
        md = package_finding(finding).to_markdown()
        assert "XSS" in md
        assert "Proof of issue" in md
        assert "Reproduce with curl" in md

    def test_response_excerpt_truncated(self):
        from heaven.devsecops.evidence import package_finding
        finding = {
            "target": "x", "vuln_type": "info_disclosure",
            "severity": "low", "confidence": 0.7,
            "evidence": {"response_body": "A" * 10000},
        }
        pkg = package_finding(finding)
        # 4000 char cap on excerpts
        assert len(pkg.response_excerpt) <= 4100  # 4000 + truncation marker

    def test_markdown_export_multiple(self):
        from heaven.devsecops.evidence import export_findings_markdown
        findings = [
            {"target": "x", "vuln_type": "sqli", "severity": "critical", "confidence": 0.95},
            {"target": "y", "vuln_type": "xss", "severity": "high", "confidence": 0.85},
        ]
        md = export_findings_markdown(findings, engagement_name="test-eng")
        assert "test-eng" in md
        assert "Severity breakdown" in md
        assert md.count("Proof of issue") == 2

    def test_csv_export(self):
        from heaven.devsecops.evidence import export_findings_csv
        findings = [
            {"id": "x1", "target": "a", "vuln_type": "sqli",
             "severity": "high", "confidence": 0.9},
        ]
        csv = export_findings_csv(findings)
        # First line is header
        assert csv.startswith("id,target,vuln_type")
        # Second line is data
        assert "x1,a,sqli" in csv


# ── End-to-end engagement workflow ─────────────────────────────────────

def test_full_engagement_workflow(tmp_path):
    """Simulate a real pentester workflow end-to-end."""
    from heaven.engagement import EngagementStore
    db = EngagementStore(tmp_path / "e2e.db")

    # 1. Initialize engagement
    db.create_engagement("acme-q2", client="ACME")

    # 2. Define scope
    db.add_scope("api.acme.test", kind="host")
    db.add_scope("https://app.acme.test", kind="url")
    db.add_scope("10.0.0.0/24", kind="cidr")
    assert len(db.list_scope()) == 3

    # 3. Run scan -> findings persisted
    db.record_scan_start("scan-001", name="initial recon", mode="web")
    findings = [
        {"target": "api.acme.test", "vuln_type": "sqli", "param": "id",
         "severity": "critical", "confidence": 0.94,
         "evidence": {"payload": "' OR 1=1--", "technique": "error_based"}},
        {"target": "api.acme.test", "vuln_type": "xss", "param": "q",
         "severity": "high", "confidence": 0.88},
        {"target": "10.0.0.5", "vuln_type": "open_port",
         "severity": "info", "confidence": 0.99},
    ]
    for f in findings:
        db.upsert_finding("scan-001", f)
    db.record_scan_complete("scan-001", {"total": 3})

    # 4. Operator triages
    sqli = [f for f in db.list_findings(severity="critical")][0]
    db.update_finding_status(sqli.id, "verified", notes="confirmed via burp")

    # 5. Run another scan — finds same SQLi, dedups
    db.record_scan_start("scan-002", name="re-test", mode="web")
    db.upsert_finding("scan-002", findings[0])
    db.record_scan_complete("scan-002", {"total": 1})

    refetched = db.get_finding(sqli.id)
    assert refetched.seen_count == 2
    assert refetched.status == "verified"  # operator status preserved

    # 6. Final stats
    stats = db.stats()
    assert stats["total_findings"] == 3
    assert stats["scans_run"] == 2
    assert stats["by_status"].get("verified") == 1


# ── API endpoint tests ─────────────────────────────────────────────────

@pytest.fixture
def api_client_with_engagement(monkeypatch, tmp_path):
    db_path = tmp_path / "api_eng.db"
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "engage-test-pwd")
    monkeypatch.setenv("HEAVEN_DB_PASSWORD", "engage-test-db")
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", str(db_path))
    monkeypatch.setenv("HEAVEN_RATE_LIMIT_LOGIN", "60/minute")
    monkeypatch.setenv("HEAVEN_RATE_LIMIT_DEFAULT", "1000/minute")

    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]

    # Pre-populate the DB
    from heaven.engagement import EngagementStore
    s = EngagementStore(db_path)
    s.create_engagement("api-test", client="TestCo")
    s.add_scope("api.test", kind="host")
    s.upsert_finding("s1", {
        "target": "api.test", "vuln_type": "sqli", "severity": "critical",
        "confidence": 0.92, "param": "id",
        "evidence": {"payload": "' OR 1=1--", "technique": "boolean_inference"},
    })

    from heaven.api.server import create_app
    from fastapi.testclient import TestClient
    return TestClient(create_app()), db_path


def test_engagement_summary_endpoint(api_client_with_engagement):
    client, _ = api_client_with_engagement
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "engage-test-pwd"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]

    r = client.get("/api/engagement", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["engagement"]["name"] == "api-test"
    assert data["stats"]["total_findings"] == 1


def test_engagement_findings_list_with_filter(api_client_with_engagement):
    client, _ = api_client_with_engagement
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "engage-test-pwd"})
    token = r.json()["token"]

    r = client.get("/api/engagement/findings?severity=critical",
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["findings"][0]["vuln_type"] == "sqli"


def test_engagement_finding_evidence_endpoint(api_client_with_engagement):
    client, _ = api_client_with_engagement
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "engage-test-pwd"})
    token = r.json()["token"]
    findings = client.get("/api/engagement/findings",
                          headers={"Authorization": f"Bearer {token}"}).json()
    finding_id = findings["findings"][0]["id"]

    r = client.get(f"/api/engagement/findings/{finding_id}/evidence",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert "evidence_package" in data
    assert "markdown" in data
    assert "curl" in data["evidence_package"]["curl_command"]


def test_finding_status_update_endpoint(api_client_with_engagement):
    client, _ = api_client_with_engagement
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "engage-test-pwd"})
    token = r.json()["token"]
    findings = client.get("/api/engagement/findings",
                          headers={"Authorization": f"Bearer {token}"}).json()
    fid = findings["findings"][0]["id"]

    r = client.put(f"/api/engagement/findings/{fid}/status",
                   json={"status": "verified", "notes": "confirmed"},
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    # Invalid status
    r = client.put(f"/api/engagement/findings/{fid}/status",
                   json={"status": "exploded", "notes": ""},
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
