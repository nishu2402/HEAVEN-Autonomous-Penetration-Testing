"""HEAVEN — tests for the two features wired in during the dead-code cleanup:

  * SBOM (CycloneDX) export — `heaven sbom` + GET /api/sbom. The generator was
    previously orphaned *and* expected an asset shape the scanner never emits;
    it now consumes the real `{host, open_ports:[...]}` shape and folds CVE
    findings into the SBOM's `vulnerabilities` section.
  * AI-assisted remediation — `heaven remediate` + POST
    /api/findings/{id}/remediation. Degrades to the knowledge-base remediation
    when no LLM key is set (so these tests need no network / API key).
"""

from __future__ import annotations

import json

import pytest

from heaven.devsecops.ai_remediation import AIRemediationEngine
from heaven.devsecops.sbom import collect_scan_data, generate_cyclonedx_sbom


# ── Unit: SBOM generator ──

def test_sbom_consumes_real_scanner_shape():
    doc = generate_cyclonedx_sbom({"assets": [{
        "host": "10.0.0.5",
        "open_ports": [
            {"port": 80, "service": "http", "version": "nginx 1.18.0",
             "cpe": "cpe:/a:nginx:nginx:1.18.0"},
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.2"},
            {"port": 443, "service": "", "version": ""},   # unnamed → skipped
        ],
    }]})
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    names = [c["name"] for c in doc["components"]]
    assert names == ["http", "ssh"]                      # unnamed port dropped
    nginx = doc["components"][0]
    assert nginx["cpe"] == "cpe:/a:nginx:nginx:1.18.0"   # cpe preserved
    assert nginx["purl"].startswith("pkg:generic/http@")


def test_sbom_consumes_legacy_ports_dict_shape():
    doc = generate_cyclonedx_sbom({"assets": [{
        "target": "host.example",
        "ports": {"8080": {"product": "Apache Tomcat", "version": "9.0.1"}},
    }]})
    assert [c["name"] for c in doc["components"]] == ["Apache Tomcat"]
    assert doc["components"][0]["version"] == "9.0.1"


def test_sbom_folds_cve_findings_and_dedups():
    doc = generate_cyclonedx_sbom({
        "assets": [],
        "vulnerabilities": [
            {"cve_id": "CVE-2021-23017", "title": "nginx overflow", "risk_score": 8.1},
            {"cve_id": "CVE-2021-23017", "title": "dup"},          # deduped
            {"title": "no cve at all"},                             # skipped
        ],
    })
    vulns = doc.get("vulnerabilities", [])
    assert [v["id"] for v in vulns] == ["CVE-2021-23017"]
    assert vulns[0]["ratings"][0]["score"] == 8.1
    assert vulns[0]["source"]["name"] == "NVD"


def test_sbom_empty_input_is_still_valid_cyclonedx():
    doc = generate_cyclonedx_sbom({})
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"] == []
    assert "vulnerabilities" not in doc          # omitted when none


def test_sbom_writes_file(tmp_path):
    out = tmp_path / "sbom.json"
    generate_cyclonedx_sbom({"assets": []}, output_path=str(out))
    assert out.exists()
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"


# ── Unit: collect_scan_data pulls assets from scan summaries + CVE findings ──

def test_collect_scan_data_from_store(tmp_path):
    from heaven.engagement import EngagementStore
    store = EngagementStore(tmp_path / "eng.db")
    store.record_scan_start("s1", name="recon")
    store.record_scan_complete("s1", {
        "assets": [{"host": "10.0.0.9", "open_ports": [
            {"port": 3306, "service": "mysql", "version": "8.0.32"}]}],
    })
    store.upsert_finding("s1", {
        "target": "10.0.0.9", "vuln_type": "sqli", "title": "SQLi",
        "severity": "high", "cve_id": "CVE-2020-1111", "risk_score": 7.5,
    })
    data = collect_scan_data(store)
    assert data["assets"][0]["host"] == "10.0.0.9"
    doc = generate_cyclonedx_sbom(data)
    assert [c["name"] for c in doc["components"]] == ["mysql"]
    assert [v["id"] for v in doc.get("vulnerabilities", [])] == ["CVE-2020-1111"]


# ── Unit: AI remediation falls back to the static patch with no LLM ──

def test_ai_remediation_static_fallback():
    engine = AIRemediationEngine()          # no key in the test env
    assert engine.available is False
    out = engine.generate_patch({
        "title": "SQL Injection", "target": "http://x",
        "patch": "Use parameterized queries.",
    })
    assert out == "Use parameterized queries."


# ── API: /api/sbom + /api/findings/{id}/remediation ──

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _seed_finding(engagement="remedtest"):
    """Seed a finding through the server's own resolver so the path matches
    exactly what the endpoint reads."""
    from heaven.api import server as srv
    store = srv._engagement_store_factory(engagement)
    return store.upsert_finding("s1", {
        "target": "http://victim.example", "vuln_type": "sqli",
        "title": "SQL Injection", "severity": "high",
        "cve_id": "CVE-2019-0001", "risk_score": 8.2,
    })


def test_sbom_endpoint_returns_cyclonedx(client):
    from heaven.api import server as srv
    store = srv._engagement_store_factory("sbomapi")
    store.record_scan_start("s1", name="r")
    store.record_scan_complete("s1", {"assets": [{"host": "1.2.3.4",
        "open_ports": [{"port": 80, "service": "http", "version": "nginx"}]}]})
    r = client.get("/api/sbom", params={"engagement": "sbomapi"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["bomFormat"] == "CycloneDX"
    assert [c["name"] for c in doc["components"]] == ["http"]


def test_sbom_endpoint_download_sets_attachment(client):
    r = client.get("/api/sbom", params={"download": True})
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")


def test_remediation_endpoint_static_fallback(client):
    fid = _seed_finding("remedtest")
    r = client.post(f"/api/findings/{fid}/remediation",
                    params={"engagement": "remedtest"})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_id"] == fid
    assert body["ai_generated"] is False        # no LLM key in test env
    assert body["remediation"]                    # KB remediation, non-empty


def test_remediation_endpoint_404_for_missing_finding(client):
    r = client.post("/api/findings/deadbeef/remediation",
                    params={"engagement": "remedtest"})
    assert r.status_code == 404


# ── CLI: both commands are wired end-to-end ──

def test_cli_sbom_writes_valid_file(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "cli-sbom.json"
    res = CliRunner().invoke(cli, ["sbom", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"


def test_cli_remediate_missing_finding_exits_2(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(cli, ["remediate", "no-such-id"])
    assert res.exit_code == 2                      # not-found path, cleanly wired
