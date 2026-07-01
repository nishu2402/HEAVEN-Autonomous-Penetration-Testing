"""HEAVEN — end-to-end API tests for the scan lifecycle + engagement wiring.

These lock in the fixes for the web-app bugs where:
  * a report download returned "No findings to report for this engagement"
    (the report read a different store than the one scans wrote to), and
  * clicking / removing / per-scan viewing didn't work.

Auth is bypassed (HEAVEN_DISABLE_AUTH) so we exercise the route logic directly.
Findings are seeded through the *same* store factory the endpoints use, so the
test proves the endpoints and the scan writer agree on which engagement holds
the data — the crux of the original bug.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    # The active-engagement pointer, not an env override, must drive resolution.
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _seed(engagement: str, scans: dict[str, list[dict]]):
    """Seed findings into the store the API resolves for *engagement*."""
    from heaven.api.server import _engagement_store_factory
    store = _engagement_store_factory(engagement)
    store.create_engagement(name=engagement)
    for scan_id, findings in scans.items():
        store.record_scan_start(scan_id, name=scan_id, mode="web")
        for f in findings:
            store.upsert_finding(scan_id, f)
    return store


def test_report_follows_active_engagement(client):
    """Switching the active engagement makes the report export read *that* store —
    no more spurious 'No findings to report for this engagement'."""
    r = client.post("/api/engagements/active", json={"name": "e2e-eng"})
    assert r.status_code == 200 and r.json()["active"] == "e2e-eng"

    _seed("e2e-eng", {
        "scanA": [{"target": "https://a.example.com", "vuln_type": "xss",
                   "title": "Reflected XSS", "severity": "high",
                   "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b.example.com", "vuln_type": "sqli",
                   "title": "SQL Injection", "severity": "critical",
                   "confidence": 0.95, "risk_score": 9.1}],
    })

    # No engagement param — the server must resolve the *active* engagement.
    r = client.get("/api/report/export?format=json")
    assert r.status_code == 200, r.text
    assert "Reflected XSS" in r.text
    assert "SQL Injection" in r.text


def test_findings_filter_by_scan(client):
    client.post("/api/engagements/active", json={"name": "e2e-filter"})
    _seed("e2e-filter", {
        "scanA": [{"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
                   "severity": "high", "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b", "vuln_type": "sqli", "title": "SQL Injection",
                   "severity": "critical", "confidence": 0.95, "risk_score": 9.1}],
    })

    r = client.get("/api/engagement/findings?scan_id=scanA")
    assert r.status_code == 200, r.text
    assert [f["title"] for f in r.json()["findings"]] == ["Reflected XSS"]


def test_scan_detail_and_delete(client):
    """A completed scan not in memory is still viewable (store fallback), and a
    finished scan can be permanently removed."""
    client.post("/api/engagements/active", json={"name": "e2e-delete"})
    _seed("e2e-delete", {
        "scanA": [{"target": "https://a", "vuln_type": "xss", "title": "Reflected XSS",
                   "severity": "high", "confidence": 0.9, "risk_score": 7.5}],
        "scanB": [{"target": "https://b", "vuln_type": "sqli", "title": "SQL Injection",
                   "severity": "critical", "confidence": 0.95, "risk_score": 9.1}],
    })

    # Clicking a scan → its findings (works even though it's not in active_scans)
    r = client.get("/api/scans/scanB?include_findings=true")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings_count"] == 1
    assert body["findings"][0]["title"] == "SQL Injection"

    # engagements listing surfaces the active engagement with its counts
    js = client.get("/api/engagements").json()
    assert js["active"] == "e2e-delete"
    row = next(e for e in js["engagements"] if e["name"] == "e2e-delete")
    assert row["active"] and row["findings"] == 2

    # Remove scanA → its finding is gone; scanB is untouched
    r = client.delete("/api/scans/scanA")
    assert r.status_code == 200 and r.json()["status"] == "deleted", r.text
    assert client.get("/api/engagement/findings?scan_id=scanA").json()["findings"] == []
    assert client.get("/api/scans/scanA").status_code == 404
    assert client.get("/api/scans/scanB").status_code == 200


def test_resolve_engagement_priority(tmp_path, monkeypatch):
    """Resolution order: explicit arg > env > active pointer > 'default'."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    from heaven.api import server
    server._active_engagement_file().unlink(missing_ok=True)

    assert server._resolve_engagement_name() == "default"
    server._set_active_engagement("acme")
    assert server._resolve_engagement_name() == "acme"
    assert server._resolve_engagement_name("explicit") == "explicit"
    monkeypatch.setenv("HEAVEN_ENGAGEMENT", "envwins")
    assert server._resolve_engagement_name() == "envwins"
