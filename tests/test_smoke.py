"""
HEAVEN smoke tests — verify that the fixes actually hold.

Run with:  pytest tests/test_smoke.py -v
"""
from __future__ import annotations

import os
import re
import sys

import pytest


# ── Target validation regex tests ────────────────────────────────────

def test_ip_regex_accepts_valid_ipv4():
    from heaven.main import _IP_REGEX
    assert _IP_REGEX.match("192.168.1.1")
    assert _IP_REGEX.match("10.0.0.0/24")
    assert _IP_REGEX.match("172.16.0.1/16")


def test_ip_regex_rejects_invalid():
    from heaven.main import _IP_REGEX
    assert not _IP_REGEX.match("not_an_ip")
    assert not _IP_REGEX.match("999.999.999.999/x")
    assert not _IP_REGEX.match("")


def test_url_regex_accepts_valid_urls():
    from heaven.main import _URL_REGEX
    assert _URL_REGEX.match("http://example.com")
    assert _URL_REGEX.match("https://example.com/path?q=1")
    assert _URL_REGEX.match("HTTPS://EXAMPLE.COM")


def test_url_regex_rejects_invalid():
    from heaven.main import _URL_REGEX
    assert not _URL_REGEX.match("not a url")
    assert not _URL_REGEX.match("ftp://example.com")
    assert not _URL_REGEX.match("")


def test_validate_target_string():
    from heaven.main import _validate_target_string
    ok, kind = _validate_target_string("192.168.1.1")
    assert ok and kind == "ip"
    ok, kind = _validate_target_string("example.com")
    assert ok and kind == "host"
    ok, _ = _validate_target_string("")
    assert not ok


# ── Authorization gate tests ─────────────────────────────────────────

def test_auth_gate_blocks_without_ack(monkeypatch):
    monkeypatch.delenv("HEAVEN_AUTHORIZED_SCOPE", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    from heaven.main import _verify_authorization
    assert not _verify_authorization({"urls": ["https://x.example"]}, ack_flag=False)


def test_auth_gate_allows_with_flag():
    from heaven.main import _verify_authorization
    assert _verify_authorization({"urls": ["https://x.example"]}, ack_flag=True)


def test_auth_gate_allows_with_env_var(monkeypatch):
    monkeypatch.setenv("HEAVEN_AUTHORIZED_SCOPE", "https://x.example,10.0.0.5")
    from heaven.main import _verify_authorization
    assert _verify_authorization({"urls": ["https://x.example"]}, ack_flag=False)


def test_auth_gate_rejects_target_outside_env_allowlist(monkeypatch):
    monkeypatch.setenv("HEAVEN_AUTHORIZED_SCOPE", "https://x.example")
    from heaven.main import _verify_authorization
    assert not _verify_authorization({"urls": ["https://other.example"]}, ack_flag=False)


def test_auth_gate_passes_when_no_targets():
    from heaven.main import _verify_authorization
    # Empty targets shouldn't trigger the gate
    assert _verify_authorization({}, ack_flag=False)


# ── API auth tests ───────────────────────────────────────────────────

@pytest.fixture
def api_client(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "smoke-test-pwd-12345")
    monkeypatch.setenv("HEAVEN_DB_PASSWORD", "smoke-test-db-pwd")

    # Reload modules under fresh env
    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]

    from heaven.api.server import create_app
    from fastapi.testclient import TestClient
    return TestClient(create_app())


def test_health_unauthenticated(api_client):
    r = api_client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dashboard_requires_auth(api_client):
    r = api_client.get("/api/dashboard")
    assert r.status_code == 401


def test_login_returns_token(api_client):
    r = api_client.post("/api/auth/login", json={"username": "admin", "password": "smoke-test-pwd-12345"})
    assert r.status_code == 200
    body = r.json()
    assert "token" in body
    assert body["expires_in"] > 0


def test_login_wrong_password_fails(api_client):
    r = api_client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_authed_dashboard_works(api_client):
    r = api_client.post("/api/auth/login", json={"username": "admin", "password": "smoke-test-pwd-12345"})
    token = r.json()["token"]
    r = api_client.get("/api/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_scan_endpoint_requires_authorization_assertion(api_client):
    r = api_client.post("/api/auth/login", json={"username": "admin", "password": "smoke-test-pwd-12345"})
    token = r.json()["token"]
    # i_have_authorization=False (default) — should be refused
    r = api_client.post(
        "/api/scans",
        json={"targets": ["10.0.0.1"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400


# ── Self-audit grade test ────────────────────────────────────────────

def test_self_audit_passes_with_secure_env(monkeypatch):
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "real-strong-password-set")
    monkeypatch.setenv("HEAVEN_DB_PASSWORD", "real-strong-db-password")
    monkeypatch.delenv("HEAVEN_DEBUG", raising=False)

    for mod in list(sys.modules.keys()):
        if mod.startswith("heaven"):
            del sys.modules[mod]

    from heaven.security.self_audit import SelfAuditor
    report = SelfAuditor().run_full_audit()
    # Should be A grade (≥90) with secrets set
    assert report["score"] >= 90, f"Self-audit score too low: {report['score']}/100, findings: {report['severity_breakdown']}"
    assert report["severity_breakdown"]["high"] == 0
    assert report["severity_breakdown"]["critical"] == 0


# ── No double-escape regex in source ─────────────────────────────────

def test_no_double_escaped_regex_in_source():
    """Catch the `\\\\d` / `\\\\s` bug from main.py / api/server.py before regression."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    bad_files = []
    for py in (root / "heaven").rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        text = py.read_text(errors="ignore")
        # Look for `re.compile(r'...\\\\d...')` literally in non-test code.
        # In Python source `\\\\d` represents the 4-character sequence \\d
        # which is broken regex. Real code should use `\d` or raw r"\d".
        # Look for re.compile(...) calls that have a doubled backslash followed
        # by a regex char class character.
        if re.search(r"re\.compile\([^)]*?\\\\[dswDSW]", text):
            bad_files.append(str(py.relative_to(root)))
    assert not bad_files, f"Double-escaped regex found in: {bad_files}"
