"""HEAVEN — regression tests for the end-to-end security-audit fixes.

Each test pins a specific vulnerability that was found and fixed:

  * SSRF / injection: the scan API previously passed raw targets straight to
    the scanners (the InputSanitizer existed but was never called). It now
    validates every target at the create-scan boundary.
  * Path traversal: an engagement name or scan id supplied over HTTP becomes a
    DB / report *filename*. Values with "../", separators or an absolute path
    are now rejected before any filesystem operation.
  * The URL sanitizer now blocks IP-literal hosts in reserved ranges (e.g.
    http://169.254.169.254/ cloud metadata), which it previously let through.
  * Auth: an unknown-username login spends the same PBKDF2 cost as a real one
    (no timing oracle) and does not raise.
"""

from __future__ import annotations

import pytest

from heaven.security.sanitizer import InputSanitizer


# ── Unit: InputSanitizer.sanitize_target / sanitize_url ──

def test_sanitize_url_blocks_cloud_metadata_even_when_localhost_allowed():
    # The 169.254.169.254 metadata endpoint must be blocked regardless of the
    # allow_localhost / allow_private policy (it's SSRF-to-infrastructure).
    s = InputSanitizer(allow_private=True, allow_localhost=True)
    r = s.sanitize_url("http://169.254.169.254/latest/meta-data/")
    assert not r.valid


def test_sanitize_target_blocks_argument_injection_leading_dash():
    s = InputSanitizer()
    assert not s.sanitize_target("-oG/tmp/pwn").valid          # nmap flag smuggling
    assert not s.sanitize_target("--os-shell").valid            # sqlmap flag smuggling


@pytest.mark.parametrize("bad", [
    "example.com; rm -rf /",
    "10.0.0.1 && curl evil",
    "target`whoami`",
    "http://site/%00null",
    "a$(id)",
])
def test_sanitize_target_blocks_injection_metacharacters(bad):
    assert not InputSanitizer().sanitize_target(bad).valid


def test_sanitize_target_blocks_metadata_and_reserved_ranges():
    s = InputSanitizer(allow_private=True, allow_localhost=True)
    assert not s.sanitize_target("169.254.169.254").valid       # cloud metadata
    assert not s.sanitize_target("224.0.0.1").valid             # multicast (reserved)


@pytest.mark.parametrize("good", [
    "example.com",
    "scanme.nmap.org",
    "dvwa",                    # single-label internal host
    "target-01.internal",
    "93.184.216.34",           # a normal public IP
    "https://app.example.com/login",
])
def test_sanitize_target_allows_ordinary_targets(good):
    assert InputSanitizer().sanitize_target(good).valid


def test_private_and_localhost_gated_by_policy():
    # Default for the *library* blocks localhost; explicit allow lets it through.
    assert not InputSanitizer(allow_localhost=False).sanitize_target("127.0.0.1").valid
    assert InputSanitizer(allow_localhost=True).sanitize_target("127.0.0.1").valid


# ── API boundary ──

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    monkeypatch.delenv("HEAVEN_ENGAGEMENT", raising=False)
    # Lock the host/private policy down so the SSRF assertions are deterministic.
    monkeypatch.setenv("HEAVEN_ALLOW_LOCALHOST", "0")
    monkeypatch.setenv("HEAVEN_ALLOW_PRIVATE", "0")

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def _scan_body(**over):
    body = {"targets": ["example.com"], "i_have_authorization": True}
    body.update(over)
    return body


def test_create_scan_rejects_metadata_url_target(client):
    r = client.post("/api/scans", json=_scan_body(targets=["http://169.254.169.254/"]))
    assert r.status_code == 400
    assert "Target validation failed" in r.json()["detail"]


def test_create_scan_rejects_injection_target(client):
    r = client.post("/api/scans", json=_scan_body(targets=["example.com; rm -rf /"]))
    assert r.status_code == 400


def test_create_scan_rejects_localhost_when_locked_down(client):
    # HEAVEN_ALLOW_LOCALHOST=0 in the fixture — a hosted deployment posture.
    r = client.post("/api/scans", json=_scan_body(targets=["127.0.0.1"]))
    assert r.status_code == 400


def test_create_scan_rejects_traversal_engagement(client):
    r = client.post("/api/scans", json=_scan_body(engagement="../../etc/evil"))
    assert r.status_code == 400
    assert "engagement" in r.json()["detail"].lower()


def test_export_rejects_traversal_engagement(client):
    r = client.get("/api/report/export", params={"engagement": "../../secret"})
    assert r.status_code == 400


def test_set_active_engagement_rejects_traversal(client):
    r = client.post("/api/engagements/active", json={"name": "../../etc/evil"})
    assert r.status_code == 400


def test_dashboard_ignores_unsafe_scan_id(client):
    # An unsafe scan_id must not read outside the data dir — the guard makes the
    # lookup return empty rather than traversing.
    r = client.get("/api/dashboard", params={"scan_id": "../../../../etc/passwd"})
    assert r.status_code == 200  # handled safely, no traversal, no crash


def test_delete_scan_rejects_unsafe_id(client):
    # A routable but non-conforming id ('.' isn't in the safe set) must be
    # rejected before any report_<id>.json unlink is attempted.
    r = client.delete("/api/scans/bad.id")
    assert r.status_code == 400


# ── Auth: no username-enumeration timing oracle / no crash ──

def test_authenticate_unknown_user_returns_none_without_error():
    from heaven.security.auth import AuthManager
    am = AuthManager()
    assert am.authenticate("no-such-user", "whatever") is None
    # A real account with a wrong password also returns None.
    assert am.authenticate("admin", "definitely-wrong") is None
