"""HEAVEN — API tests for report export + the auth password-change flow.

Uses a per-test app with a fresh AuthManager (seeded from a known env password)
and a tmp working directory, so the .env-persistence path is exercised
deterministically. Auth is bypassed (HEAVEN_DISABLE_AUTH) so we hit the route
logic directly without a login round-trip.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None  # force a fresh manager seeded from the env above
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None  # don't leak the singleton into other tests


# ── Report export ──

def test_report_export_empty_engagement_404(client):
    # A brand-new engagement (created under tmp cwd) has no findings → 404.
    r = client.get("/api/report/export?engagement=__empty_test_eng__&format=json")
    assert r.status_code == 404, r.text


def test_report_export_unknown_format_is_handled(client):
    # Even an unknown format must not 500 — it's either 404 (no findings) or 400.
    r = client.get("/api/report/export?engagement=__empty_test_eng__&format=does-not-exist")
    assert r.status_code in (400, 404), r.text


# ── Change password ──

def test_change_password_wrong_current_401(client):
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "WRONG-PASSWORD", "new_password": "New-Strong-Passw0rd"},
    )
    assert r.status_code == 401, r.text


def test_change_password_weak_new_422(client):
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "Known-Old-Passw0rd", "new_password": "short"},
    )
    assert r.status_code == 422, r.text


def test_change_password_common_new_422(client):
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "Known-Old-Passw0rd", "new_password": "password"},
    )
    assert r.status_code == 422, r.text


def test_change_password_success_persists_to_env(client, tmp_path):
    r = client.post(
        "/api/auth/change-password",
        json={"current_password": "Known-Old-Passw0rd", "new_password": "New-Strong-Passw0rd-9"},
    )
    assert r.status_code == 200, r.text
    assert r.json().get("persisted") is True
    assert "HEAVEN_ADMIN_PASSWORD=New-Strong-Passw0rd-9" in (tmp_path / ".env").read_text()
