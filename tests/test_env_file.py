"""HEAVEN — tests for `.env` persistence of Web-UI password changes.

Covers the surgical .env writer (heaven/utils/env_file.py) and the end-to-end
"a password set in the browser survives a server restart" behaviour, which is
what makes .env the source of truth for the in-memory AuthManager.
"""

from __future__ import annotations

from heaven.utils.env_file import set_env_var


def test_set_env_var_creates_file(tmp_path):
    p = tmp_path / ".env"
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "Hunter2-strong")
    assert p.exists()
    assert "HEAVEN_ADMIN_PASSWORD=Hunter2-strong" in p.read_text()


def test_set_env_var_replaces_in_place_preserving_other_lines(tmp_path):
    p = tmp_path / ".env"
    p.write_text(
        "# my env\n"
        "HEAVEN_ADMIN_USERNAME=nisarg\n"
        "HEAVEN_ADMIN_PASSWORD=old-pass-123\n"
        "GEMINI_API_KEY=keep-me\n"
    )
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "new-pass-456")
    text = p.read_text()
    assert "HEAVEN_ADMIN_PASSWORD=new-pass-456" in text
    assert "old-pass-123" not in text
    # Other keys + comments untouched
    assert "# my env" in text
    assert "HEAVEN_ADMIN_USERNAME=nisarg" in text
    assert "GEMINI_API_KEY=keep-me" in text
    # Exactly one password line
    assert text.count("HEAVEN_ADMIN_PASSWORD=") == 1


def test_set_env_var_appends_when_missing(tmp_path):
    p = tmp_path / ".env"
    p.write_text("GEMINI_API_KEY=abc\n")
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "appended-pass-1")
    text = p.read_text()
    assert "GEMINI_API_KEY=abc" in text
    assert "HEAVEN_ADMIN_PASSWORD=appended-pass-1" in text


def test_set_env_var_ignores_commented_line(tmp_path):
    p = tmp_path / ".env"
    p.write_text("# HEAVEN_ADMIN_PASSWORD=disabled\n")
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "real-pass-1")
    text = p.read_text()
    # The comment is preserved; a real line is appended.
    assert "# HEAVEN_ADMIN_PASSWORD=disabled" in text
    assert "HEAVEN_ADMIN_PASSWORD=real-pass-1" in text


def test_set_env_var_quotes_values_with_spaces(tmp_path):
    p = tmp_path / ".env"
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "pass with spaces")
    assert 'HEAVEN_ADMIN_PASSWORD="pass with spaces"' in p.read_text()


def test_password_change_survives_restart(tmp_path, monkeypatch):
    """Simulate the full loop: write new password to .env → restart (re-load
    .env into a fresh AuthManager) → the new password authenticates."""
    from dotenv import load_dotenv
    from heaven.security.auth import AuthManager

    env = tmp_path / ".env"
    set_env_var(env, "HEAVEN_ADMIN_USERNAME", "nisarg")
    set_env_var(env, "HEAVEN_ADMIN_PASSWORD", "brand-New-Passw0rd")

    # Register the keys with monkeypatch FIRST so load_dotenv(override=True) —
    # which writes straight into os.environ — gets cleanly reverted on teardown
    # and can't leak the admin identity into other tests.
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "placeholder")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "placeholder")

    # "Restart": load the persisted .env (override=True mimics authoritative load)
    load_dotenv(env, override=True)
    am = AuthManager()
    assert am.authenticate("nisarg", "brand-New-Passw0rd") is not None
    assert am.authenticate("nisarg", "old-whatever") is None


def test_change_password_endpoint_persists_to_env(tmp_path, monkeypatch):
    """POST /api/auth/change-password writes HEAVEN_ADMIN_PASSWORD to ./.env."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "old-Passw0rd-1")

    # Fresh AuthManager so it seeds the admin with the env password above.
    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        client = TestClient(create_app())
        r = client.post(
            "/api/auth/change-password",
            json={"current_password": "old-Passw0rd-1", "new_password": "new-Passw0rd-2"},
        )
        assert r.status_code == 200, r.text
        assert r.json().get("persisted") is True
        assert "HEAVEN_ADMIN_PASSWORD=new-Passw0rd-2" in (tmp_path / ".env").read_text()
    finally:
        auth_mod._auth_manager = None  # don't leak the singleton into other tests
