"""HEAVEN — tests for `.env` persistence of Web-UI password changes.

Covers the surgical .env writer (heaven/utils/env_file.py) and the end-to-end
"a password set in the browser survives a server restart" behaviour, which is
what makes .env the source of truth for the in-memory AuthManager.
"""

from __future__ import annotations

import os

import pytest

from heaven.utils.env_file import set_env_var, write_private_file

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX file-mode semantics"
)


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


# ── .env line-injection (CWE-93) is rejected at the writer chokepoint ──

@pytest.mark.parametrize("payload", [
    "ok\nHEAVEN_DISABLE_AUTH=1",       # smuggle an out-of-catalog key on line 2
    "ok\r\nHEAVEN_DISABLE_AUTH=1",     # CRLF variant
    "ok\rHEAVEN_DISABLE_AUTH=1",       # bare CR
    "ok\x00trailing",                  # NUL
])
def test_set_env_var_rejects_control_chars(tmp_path, payload):
    """A value carrying a newline/CR/NUL must never be written — it would break
    out of its own KEY=value line and inject another key."""
    p = tmp_path / ".env"
    p.write_text("EXISTING=keep\n")
    with pytest.raises(ValueError):
        set_env_var(p, "HEAVEN_ADMIN_PASSWORD", payload)
    # The file is untouched: no second line, nothing smuggled in.
    text = p.read_text()
    assert "HEAVEN_DISABLE_AUTH" not in text
    assert text == "EXISTING=keep\n"


def test_set_env_var_rejects_malformed_key(tmp_path):
    p = tmp_path / ".env"
    with pytest.raises(ValueError):
        set_env_var(p, "BAD KEY\nINJECTED=1", "whatever")
    assert not p.exists() or "INJECTED" not in p.read_text()


def test_set_password_rejects_control_chars():
    """The change-password policy rejects a control char, so the injection can't
    even reach the .env writer (and the admin password isn't silently truncated)."""
    from heaven.security.auth import AuthManager
    am = AuthManager()
    admin = next(u for u in am._users.values() if u.username == "admin")
    with pytest.raises(ValueError):
        am.set_password(admin.username, "GoodStart\nHEAVEN_DISABLE_AUTH=1")


def test_settings_api_cannot_inject_env_line_via_value(tmp_path, monkeypatch):
    """POST /api/settings routes through the same writer, so a newline in a
    catalog value can't smuggle HEAVEN_DISABLE_AUTH into .env either."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")  # test-mode: bypass auth dep
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "old-Passw0rd-1")

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        client = TestClient(create_app())
        # SHODAN_API_KEY is a real catalog key; the newline payload must be refused.
        r = client.post(
            "/api/settings",
            json={"settings": {"SHODAN_API_KEY": "abc\nHEAVEN_DISABLE_AUTH=1"}},
        )
        assert r.status_code == 422, r.text
        env_file = tmp_path / ".env"
        if env_file.exists():
            assert "HEAVEN_DISABLE_AUTH=1" not in env_file.read_text()
    finally:
        auth_mod._auth_manager = None


# ── Secret .env files are written atomically + owner-only (CWE-276) ──

@_POSIX_ONLY
def test_write_private_file_is_owner_only(tmp_path):
    """The writer must not leave a secret file readable by group or other."""
    p = tmp_path / ".env"
    write_private_file(p, "HEAVEN_ADMIN_PASSWORD=s3cr3t\n")
    assert p.read_text() == "HEAVEN_ADMIN_PASSWORD=s3cr3t\n"
    assert (p.stat().st_mode & 0o077) == 0, "group/other must have no access"


@_POSIX_ONLY
def test_set_env_var_writes_owner_only(tmp_path):
    p = tmp_path / ".env"
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "Hunter2-strong")
    assert (p.stat().st_mode & 0o077) == 0


@_POSIX_ONLY
def test_set_env_var_narrows_legacy_world_readable_file(tmp_path):
    """A pre-existing 0644 .env is tightened to owner-only on the next write."""
    p = tmp_path / ".env"
    p.write_text("HEAVEN_ADMIN_PASSWORD=old\n")
    os.chmod(p, 0o644)  # simulate a legacy world-readable file
    set_env_var(p, "HEAVEN_ADMIN_PASSWORD", "new-pass-123")
    assert "new-pass-123" in p.read_text()
    assert (p.stat().st_mode & 0o077) == 0


@_POSIX_ONLY
def test_init_write_env_is_owner_only(tmp_path):
    """`heaven init` writes the primary secret file 0600, not world-readable."""
    from heaven.cli.init import _write_env
    p = tmp_path / ".env"
    _write_env(p, {"HEAVEN_ADMIN_PASSWORD": "Hunter2", "HEAVEN_DB_PASSWORD": "dbpw"})
    text = p.read_text()
    assert "HEAVEN_ADMIN_PASSWORD=Hunter2" in text
    assert "HEAVEN_DB_PASSWORD=dbpw" in text
    assert (p.stat().st_mode & 0o077) == 0


def test_write_private_file_leaves_no_temp_on_success(tmp_path):
    """The atomic write cleans up: only .env remains, no .env-*.tmp scratch."""
    p = tmp_path / ".env"
    write_private_file(p, "A=1\n")
    assert [q.name for q in tmp_path.iterdir()] == [".env"]


def test_write_private_file_preserves_original_on_failure(tmp_path, monkeypatch):
    """If the write fails partway, the existing .env is left intact (atomic) and
    the scratch temp is cleaned up — the admin password can't be truncated away."""
    from heaven.utils import env_file
    p = tmp_path / ".env"
    p.write_text("HEAVEN_ADMIN_PASSWORD=original\n")

    def boom(*_a, **_k):
        raise OSError("simulated disk-full mid-write")

    monkeypatch.setattr(env_file.os, "fsync", boom)
    with pytest.raises(OSError):
        env_file.write_private_file(p, "HEAVEN_ADMIN_PASSWORD=would-replace\n")
    # Original survived; no partial/truncated write; no leftover scratch file.
    assert p.read_text() == "HEAVEN_ADMIN_PASSWORD=original\n"
    assert [q.name for q in tmp_path.iterdir()] == [".env"]


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


# ── Data-dir root secrecy (CWE-276) ──────────────────────────────────────
@_POSIX_ONLY
def test_ensure_dirs_locks_data_root_owner_only(tmp_path):
    """`ensure_dirs()` must create the data root (and audit dir) owner-only, so
    a shared host can't let another local user traverse in and read a client's
    engagement DBs, reports or the audit trail."""
    from heaven.config import HeavenConfig

    cfg = HeavenConfig()
    cfg.data_dir = tmp_path / "state"
    cfg.security.audit_log_dir = cfg.data_dir / "audit"
    cfg.ensure_dirs()

    assert cfg.data_dir.is_dir()
    assert (cfg.data_dir.stat().st_mode & 0o077) == 0, oct(cfg.data_dir.stat().st_mode)
    assert (cfg.security.audit_log_dir.stat().st_mode & 0o077) == 0, \
        oct(cfg.security.audit_log_dir.stat().st_mode)
