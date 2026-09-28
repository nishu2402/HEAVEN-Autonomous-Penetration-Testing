"""Tests for the encrypted credential vault and its wiring into the product.

Covers the crypto round-trip, the ``os.environ`` load seam (how a stored key
actually drives HEAVEN), master-password rotation, and the `heaven vault` CLI.
"""

from __future__ import annotations

import pytest

from heaven.security import vault as vaultlib

pytestmark = pytest.mark.skipif(
    not vaultlib.HAS_CRYPTO, reason="cryptography not installed"
)


# ── Library: crypto round-trip ───────────────────────────────────────────────

def test_init_store_retrieve_roundtrip(tmp_path):
    vp = tmp_path / "vault.enc"
    cv = vaultlib.CredentialVault(vault_path=vp)
    cv.initialize("master-pw")
    cv.save()
    assert vp.exists()
    cv.store("OPENAI_API_KEY", "sk-secret")
    cv.lock()

    reopened = vaultlib.open_vault("master-pw", vp)
    assert reopened is not None
    assert reopened.retrieve("OPENAI_API_KEY") == "sk-secret"


def test_wrong_password_is_rejected(tmp_path):
    vp = tmp_path / "vault.enc"
    cv = vaultlib.CredentialVault(vault_path=vp)
    cv.initialize("right-pw")
    cv.store("K", "v")
    cv.lock()
    assert vaultlib.open_vault("wrong-pw", vp) is None


def test_ciphertext_is_not_plaintext_on_disk(tmp_path):
    vp = tmp_path / "vault.enc"
    cv = vaultlib.CredentialVault(vault_path=vp)
    cv.initialize("pw")
    cv.store("NVD_API_KEY", "super-secret-value")
    cv.lock()
    raw = vp.read_bytes()
    assert b"super-secret-value" not in raw  # encrypted at rest


def test_rotate_master_password(tmp_path):
    vp = tmp_path / "vault.enc"
    cv = vaultlib.CredentialVault(vault_path=vp)
    cv.initialize("old-pw")
    cv.store("K", "v")
    cv.rotate_key("new-pw")
    cv.lock()
    assert vaultlib.open_vault("old-pw", vp) is None
    rotated = vaultlib.open_vault("new-pw", vp)
    assert rotated is not None and rotated.retrieve("K") == "v"


# ── The os.environ load seam (how the vault drives the product) ───────────────

def test_load_into_env_override_semantics(tmp_path, monkeypatch):
    vp = tmp_path / "vault.enc"
    cv = vaultlib.CredentialVault(vault_path=vp)
    cv.initialize("pw")
    cv.store("OPENAI_API_KEY", "from-vault")
    cv.store("NVD_API_KEY", "vault-nvd")
    cv.lock()

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("NVD_API_KEY", "env-wins")

    # override=False preserves an existing env value, fills the missing one
    count, _msg = vaultlib.load_into_env("pw", path=vp)
    assert count == 1
    import os
    assert os.environ["OPENAI_API_KEY"] == "from-vault"
    assert os.environ["NVD_API_KEY"] == "env-wins"

    # override=True lets the vault replace it
    vaultlib.load_into_env("pw", path=vp, override=True)
    assert os.environ["NVD_API_KEY"] == "vault-nvd"


def test_load_into_env_needs_password(tmp_path, monkeypatch):
    vp = tmp_path / "vault.enc"
    vaultlib.CredentialVault(vault_path=vp).initialize("pw")  # not even saved
    monkeypatch.delenv("HEAVEN_VAULT_PASSWORD", raising=False)
    count, msg = vaultlib.load_into_env(path=vp)
    assert count == 0 and "password" in msg.lower()


# ── CLI: end-to-end through `heaven vault` ───────────────────────────────────

def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("HEAVEN_VAULT_PATH", str(tmp_path / "vault.enc"))
    monkeypatch.setenv("HEAVEN_VAULT_PASSWORD", "cli-master")


def test_cli_vault_init_set_list_get(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    _env(monkeypatch, tmp_path)
    r = CliRunner()

    assert r.invoke(cli, ["vault", "init"]).exit_code == 0
    assert r.invoke(cli, ["vault", "set", "OPENAI_API_KEY", "sk-cli"]).exit_code == 0
    listed = r.invoke(cli, ["vault", "list"])
    assert listed.exit_code == 0 and "OPENAI_API_KEY" in listed.output

    masked = r.invoke(cli, ["vault", "get", "OPENAI_API_KEY"])
    assert masked.exit_code == 0 and "sk-cli" not in masked.output  # masked
    revealed = r.invoke(cli, ["vault", "get", "OPENAI_API_KEY", "--reveal"])
    assert "sk-cli" in revealed.output


def test_cli_vault_import_env(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    _env(monkeypatch, tmp_path)
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-live")
    r = CliRunner()
    assert r.invoke(cli, ["vault", "init"]).exit_code == 0
    imp = r.invoke(cli, ["vault", "import-env"])
    assert imp.exit_code == 0 and "SHODAN_API_KEY" in imp.output

    listed = r.invoke(cli, ["vault", "list"])
    assert "SHODAN_API_KEY" in listed.output


def test_cli_vault_init_refuses_to_clobber(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from heaven.cli import cli
    _env(monkeypatch, tmp_path)
    r = CliRunner()
    assert r.invoke(cli, ["vault", "init"]).exit_code == 0
    second = r.invoke(cli, ["vault", "init"])
    assert second.exit_code == 1 and "already exists" in second.output
