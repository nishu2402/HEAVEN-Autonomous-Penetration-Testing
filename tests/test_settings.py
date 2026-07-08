"""HEAVEN — tests for the shared settings catalog + the /api/settings surface.

Covers the single-source-of-truth contract: the catalog masks secrets, rejects
unknown keys, persists to .env *and* os.environ, and the API exposes exactly the
same behaviour to the web-UI Settings page. A per-test tmp cwd + monkeypatched
env keeps every case isolated (no real .env or process env is mutated for long).
"""

from __future__ import annotations

import pytest


# ══════════════════════════════════════════════════════════════════
# Catalog (heaven/settings_catalog.py)
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Run in a throwaway cwd so resolve_env_path() targets tmp/.env, and clear
    the keys we touch so assertions start from a known state."""
    monkeypatch.chdir(tmp_path)
    for k in ("GEMINI_API_KEY", "HEAVEN_LLM_PROVIDER", "SHODAN_API_KEY", "WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def test_apply_writes_env_and_process(isolated):
    from heaven import settings_catalog as sc
    import os
    res = sc.apply_settings({"GEMINI_API_KEY": "AIzaSECRETKEY1234"})
    assert res["changed"] == ["GEMINI_API_KEY"]
    # process env updated immediately…
    assert os.environ["GEMINI_API_KEY"] == "AIzaSECRETKEY1234"
    # …and persisted to .env
    env = (isolated / ".env").read_text()
    assert "GEMINI_API_KEY=AIzaSECRETKEY1234" in env


def test_secret_is_masked_never_leaked(isolated):
    from heaven import settings_catalog as sc
    sc.apply_settings({"GEMINI_API_KEY": "AIzaSECRETKEY1234"})
    status = sc.catalog_status()
    entry = _find(status, "GEMINI_API_KEY")
    assert entry["is_set"] is True
    assert entry["secret"] is True
    assert entry["value"] == ""                      # full secret never returned
    assert entry["masked"] == "AIza…1234"            # only a preview
    assert "SECRETKEY" not in str(status)


def test_non_secret_value_returned_in_full(isolated):
    from heaven import settings_catalog as sc
    sc.apply_settings({"HEAVEN_LLM_PROVIDER": "gemini"})
    entry = _find(sc.catalog_status(), "HEAVEN_LLM_PROVIDER")
    assert entry["secret"] is False
    assert entry["value"] == "gemini"
    assert entry["masked"] == "gemini"


def test_empty_value_unsets_key(isolated):
    from heaven import settings_catalog as sc
    import os
    sc.apply_settings({"SHODAN_API_KEY": "abc123def456"})
    assert "SHODAN_API_KEY" in os.environ
    res = sc.apply_settings({"SHODAN_API_KEY": ""})
    assert res["changed"] == ["SHODAN_API_KEY"]
    assert "SHODAN_API_KEY" not in os.environ
    assert "SHODAN_API_KEY" not in (isolated / ".env").read_text()


def test_no_op_when_value_unchanged(isolated):
    from heaven import settings_catalog as sc
    sc.apply_settings({"WEBHOOK_URL": "https://hooks.example/abc"})
    res = sc.apply_settings({"WEBHOOK_URL": "https://hooks.example/abc"})
    assert res["changed"] == []


def test_unknown_key_rejected(isolated):
    from heaven import settings_catalog as sc
    with pytest.raises(ValueError, match="unknown setting"):
        sc.apply_settings({"NOT_A_REAL_KEY": "x"})


def test_mask_short_and_empty():
    from heaven.settings_catalog import mask
    assert mask("") == ""
    assert mask("short") == "•••••"           # <=8 chars fully dotted
    assert mask("AIzaSECRETKEY1234") == "AIza…1234"


def test_catalog_matches_init_optional_keys():
    # The wizard derives its optional prompts from the catalog — guard the link.
    from heaven.settings_catalog import VALID_KEYS
    from heaven.cli.init import _ENV_KEYS_ORDER
    assert VALID_KEYS <= set(_ENV_KEYS_ORDER)


# ══════════════════════════════════════════════════════════════════
# env_file.unset_env_var
# ══════════════════════════════════════════════════════════════════

def test_unset_env_var_preserves_other_lines(tmp_path):
    from heaven.utils.env_file import set_env_var, unset_env_var
    p = tmp_path / ".env"
    set_env_var(p, "KEEP_ME", "yes")
    set_env_var(p, "DROP_ME", "bye")
    unset_env_var(p, "DROP_ME")
    text = p.read_text()
    assert "KEEP_ME=yes" in text
    assert "DROP_ME" not in text


def test_unset_env_var_missing_file_is_noop(tmp_path):
    from heaven.utils.env_file import unset_env_var
    # Should not raise even when the file doesn't exist.
    unset_env_var(tmp_path / "nope.env", "ANY")


# ══════════════════════════════════════════════════════════════════
# API — /api/settings
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    monkeypatch.setenv("HEAVEN_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("HEAVEN_ADMIN_PASSWORD", "Known-Old-Passw0rd")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    import heaven.security.auth as auth_mod
    auth_mod._auth_manager = None
    try:
        from fastapi.testclient import TestClient
        from heaven.api.server import create_app
        yield TestClient(create_app())
    finally:
        auth_mod._auth_manager = None


def test_get_settings_lists_groups(client):
    r = client.get("/api/settings")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "groups" in data and data["groups"]
    keys = {s["key"] for g in data["groups"] for s in g["settings"]}
    assert {"GEMINI_API_KEY", "SHODAN_API_KEY", "HEAVEN_JIRA_URL"} <= keys


def test_post_settings_persists_and_masks(client, tmp_path):
    r = client.post("/api/settings", json={"settings": {"GEMINI_API_KEY": "AIzaWEBUIKEY9999"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["changed"] == ["GEMINI_API_KEY"]
    # masked in the returned status, full secret absent
    entry = _find(body["status"], "GEMINI_API_KEY")
    assert entry["is_set"] is True and entry["masked"] == "AIza…9999"
    assert "WEBUIKEY" not in r.text
    # actually written to .env
    assert "GEMINI_API_KEY=AIzaWEBUIKEY9999" in (tmp_path / ".env").read_text()


def test_post_settings_unknown_key_422(client):
    r = client.post("/api/settings", json={"settings": {"BOGUS_KEY": "x"}})
    assert r.status_code == 422, r.text


def test_test_llm_shape(client):
    r = client.post("/api/settings/test-llm")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"provider", "model", "available", "reason"}
    assert isinstance(body["available"], bool)


# ══════════════════════════════════════════════════════════════════
# CLI: `heaven config test-llm` (parity with the /api/settings/test-llm check)
# ══════════════════════════════════════════════════════════════════

def _invoke_test_llm(monkeypatch, fake_gw, args=()):
    """Invoke `config test-llm` with LLMGateway monkeypatched to fake_gw."""
    import heaven.ai.llm_gateway as gw_mod
    from click.testing import CliRunner

    from heaven.cli.config_cmd import config_grp
    monkeypatch.setattr(gw_mod, "LLMGateway", fake_gw)
    return CliRunner().invoke(config_grp, ["test-llm", *args])


def test_cli_test_llm_not_configured(monkeypatch):
    class _GW:  # no provider/key → unavailable
        provider = ""
        model = ""
        api_key = ""
        available = False

    r = _invoke_test_llm(monkeypatch, _GW)
    assert r.exit_code == 1
    assert "not configured" in r.output.lower()


def test_cli_test_llm_ready_cheap(monkeypatch):
    class _GW:
        provider = "anthropic"
        model = "claude-x"
        api_key = "sk-x"
        available = True

    r = _invoke_test_llm(monkeypatch, _GW)
    assert r.exit_code == 0
    assert "ready" in r.output.lower()
    # Cheap check must NOT make a call.
    assert "round-trip" not in r.output.lower()


def test_cli_test_llm_live_roundtrip(monkeypatch):
    class _Resp:
        text = "pong"
        error = None
        latency_ms = 12.3

        def ok(self):
            return True

    class _GW:
        provider = "openai"
        model = "gpt-x"
        api_key = "sk-x"
        available = True

        def complete(self, req):
            return _Resp()

    r = _invoke_test_llm(monkeypatch, _GW, args=["--live"])
    assert r.exit_code == 0
    assert "pong" in r.output.lower()


def test_cli_test_llm_live_failure_exits_nonzero(monkeypatch):
    class _Resp:
        text = ""
        error = "exhausted retries: 401 unauthorized"
        latency_ms = 5.0

        def ok(self):
            return False

    class _GW:
        provider = "openai"
        model = "gpt-x"
        api_key = "sk-bad"
        available = True

        def complete(self, req):
            return _Resp()

    r = _invoke_test_llm(monkeypatch, _GW, args=["--live"])
    assert r.exit_code == 1
    assert "failed" in r.output.lower()


# ── helper ──

def _find(status: dict, key: str) -> dict:
    for g in status["groups"]:
        for s in g["settings"]:
            if s["key"] == key:
                return s
    raise AssertionError(f"{key} not in catalog status")
