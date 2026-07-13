"""Regression test: a key saved at runtime takes effect WITHOUT a restart.

The bug this guards against was general, not Gemini-specific: the web Settings
page (and `heaven config set`) write to `.env` + `os.environ`, but long-running
processes cache env-derived values in singletons built at startup — the LLM
gateway and the HeavenConfig object (NVD key, …). `apply_settings` must refresh
both so the operator doesn't have to restart `heaven serve` after adding a key.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def _isolated_env(tmp_path, monkeypatch):
    """Run apply_settings against a throwaway .env in a temp cwd."""
    monkeypatch.chdir(tmp_path)
    for key in ("NVD_API_KEY", "HEAVEN_NVD_API_KEY", "GEMINI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "HEAVEN_LLM_PROVIDER"):
        monkeypatch.delenv(key, raising=False)
    yield tmp_path


def test_runtime_key_add_refreshes_config_and_gateway(_isolated_env) -> None:
    from heaven.config import get_config, reload_config
    from heaven.ai.llm_gateway import get_gateway, reset_gateway
    from heaven.settings_catalog import apply_settings

    # Simulate a fresh server process: singletons built with no keys.
    reload_config()
    reset_gateway()
    assert get_config().api.nvd_api_key in (None, "")
    assert get_gateway().available is False

    # Operator adds keys at runtime (as the Settings page does).
    result = apply_settings({
        "NVD_API_KEY": "runtime-added-nvd-key",
        "GEMINI_API_KEY": "AIzaTESTkeyForWiringOnly0000000000000000",
    })
    assert set(result["changed"]) == {"NVD_API_KEY", "GEMINI_API_KEY"}

    # No restart: config + a freshly built client must see the new NVD key,
    # and the gateway must now resolve a provider.
    assert get_config().api.nvd_api_key == "runtime-added-nvd-key"
    from heaven.vulnscan.nvd_client import NVDClient
    assert NVDClient().api_key == "runtime-added-nvd-key"
    assert get_gateway().provider == "gemini"
    assert get_gateway().available is True


def test_no_changes_leaves_singletons_untouched(_isolated_env) -> None:
    """A no-op apply (same values) shouldn't churn — changed list is empty."""
    from heaven.settings_catalog import apply_settings
    os.environ["NVD_API_KEY"] = "already-set"
    try:
        result = apply_settings({"NVD_API_KEY": "already-set"})
        assert result["changed"] == []
    finally:
        os.environ.pop("NVD_API_KEY", None)


def test_gateway_self_heals_on_env_change_without_reset(_isolated_env) -> None:
    """The gateway must pick up a new key even if nobody calls reset_gateway().

    Belt-and-suspenders against a missed reset or a key set outside apply_settings:
    get_gateway() fingerprints its defining env vars and transparently rebuilds
    when they change, so a saved key always takes effect on the next AI call.
    """
    from heaven.ai.llm_gateway import get_gateway, reset_gateway

    reset_gateway()
    first = get_gateway()
    assert first.provider == ""          # no provider key present yet

    # Operator sets a key directly in the environment — no apply_settings, no reset.
    os.environ["GEMINI_API_KEY"] = "AIzaSelfHealTestKey000000000000000000000"
    try:
        second = get_gateway()
        assert second is not first           # stale cache was rebuilt, not reused
        assert second.provider == "gemini"   # new key picked up automatically
        assert get_gateway() is second       # stable when env is unchanged (no churn)
    finally:
        os.environ.pop("GEMINI_API_KEY", None)
        reset_gateway()
