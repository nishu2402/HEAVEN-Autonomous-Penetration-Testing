"""Dynamic AI model discovery: live provider rosters merged with the curated set.

The Settings model picker used to show only a hand-picked 2-4 models per provider.
It now discovers each provider's real, current model list live from its API and
merges it with the curated recommended short-list. These tests pin that behavior:
offline safety, the merge rules, per-provider response parsing, the key never
leaking into a URL, and the endpoint's source/cache/refresh contract.
"""
from __future__ import annotations

import httpx
import pytest

from heaven.ai import llm_gateway as gw


class _FakeResp:
    def __init__(self, data):
        self._d = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


def _router(routes):
    """Build a fake httpx.get that returns a canned JSON per URL substring, and
    records the (url, headers, params) of every call."""
    calls = []

    def _get(url, headers=None, params=None, timeout=None):
        calls.append({"url": url, "headers": headers or {}, "params": params or {}})
        for sub, data in routes:
            if sub in url:
                return _FakeResp(data)
        raise AssertionError(f"unexpected url {url}")

    _get.calls = calls  # type: ignore[attr-defined]
    return _get


@pytest.fixture(autouse=True)
def _clear_model_cache():
    gw._MODELS_CACHE.clear()
    yield
    gw._MODELS_CACHE.clear()


@pytest.fixture(autouse=True)
def _no_provider_keys(monkeypatch):
    # A clean slate so "no key -> curated" holds regardless of the dev's env.
    for env in set(gw.PROVIDER_KEY_ENVS.values()):
        if env:
            monkeypatch.delenv(env, raising=False)
    monkeypatch.delenv("HEAVEN_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("HEAVEN_LLM_MODEL", raising=False)
    monkeypatch.delenv("HEAVEN_LLM_BASE_URL", raising=False)


# ── offline safety ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("provider",
                         ["anthropic", "openai", "gemini", "deepseek", "ollama", "local"])
def test_fetch_live_models_offline_never_raises(provider, monkeypatch):
    # No key, and any network attempt blows up -> must degrade to [] silently.
    def _boom(*a, **k):
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", _boom)
    assert gw.fetch_live_models(provider, "") == []
    # And the picker is still populated because merge falls back to curated.
    merged = gw.merge_models(gw.known_models(provider), [])
    assert isinstance(merged, list)


# ── merge semantics ──────────────────────────────────────────────────────────

def test_merge_recommended_first_and_dedup():
    curated = gw.known_models("openai")            # gpt-4o, gpt-4o-mini, o3-mini
    live = [{"id": "gpt-4o", "label": "gpt-4o", "note": ""},   # dup of curated
            {"id": "gpt-4.1", "label": "gpt-4.1", "note": ""}]  # new
    merged = gw.merge_models(curated, live)
    ids = [m["id"] for m in merged]
    # curated recommended come first, in order
    assert ids[:3] == ["gpt-4o", "gpt-4o-mini", "o3-mini"]
    assert all(m["recommended"] for m in merged[:3])
    # the new live model is appended once; the dup is not duplicated
    assert ids.count("gpt-4o") == 1
    assert ids[-1] == "gpt-4.1"
    assert merged[-1].get("recommended") is not True


def test_merge_folds_installed_marker_into_curated_note():
    curated = gw.known_models("ollama")
    live = [{"id": "qwen2.5:7b", "label": "qwen2.5:7b", "note": "installed"},
            {"id": "custom:latest", "label": "custom:latest", "note": "installed"}]
    merged = gw.merge_models(curated, live)
    qwen = next(m for m in merged if m["id"] == "qwen2.5:7b")
    assert "installed" in qwen["note"] and "Recommended" in qwen["note"]
    assert any(m["id"] == "custom:latest" for m in merged)


# ── per-provider live parsing ────────────────────────────────────────────────

def test_live_anthropic_paginates_and_uses_display_name(monkeypatch):
    page1 = {"data": [{"id": "claude-opus-5", "display_name": "Claude Opus 5"}],
             "has_more": True, "last_id": "cur1"}
    page2 = {"data": [{"id": "claude-3-5-haiku-20241022", "display_name": "Haiku 3.5"}],
             "has_more": False, "last_id": "cur2"}
    seq = iter([page1, page2])

    def _get(url, headers=None, params=None, timeout=None):
        assert headers.get("x-api-key") == "KEY"
        assert headers.get("anthropic-version")
        return _FakeResp(next(seq))

    monkeypatch.setattr(httpx, "get", _get)
    live = gw._fetch_live_uncached("anthropic", "KEY", 5.0)
    ids = [m["id"] for m in live]
    assert ids == ["claude-opus-5", "claude-3-5-haiku-20241022"]
    assert live[0]["label"] == "Claude Opus 5"


def test_live_openai_filters_non_chat(monkeypatch):
    data = {"data": [{"id": x} for x in [
        "gpt-4o", "gpt-4.1", "o3", "chatgpt-4o-latest",
        "text-embedding-3-large", "whisper-1", "dall-e-3", "tts-1",
        "gpt-3.5-turbo-instruct", "omni-moderation-latest"]]}
    monkeypatch.setattr(httpx, "get", _router([("api.openai.com", data)]))
    ids = [m["id"] for m in gw._fetch_live_uncached("openai", "KEY", 5.0)]
    assert {"gpt-4o", "gpt-4.1", "o3", "chatgpt-4o-latest"} <= set(ids)
    for bad in ("text-embedding-3-large", "whisper-1", "dall-e-3", "tts-1",
                "gpt-3.5-turbo-instruct", "omni-moderation-latest"):
        assert bad not in ids


def test_live_gemini_filters_to_generate_content_and_key_in_header(monkeypatch):
    data = {"models": [
        {"name": "models/gemini-2.5-pro", "displayName": "Gemini 2.5 Pro",
         "supportedGenerationMethods": ["generateContent"]},
        {"name": "models/text-embedding-004", "displayName": "Embed",
         "supportedGenerationMethods": ["embedContent"]},
    ]}
    router = _router([("generativelanguage.googleapis.com", data)])
    monkeypatch.setattr(httpx, "get", router)
    live = gw._fetch_live_uncached("gemini", "SECRETKEY", 5.0)
    ids = [m["id"] for m in live]
    assert ids == ["gemini-2.5-pro"]              # embed-only dropped, models/ stripped
    call = router.calls[0]
    # Privacy: the key rides the header, never the URL or query string.
    assert call["headers"].get("x-goog-api-key") == "SECRETKEY"
    assert "SECRETKEY" not in call["url"]
    assert "SECRETKEY" not in str(call["params"])


def test_live_deepseek_openai_compatible(monkeypatch):
    data = {"data": [{"id": "deepseek-chat"}, {"id": "deepseek-reasoner"},
                     {"id": "deepseek-coder"}]}
    monkeypatch.setattr(httpx, "get", _router([("api.deepseek.com", data)]))
    ids = [m["id"] for m in gw._fetch_live_uncached("deepseek", "KEY", 5.0)]
    assert "deepseek-coder" in ids


# ── caching ──────────────────────────────────────────────────────────────────

def test_cache_serves_repeat_and_refresh_bypasses(monkeypatch):
    data = {"data": [{"id": "gpt-4o"}, {"id": "gpt-4.1"}]}
    router = _router([("api.openai.com", data)])
    monkeypatch.setattr(httpx, "get", router)
    gw.fetch_live_models("openai", "KEY")
    assert len(router.calls) == 1
    gw.fetch_live_models("openai", "KEY")            # cached -> no new call
    assert len(router.calls) == 1
    gw.fetch_live_models("openai", "KEY", use_cache=False)  # forced refresh
    assert len(router.calls) == 2


def test_empty_result_is_not_cached(monkeypatch):
    # A transient blank must not pin an empty roster for the whole TTL.
    calls = {"n": 0}

    def _get(url, headers=None, params=None, timeout=None):
        calls["n"] += 1
        return _FakeResp({"data": []})

    monkeypatch.setattr(httpx, "get", _get)
    assert gw.fetch_live_models("openai", "KEY") == []
    assert gw.fetch_live_models("openai", "KEY") == []
    assert calls["n"] == 2   # not cached, so it retried


# ── endpoint contract ────────────────────────────────────────────────────────

def _client(monkeypatch):
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")
    from fastapi.testclient import TestClient

    from heaven.api.server import create_app
    return TestClient(create_app())


def test_endpoint_marks_live_vs_curated(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")   # openai becomes "keyed"
    data = {"data": [{"id": "gpt-4o"}, {"id": "gpt-4.1"}, {"id": "o3"}]}

    def _get(url, headers=None, params=None, timeout=None):
        if "openai.com" in url:
            return _FakeResp(data)
        return _FakeResp({"data": [], "models": []})

    monkeypatch.setattr(httpx, "get", _get)
    with _client(monkeypatch) as c:
        body = c.get("/api/ai/models").json()
    oi = body["providers"]["openai"]
    assert oi["source"] == "live" and oi["live_count"] == 3
    ids = [m["id"] for m in oi["models"]]
    assert "gpt-4.1" in ids and "o3" in ids
    assert ids[0] == "gpt-4o"                         # curated recommended first
    # No key for anthropic -> the broader offline catalog (NOT just the curated
    # short-list), so the picker is still comprehensive before a key is set.
    anth = body["providers"]["anthropic"]
    assert anth["source"] == "catalog" and anth["live_count"] == 0
    assert len(anth["models"]) > len(gw.known_models("anthropic"))
    anth_ids = [m["id"] for m in anth["models"]]
    assert anth_ids[0] == "claude-opus-5"             # curated recommended first
    assert any(m.get("recommended") for m in anth["models"][:3])
    assert "claude-opus-4-8" in anth_ids              # catalog-only extra present


# ── resolver ladder (live → catalog → curated) ───────────────────────────────

def test_resolve_falls_back_to_catalog_without_key(monkeypatch):
    # No key and no network: cloud providers with a published family return the
    # broader catalog, not the 2-4 curated basics.
    def _boom(*a, **k):
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", _boom)
    for prov in ("anthropic", "openai", "gemini"):
        models, source, live_count = gw.resolve_picker_models(prov, "")
        assert source == "catalog" and live_count == 0
        assert len(models) > len(gw.known_models(prov))
        # recommended picks stay starred and lead the list
        assert models[0].get("recommended") is True


def test_resolve_live_supersedes_catalog(monkeypatch):
    data = {"data": [{"id": "gpt-4o"}, {"id": "gpt-9-turbo"}]}
    monkeypatch.setattr(httpx, "get", _router([("api.openai.com", data)]))
    models, source, live_count = gw.resolve_picker_models("openai", "KEY")
    assert source == "live" and live_count == 2
    assert any(m["id"] == "gpt-9-turbo" for m in models)   # live-only id present


def test_resolve_deepseek_and_local_are_curated(monkeypatch):
    # DeepSeek has no broader catalog (it serves only two models) and 'local' has
    # no curated list, so both resolve to 'curated' when nothing is discovered.
    def _boom(*a, **k):
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", _boom)
    _, ds_source, _ = gw.resolve_picker_models("deepseek", "")
    assert ds_source == "curated"
    local_models, local_source, _ = gw.resolve_picker_models("local", "")
    assert local_source == "curated" and local_models == []
