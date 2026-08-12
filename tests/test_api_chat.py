"""API tests for the AI assistant + local-LLM status endpoints.

Mocks the assistant so no real LLM is contacted. Mirrors the auth-disabled
TestClient fixture used by test_settings.py.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("aiohttp")


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


def test_chat_requires_messages(client):
    r = client.post("/api/chat", json={"messages": []})
    assert r.status_code == 422, r.text


def test_chat_reply_ok(client, monkeypatch):
    import heaven.ai.chat_assistant as ca
    from heaven.ai.llm_gateway import LLMResponse
    monkeypatch.setattr(ca.ChatAssistant, "available", property(lambda self: True))
    monkeypatch.setattr(
        ca.ChatAssistant, "reply",
        lambda self, messages, **kw: LLMResponse(text="hi there", provider="ollama",
                                                 model="qwen2.5:7b"),
    )
    r = client.post("/api/chat",
                    json={"messages": [{"role": "user", "content": "hello"}], "grounded": False})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["reply"] == "hi there"
    assert d["provider"] == "ollama" and d["model"] == "qwen2.5:7b"


def test_chat_reply_skipped_when_no_llm(client, monkeypatch):
    import heaven.ai.chat_assistant as ca
    monkeypatch.setattr(ca.ChatAssistant, "available", property(lambda self: False))
    r = client.post("/api/chat",
                    json={"messages": [{"role": "user", "content": "x"}], "grounded": False})
    assert r.status_code == 200, r.text
    assert "skipped" in r.json()


def test_ai_local_status_shape(client):
    r = client.get("/api/ai/local/status")
    assert r.status_code == 200, r.text
    d = r.json()
    for key in ("installed", "reachable", "host", "models", "recommended", "default_model"):
        assert key in d


# ── POST /api/ai/local/configure — one-click web setup ──

def test_ai_local_configure_ollama_applies_and_tests(client, monkeypatch):
    import heaven.ai.llm_gateway as gw_mod
    import heaven.ai.local_llm as L
    import heaven.settings_catalog as sc
    from heaven.ai.llm_gateway import LLMResponse

    captured: dict = {}
    monkeypatch.setattr(sc, "apply_settings",
                        lambda updates: captured.update(updates) or {"changed": list(updates)})

    class _GW:
        provider, model, available, _init_error = "ollama", "qwen2.5:7b", True, ""

        async def acomplete(self, req):
            return LLMResponse(text="OK", provider="ollama", model="qwen2.5:7b", latency_ms=9.0)

    monkeypatch.setattr(gw_mod, "LLMGateway", lambda *a, **k: _GW())
    monkeypatch.setattr(gw_mod, "reset_gateway", lambda: None)
    monkeypatch.setattr(L, "local_status", lambda provider="ollama", base_url="": {
        "provider": provider, "installed": True, "reachable": True,
        "models": ["qwen2.5:7b"], "host": "http://localhost:11434",
        "default_model": "qwen2.5:7b", "recommended": []})

    r = client.post("/api/ai/local/configure", json={"provider": "ollama", "model": "qwen2.5:7b"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] and d["provider"] == "ollama" and d["model"] == "qwen2.5:7b"
    assert d["test"]["available"] is True
    assert captured["HEAVEN_LLM_PROVIDER"] == "ollama"
    assert captured["HEAVEN_LLM_MODEL"] == "qwen2.5:7b"
    assert "HEAVEN_OLLAMA_HOST" in captured


def test_ai_local_configure_rejects_unknown_provider(client):
    r = client.post("/api/ai/local/configure", json={"provider": "gpt-9000"})
    assert r.status_code == 422, r.text


def test_ai_local_configure_local_requires_base_url(client):
    r = client.post("/api/ai/local/configure", json={"provider": "local", "model": "m"})
    assert r.status_code == 422, r.text


# ── WS /api/ai/local/pull — streamed model pull for the web wizard ──

def test_ai_local_pull_streams_progress_then_done(client, monkeypatch):
    import json as _json

    import httpx

    import heaven.ai.local_llm as L
    monkeypatch.setattr(L, "list_models", lambda timeout=3.0: ["qwen2.5:7b"])
    monkeypatch.setattr(L, "ollama_host", lambda: "http://localhost:11434")

    class _Resp:
        status_code = 200

        def __init__(self, lines):
            self._lines = lines

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def aread(self):
            return b""

        async def aiter_lines(self):
            for ln in self._lines:
                yield ln

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, json=None):
            return _Resp([
                _json.dumps({"status": "pulling abc", "completed": 10, "total": 100}),
                _json.dumps({"status": "success"}),
            ])

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    with client.websocket_connect("/api/ai/local/pull") as ws:
        ws.send_json({"model": "qwen2.5:7b"})
        frames = []
        while True:
            f = ws.receive_json()
            frames.append(f)
            if f.get("type") == "done":
                break
    types = [f["type"] for f in frames]
    assert "progress" in types
    prog = next(f for f in frames if f["type"] == "progress")
    assert prog["percent"] == 10.0
    done = frames[-1]
    assert done["type"] == "done" and done["ok"] is True
    assert done["models"] == ["qwen2.5:7b"]


def test_ai_local_pull_rejects_empty_model(client):
    with client.websocket_connect("/api/ai/local/pull") as ws:
        ws.send_json({"model": ""})
        f = ws.receive_json()
        assert f["type"] == "error"
