"""Tests for heaven/ai/local_llm.py — the offline-safe Ollama helpers.

All mocked; no real Ollama server is contacted.
"""
from __future__ import annotations

from heaven.ai import local_llm as L


def test_default_model_is_the_documented_7b():
    assert L.DEFAULT_OLLAMA_MODEL == "qwen2.5:7b"


def test_install_hint_nonempty_string():
    hint = L.install_hint()
    assert isinstance(hint, str) and hint


def test_recommended_models_cover_tiers():
    models = {m["model"] for m in L.RECOMMENDED_MODELS}
    assert "qwen2.5:7b" in models and len(models) >= 3


def test_list_models_parses_tags(monkeypatch):
    monkeypatch.setattr(L, "_tags", lambda timeout: {
        "models": [{"name": "qwen2.5:7b"}, {"model": "llama3.1:8b"}]})
    assert L.list_models() == ["qwen2.5:7b", "llama3.1:8b"]
    assert L.ollama_reachable() is True


def test_tags_offline_returns_none(monkeypatch):
    import httpx

    def _boom(*a, **k):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "get", _boom)
    assert L._tags(0.1) is None
    assert L.ollama_reachable(0.1) is False
    assert L.list_models() == []


def test_local_status_offline_shape(monkeypatch):
    monkeypatch.setattr(L, "is_ollama_installed", lambda: False)
    st = L.local_status()
    assert st["provider"] == "ollama"
    assert st["installed"] is False
    assert st["models"] == []
    assert st["default_model"] == "qwen2.5:7b"
    assert st["recommended"]


def test_local_status_for_generic_endpoint(monkeypatch):
    monkeypatch.setattr(L, "endpoint_reachable", lambda base, timeout=2.0: True)
    st = L.local_status("local", "http://localhost:1234/v1")
    assert st["provider"] == "local"
    assert st["reachable"] is True
    assert st["host"] == "http://localhost:1234/v1"


# ── pull_progress_frame: normalize Ollama /api/pull streaming lines ──

def test_pull_frame_layer_download_computes_percent():
    f = L.pull_progress_frame({"status": "pulling abc123", "completed": 50, "total": 200})
    assert f["status"] == "pulling abc123"
    assert f["completed"] == 50 and f["total"] == 200
    assert f["percent"] == 25.0
    assert f["done"] is False and f["error"] == ""


def test_pull_frame_success_is_done():
    f = L.pull_progress_frame({"status": "success"})
    assert f["done"] is True and f["error"] == ""
    assert f["percent"] is None  # no total → no percent


def test_pull_frame_error_is_done_with_message():
    f = L.pull_progress_frame({"error": "model 'nope' not found"})
    assert f["done"] is True
    assert "not found" in f["error"]


def test_pull_frame_phase_line_without_totals():
    f = L.pull_progress_frame({"status": "verifying sha256 digest"})
    assert f["status"] == "verifying sha256 digest"
    assert f["percent"] is None and f["done"] is False


def test_pull_frame_is_total_safe_on_junk():
    # Never raises, even on garbage/None values.
    f = L.pull_progress_frame({"status": None, "completed": "x", "total": None})
    assert f["completed"] == 0 and f["total"] == 0 and f["percent"] is None
    assert L.pull_progress_frame("not-a-dict")["status"] == ""  # type: ignore[arg-type]
