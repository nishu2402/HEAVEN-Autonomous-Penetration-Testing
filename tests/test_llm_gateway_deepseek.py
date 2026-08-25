"""Regression tests for first-class DeepSeek support in the LLM gateway.

DeepSeek is a remote, OpenAI-compatible cloud API (https://api-docs.deepseek.com/).
It rides the shared httpx `/chat/completions` path (`_call_local`/`_stream_local`)
with zero extra SDK, but keeps CLOUD semantics: it needs a key, it is NOT in
LOCAL_PROVIDERS, transient errors are retried, and the rate-limit circuit breaker
applies. All mocked — no real network call. Pins:
  * provider selection + auto-detect from DEEPSEEK_API_KEY;
  * default base URL https://api.deepseek.com, overridable via DEEPSEEK_BASE_URL;
  * curated model list (deepseek-chat / deepseek-reasoner);
  * the API key rides an Authorization header only — never the request body;
  * mocked completion parses the OpenAI shape; mocked streaming parses SSE deltas;
  * the deterministic hybrid fallback and the 429 rate-limit breaker still fire;
  * the singleton fingerprint tracks DEEPSEEK_API_KEY / DEEPSEEK_BASE_URL.
"""
from __future__ import annotations

import json

import pytest

from heaven.ai.llm_gateway import (
    DEFAULT_DEEPSEEK_BASE_URL,
    OPENAI_HTTP_PROVIDERS,
    LLMGateway,
    LLMProviderError,
    LLMRequest,
    LLMResponse,
    _env_fingerprint,
    _local_base_url,
    known_models,
)

_CLOUD_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY")


# ── fakes ──────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


class _CapClient:
    """Captures the URL + payload of each POST; returns fixed content."""

    def __init__(self, content="ok"):
        self.content = content
        self.calls: list[dict] = []

    def post(self, url, json=None):
        self.calls.append({"url": url, "json": dict(json) if json else json})
        return _Resp({
            "choices": [{"message": {"content": self.content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        })


class _ExcClient:
    def __init__(self, exc):
        self._exc = exc

    def post(self, url, json=None):
        raise self._exc


def _bare_deepseek(model="deepseek-chat", base=DEFAULT_DEEPSEEK_BASE_URL):
    """A minimally-populated DeepSeek gateway for the low-level _call_local path."""
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "deepseek"
    gw.model = model
    gw._local_base = base
    gw._is_local = False        # DeepSeek is a remote cloud provider, not local
    return gw


def _clear_cloud_keys(monkeypatch):
    for k in _CLOUD_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("HEAVEN_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("HEAVEN_LLM_MODEL", raising=False)
    monkeypatch.delenv("HEAVEN_LLM_FALLBACK_PROVIDER", raising=False)
    monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)


# ── provider selection + config ──────────────────────────────────────────────
def test_deepseek_is_an_openai_http_provider_but_not_local():
    assert "deepseek" in OPENAI_HTTP_PROVIDERS
    from heaven.ai.llm_gateway import LOCAL_PROVIDERS
    assert "deepseek" not in LOCAL_PROVIDERS


def test_deepseek_selected_and_available(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-not-real")
    gw = LLMGateway(provider="deepseek")
    assert gw.available
    assert gw.provider == "deepseek"
    assert gw.model == "deepseek-chat"      # default when no override
    assert gw._is_local is False            # cloud semantics
    assert gw._local_base == DEFAULT_DEEPSEEK_BASE_URL


def test_deepseek_not_available_without_key(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    gw = LLMGateway(provider="deepseek")
    assert not gw.available                 # a cloud provider needs its key


def test_deepseek_autodetected_from_key(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-not-real")
    # No HEAVEN_LLM_PROVIDER set → auto-detect must pick deepseek off its key.
    gw = LLMGateway()
    assert gw.provider == "deepseek" and gw.available


def test_deepseek_base_url_default_and_override(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
    assert _local_base_url("deepseek") == "https://api.deepseek.com"
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://proxy.example.com/v1/")
    assert _local_base_url("deepseek") == "https://proxy.example.com/v1"  # trailing slash trimmed


def test_deepseek_known_models():
    ids = [m["id"] for m in known_models("deepseek")]
    assert ids == ["deepseek-chat", "deepseek-reasoner"]


def test_fingerprint_tracks_deepseek_env(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    base = _env_fingerprint()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-not-real")
    f1 = _env_fingerprint()
    assert f1 != base
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://proxy.example.com")
    assert _env_fingerprint() != f1


# ── secret hygiene: key in header, never in the request body ─────────────────
def test_deepseek_key_rides_auth_header_not_body(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    secret = "sk-deepseek-super-secret-123"
    monkeypatch.setenv("DEEPSEEK_API_KEY", secret)
    gw = LLMGateway(provider="deepseek")
    assert gw.available
    # The real httpx client carries the bearer token as a header.
    assert gw._client.headers.get("authorization") == f"Bearer {secret}"
    # Swap in a capture client and confirm the key never appears in the POST body,
    # and the endpoint is {base}/chat/completions.
    cap = _CapClient('{"ok": true}')
    gw._client = cap
    gw._call_local("hello", "sys", LLMRequest(prompt="hello", redact_secrets=False))
    assert cap.calls[-1]["url"] == "https://api.deepseek.com/chat/completions"
    assert secret not in json.dumps(cap.calls[-1]["json"])


# ── mocked completion + streaming (reuse the OpenAI-compatible path) ─────────
def test_deepseek_completion_parses_openai_shape():
    gw = _bare_deepseek()
    gw._client = _CapClient("hi from deepseek")
    r = gw._call_local("hi", "sys", LLMRequest(prompt="hi"))
    assert r.text == "hi from deepseek"
    assert r.provider == "deepseek" and r.model == "deepseek-chat"
    assert r.input_tokens == 5 and r.output_tokens == 2 and r.error is None


def test_deepseek_streaming_parses_sse_deltas():
    class _StreamResp:
        def __init__(self, lines):
            self._lines = lines

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        def iter_lines(self):
            yield from self._lines

    class _StreamClient:
        def __init__(self, lines):
            self._lines = lines

        def stream(self, method, url, json=None):
            return _StreamResp(self._lines)

    gw = _bare_deepseek()
    gw._client = _StreamClient([
        'data: {"choices":[{"delta":{"content":"Dee"}}]}',
        'data: {"choices":[{"delta":{"content":"pSeek"}}]}',
        "data: [DONE]",
    ])
    pieces = list(gw._stream_local("hi", None, LLMRequest(prompt="hi")))
    assert "".join(pieces) == "DeepSeek"


def test_deepseek_unreachable_message_names_provider():
    import httpx
    gw = _bare_deepseek()
    gw._client = _ExcClient(httpx.ConnectError("Connection refused"))
    with pytest.raises(LLMProviderError) as ei:
        gw._call_local("hi", None, LLMRequest(prompt="hi"))
    msg = str(ei.value).lower()
    assert "unreachable" in msg and "deepseek" in msg  # not "local LLM"


# ── preserved behavior: rate-limit breaker + deterministic hybrid fallback ───
def test_deepseek_429_arms_ratelimit_breaker(monkeypatch):
    _clear_cloud_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-not-real")
    gw = LLMGateway(provider="deepseek")
    assert gw.available
    calls = {"n": 0}

    def boom(prompt, system, req):
        calls["n"] += 1
        raise RuntimeError("429 Too Many Requests: rate limit exceeded, retry in 20s")

    gw._dispatch = boom
    resp = gw.complete(LLMRequest(prompt="hi"))
    assert not resp.ok()
    assert calls["n"] == 1                       # 429 fails fast, no 3× retry
    assert gw._ratelimit_gate() is not None      # breaker armed → later calls short-circuit


def test_deepseek_hybrid_fallback_used_when_primary_fails():
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "deepseek"
    gw.model = "deepseek-chat"
    gw._allow_fallback = True
    gw.fallback_provider = "ollama"
    gw._fallback_gw = None
    gw._complete_once = lambda req: LLMResponse(
        text="", provider="deepseek", model="deepseek-chat",
        error="deepseek endpoint unreachable")
    fb = LLMGateway.__new__(LLMGateway)
    fb.provider, fb.model, fb._client = "ollama", "qwen2.5:7b", object()
    fb.complete = lambda req: LLMResponse(text="from local fallback", provider="ollama",
                                          model="qwen2.5:7b")
    gw._get_fallback_gateway = lambda: fb
    r = gw.complete(LLMRequest(prompt="x"))
    assert r.text == "from local fallback" and r.provider == "ollama"
