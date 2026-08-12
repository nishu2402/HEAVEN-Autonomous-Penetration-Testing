"""Regression tests for the local-LLM providers (ollama / local) + streaming +
hybrid fallback added to heaven/ai/llm_gateway.py.

All mocked — no real Ollama server or network call. Pins:
  * ollama/local providers select, resolve their base URL, and are keyless-available;
  * _call_local parses the OpenAI-compatible shape and raises a distinct
    'unreachable' error when the endpoint is down (so complete() fails fast);
  * the singleton fingerprint tracks the new env vars;
  * hybrid fallback kicks in only when configured and the primary result is bad;
  * stream() falls back to a single chunk when native streaming errors, and
    _stream_local parses SSE deltas.
"""
from __future__ import annotations

import pytest

from heaven.ai.llm_gateway import (
    LLMGateway,
    LLMProviderError,
    LLMRequest,
    LLMResponse,
    _env_fingerprint,
    _local_base_url,
)


# ── fakes ──────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


class _Client:
    def __init__(self, resp=None, exc=None):
        self._resp, self._exc = resp, exc

    def post(self, url, json=None):
        if self._exc:
            raise self._exc
        return self._resp


def _bare(provider="ollama", model="qwen2.5:7b", base="http://localhost:11434/v1"):
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = provider
    gw.model = model
    gw._local_base = base
    gw._is_local = True
    return gw


# ── base-url resolution ─────────────────────────────────────────────────────
def test_ollama_base_url_default(monkeypatch):
    monkeypatch.delenv("HEAVEN_OLLAMA_HOST", raising=False)
    assert _local_base_url("ollama") == "http://localhost:11434/v1"


def test_ollama_base_url_env_and_trailing_slash(monkeypatch):
    monkeypatch.setenv("HEAVEN_OLLAMA_HOST", "http://box:11434/")
    assert _local_base_url("ollama") == "http://box:11434/v1"


def test_local_base_url_from_env(monkeypatch):
    monkeypatch.setenv("HEAVEN_LLM_BASE_URL", "http://host:1234/v1/")
    assert _local_base_url("local") == "http://host:1234/v1"


# ── keyless availability + config gates ─────────────────────────────────────
def test_ollama_is_keyless_available():
    gw = LLMGateway(provider="ollama", model="qwen2.5:7b")
    assert gw.available and gw._is_local
    assert gw._local_base.endswith("/v1")


def test_local_requires_base_url(monkeypatch):
    monkeypatch.delenv("HEAVEN_LLM_BASE_URL", raising=False)
    gw = LLMGateway(provider="local", model="m")
    assert not gw.available and "endpoint" in (gw._init_error or "")


def test_local_requires_model(monkeypatch):
    monkeypatch.setenv("HEAVEN_LLM_BASE_URL", "http://host/v1")
    gw = LLMGateway(provider="local", model="")
    assert not gw.available and "model" in (gw._init_error or "")


# ── _call_local: parse + unreachable ────────────────────────────────────────
def test_call_local_parses_openai_shape():
    gw = _bare()
    gw._client = _Client(resp=_Resp({
        "choices": [{"message": {"content": "hello world"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3},
    }))
    r = gw._call_local("hi", "sys", LLMRequest(prompt="hi"))
    assert r.text == "hello world"
    assert r.input_tokens == 7 and r.output_tokens == 3 and r.error is None


def test_call_local_unreachable_raises_clear_error():
    import httpx
    gw = _bare()
    gw._client = _Client(exc=httpx.ConnectError("Connection refused"))
    with pytest.raises(LLMProviderError) as ei:
        gw._call_local("hi", None, LLMRequest(prompt="hi"))
    assert "unreachable" in str(ei.value).lower()


@pytest.mark.parametrize("msg, expected", [
    ("Connection refused", True),
    ("connection reset by peer", True),
    ("read timeout", True),
    ("nodename nor servname provided", True),
    ("quota exceeded", False),
    ("bad request", False),
])
def test_is_local_unreachable_classifier(msg, expected):
    assert LLMGateway._is_local_unreachable(RuntimeError(msg)) is expected


# ── singleton fingerprint tracks the new env vars ───────────────────────────
def test_fingerprint_tracks_local_env_vars(monkeypatch):
    for k in ("HEAVEN_OLLAMA_HOST", "HEAVEN_LLM_BASE_URL", "HEAVEN_LLM_FALLBACK_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    base = _env_fingerprint()
    monkeypatch.setenv("HEAVEN_OLLAMA_HOST", "http://newhost:11434")
    f1 = _env_fingerprint()
    assert f1 != base
    monkeypatch.setenv("HEAVEN_LLM_FALLBACK_PROVIDER", "gemini")
    f2 = _env_fingerprint()
    assert f2 != f1
    monkeypatch.setenv("HEAVEN_LLM_BASE_URL", "http://host/v1")
    assert _env_fingerprint() != f2


# ── hybrid fallback ─────────────────────────────────────────────────────────
def _fallback_primary(fallback_provider):
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "ollama"
    gw.model = "m"
    gw._allow_fallback = True
    gw.fallback_provider = fallback_provider
    gw._fallback_gw = None
    gw._complete_once = lambda req: LLMResponse(
        text="", provider="ollama", model="m", error="local LLM unreachable")
    return gw


def test_hybrid_fallback_used_when_primary_fails():
    gw = _fallback_primary("gemini")
    fb = LLMGateway.__new__(LLMGateway)
    fb.provider, fb.model, fb._client = "gemini", "g", object()
    fb.complete = lambda req: LLMResponse(text="from fallback", provider="gemini", model="g")
    gw._get_fallback_gateway = lambda: fb
    r = gw.complete(LLMRequest(prompt="x"))
    assert r.text == "from fallback" and r.provider == "gemini"


def test_no_fallback_when_unconfigured():
    gw = _fallback_primary("")   # no fallback provider set
    r = gw.complete(LLMRequest(prompt="x"))
    assert not r.ok() and "unreachable" in (r.error or "")


# ── streaming ───────────────────────────────────────────────────────────────
def test_stream_falls_back_to_single_chunk_on_native_error():
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider, gw.model, gw._client = "ollama", "m", object()
    gw._ratelimited_until = 0.0

    def _boom(prompt, system, req):
        raise RuntimeError("no native stream")
    gw._dispatch_stream = _boom
    gw.complete = lambda req: LLMResponse(text="FULL ANSWER", provider="ollama", model="m")

    chunks = list(gw.stream(LLMRequest(prompt="hi", redact_secrets=False)))
    assert chunks == ["FULL ANSWER"]


def test_stream_local_parses_sse_deltas():
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

    gw = _bare()
    gw._client = _StreamClient([
        'data: {"choices":[{"delta":{"content":"He"}}]}',
        'data: {"choices":[{"delta":{"content":"llo"}}]}',
        "data: [DONE]",
    ])
    pieces = list(gw._stream_local("hi", None, LLMRequest(prompt="hi")))
    assert "".join(pieces) == "Hello"
