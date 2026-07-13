"""Regression tests for the Anthropic and OpenAI paths of the LLM gateway.

The Gemini bug (empty output that silently fell back to non-LLM behaviour) had a
general lesson: every provider must (a) receive the prepared, schema-carrying
system prompt, and (b) report *why* a response was empty instead of returning a
silent blank. OpenAI additionally must tolerate the reasoning-model parameter
rename (max_tokens → max_completion_tokens) so a pinned newer model still works.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from heaven.ai.llm_gateway import LLMGateway, LLMRequest


# ── Anthropic ────────────────────────────────────────────────────────────────

class _FakeAnthropicMessages:
    def __init__(self, content: list[Any], stop_reason: str = "end_turn") -> None:
        self._content = content
        self._stop_reason = stop_reason
        self.captured: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> Any:
        self.captured = kwargs
        return SimpleNamespace(
            content=self._content, stop_reason=self._stop_reason,
            usage=SimpleNamespace(input_tokens=3, output_tokens=5,
                                  cache_read_input_tokens=0),
        )


class _FakeAnthropicClient:
    def __init__(self, content: list[Any], stop_reason: str = "end_turn") -> None:
        self.messages = _FakeAnthropicMessages(content, stop_reason)


def _anthropic_gateway(client: _FakeAnthropicClient) -> LLMGateway:
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "anthropic"
    gw.model = "claude-sonnet-5"
    gw.api_key = "test"
    gw._init_error = None
    gw._client = client
    return gw


def test_anthropic_receives_prepared_system_and_returns_text() -> None:
    block = SimpleNamespace(type="text", text="hello")
    client = _FakeAnthropicClient([block])
    gw = _anthropic_gateway(client)
    resp = gw.complete(LLMRequest(prompt="hi", system="You are a bot."))
    assert resp.ok()
    assert resp.text == "hello"
    assert client.messages.captured["system"] == "You are a bot."


def test_anthropic_empty_surfaces_stop_reason() -> None:
    client = _FakeAnthropicClient([], stop_reason="max_tokens")
    gw = _anthropic_gateway(client)
    resp = gw.complete(LLMRequest(prompt="hi"))
    assert not resp.ok()
    assert resp.error and "max_tokens" in resp.error


# ── OpenAI ───────────────────────────────────────────────────────────────────

class _FakeOpenAICompletions:
    def __init__(self, text: str | None, finish: str = "stop",
                 refusal: str | None = None, reject_max_tokens: bool = False) -> None:
        self._text = text
        self._finish = finish
        self._refusal = refusal
        self._reject_max_tokens = reject_max_tokens
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self._reject_max_tokens and "max_tokens" in kwargs:
            raise TypeError(
                "Unsupported parameter: 'max_tokens' is not supported with this "
                "model. Use 'max_completion_tokens' instead."
            )
        msg = SimpleNamespace(content=self._text, refusal=self._refusal)
        choice = SimpleNamespace(message=msg, finish_reason=self._finish)
        return SimpleNamespace(
            choices=[choice],
            usage=SimpleNamespace(prompt_tokens=4, completion_tokens=6),
        )


class _FakeOpenAIClient:
    def __init__(self, completions: _FakeOpenAICompletions) -> None:
        self.chat = SimpleNamespace(completions=completions)


def _openai_gateway(completions: _FakeOpenAICompletions, model: str = "gpt-4o") -> LLMGateway:
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "openai"
    gw.model = model
    gw.api_key = "test"
    gw._init_error = None
    gw._client = _FakeOpenAIClient(completions)
    return gw


def test_openai_happy_path() -> None:
    comp = _FakeOpenAICompletions("answer")
    gw = _openai_gateway(comp)
    resp = gw.complete(LLMRequest(prompt="q", system="sys"))
    assert resp.ok()
    assert resp.text == "answer"
    # prepared system reaches the model as a system message
    assert comp.calls[0]["messages"][0] == {"role": "system", "content": "sys"}


def test_openai_retries_with_max_completion_tokens() -> None:
    """A reasoning model rejecting max_tokens must be retried, not failed."""
    comp = _FakeOpenAICompletions("answer", reject_max_tokens=True)
    gw = _openai_gateway(comp, model="gpt-5")
    resp = gw.complete(LLMRequest(prompt="q", max_tokens=100))
    assert resp.ok()
    assert resp.text == "answer"
    assert "max_tokens" in comp.calls[0]
    assert "max_completion_tokens" in comp.calls[1]


def test_openai_refusal_surfaces_reason() -> None:
    comp = _FakeOpenAICompletions(None, finish="content_filter", refusal="I can't help with that")
    gw = _openai_gateway(comp)
    resp = gw.complete(LLMRequest(prompt="q"))
    assert not resp.ok()
    assert resp.error and "refused" in resp.error


# ── Retry classification ─────────────────────────────────────────────────────

def _bare_gateway() -> LLMGateway:
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "gemini"
    gw.model = "gemini-flash-latest"
    gw.api_key = "test"
    gw._init_error = None
    gw._client = object()
    gw.BASE_BACKOFF_S = 0.0  # no real sleeping in tests
    gw.MAX_BACKOFF_S = 0.0
    return gw


def test_quota_error_fails_fast_without_retry() -> None:
    """A 429/quota error must NOT be retried — the caller should get a fast
    failure and fall back (e.g. remediation → KB), not wait out 3 attempts."""
    gw = _bare_gateway()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError(
            "429 RESOURCE_EXHAUSTED. Quota exceeded for free_tier_requests; retry in 39s")

    gw._dispatch = boom  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="hi"))
    assert not resp.ok()
    assert calls["n"] == 1                          # fail fast — one attempt only
    assert resp.error and "RESOURCE_EXHAUSTED" in resp.error
    assert "exhausted retries" not in resp.error    # message reflects the fast-fail


def test_transient_error_is_retried() -> None:
    """A transient 503 should be retried across all attempts before giving up."""
    gw = _bare_gateway()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError("503 UNAVAILABLE")

    gw._dispatch = boom  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="hi"))
    assert not resp.ok()
    assert calls["n"] == LLMGateway.MAX_RETRIES     # genuinely transient → retried
    assert resp.error and "exhausted retries" in resp.error
