"""Regression tests for the Gemini path of the provider-agnostic LLM gateway.

These lock in two production bugs that silently disabled every AI feature when
the operator used a Gemini key (the default "free tier" path):

1. Gemini 2.5 models ("gemini-flash-latest") run an internal *thinking* pass by
   default that spends the whole output-token budget on hidden reasoning, so
   `.text` comes back empty and callers fall back to their non-LLM path. The
   gateway must disable thinking (``ThinkingConfig(thinking_budget=0)``).

2. The gateway prepared the redacted, schema-carrying ``system`` prompt but the
   Gemini dispatcher ignored it and used the raw ``req.system`` — so
   ``response_schema`` requests never received the JSON-schema instruction and
   produced empty/degenerate structured output. The prepared ``system`` must be
   the one sent to Gemini.
"""
from __future__ import annotations

from typing import Any, Optional

from google.genai import types  # available; SDK ships with the project

from heaven.ai.llm_gateway import LLMGateway, LLMRequest


class _FakeUsage:
    prompt_token_count = 5
    candidates_token_count = 7
    thoughts_token_count = None


class _FakeCandidate:
    def __init__(self, finish_reason: Any = None) -> None:
        self.finish_reason = finish_reason


class _FakeResult:
    def __init__(self, text: Optional[str], candidates: list[Any] | None = None) -> None:
        self.text = text
        self.usage_metadata = _FakeUsage()
        self.candidates = candidates if candidates is not None else [_FakeCandidate("STOP")]
        self.prompt_feedback = None


class _FakeModels:
    def __init__(self, result: _FakeResult) -> None:
        self._result = result
        self.captured: dict[str, Any] = {}

    def generate_content(self, model: str, contents: str, config: Any) -> _FakeResult:
        self.captured = {"model": model, "contents": contents, "config": config}
        return self._result


class _FakeGeminiClient:
    def __init__(self, result: _FakeResult) -> None:
        self.models = _FakeModels(result)


def _gateway_with(result: _FakeResult) -> LLMGateway:
    """Build a gateway wired to a fake Gemini 'new' SDK client."""
    gw = LLMGateway.__new__(LLMGateway)  # bypass __init__ / real key + SDK
    gw.provider = "gemini"
    gw.model = "gemini-flash-latest"
    gw.api_key = "test"
    gw._gemini_sdk = "new"
    gw._init_error = None
    gw._client = _FakeGeminiClient(result)
    return gw


def test_gemini_disables_thinking() -> None:
    """Thinking must be turned off so the token budget yields visible text."""
    gw = _gateway_with(_FakeResult("PONG"))
    resp = gw.complete(LLMRequest(prompt="ping", max_tokens=64))
    assert resp.ok()
    assert resp.text == "PONG"
    cfg = gw._client.models.captured["config"]
    assert isinstance(cfg, types.GenerateContentConfig)
    assert cfg.thinking_config is not None
    assert cfg.thinking_config.thinking_budget == 0


def test_gemini_receives_prepared_system_with_schema_hint() -> None:
    """A response_schema request must reach Gemini as a system_instruction that
    carries the JSON-schema instruction (otherwise structured output is empty)."""
    try:
        from pydantic import BaseModel
    except ImportError:  # pragma: no cover
        return

    class Shape(BaseModel):
        answer: str

    gw = _gateway_with(_FakeResult('{"answer": "yes"}'))
    resp = gw.complete(LLMRequest(
        prompt="q?", system="You are a bot.", response_schema=Shape, max_tokens=128,
    ))
    cfg = gw._client.models.captured["config"]
    sysinstr = cfg.system_instruction or ""
    assert "You are a bot." in sysinstr
    assert "JSON" in sysinstr  # schema hint appended by _prepare
    # And the structured object parsed cleanly.
    assert resp.structured is not None
    assert resp.structured.answer == "yes"


def test_gemini_empty_response_surfaces_reason() -> None:
    """An empty completion (MAX_TOKENS before any text) must report a reason,
    not a silent blank — so operators see *why* the AI produced nothing."""
    gw = _gateway_with(_FakeResult("", candidates=[_FakeCandidate("MAX_TOKENS")]))
    resp = gw.complete(LLMRequest(prompt="ping", max_tokens=8))
    assert not resp.ok()
    assert resp.error and "MAX_TOKENS" in resp.error


def test_gemini_secrets_redacted_in_prompt() -> None:
    """Redaction still applies on the Gemini path."""
    gw = _gateway_with(_FakeResult("ok"))
    gw.complete(LLMRequest(prompt="key is AKIAAAAAAAAAAAAAAAAA here"))
    sent = gw._client.models.captured["contents"]
    assert "AKIA" not in sent
    assert "[REDACTED:aws-access-key]" in sent
