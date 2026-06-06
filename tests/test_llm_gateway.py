"""HEAVEN — tests for the provider-agnostic LLM gateway.

No real API calls: provider clients are constructed with dummy keys (the SDKs
don't validate keys at construction), and we only assert wiring — provider
selection, the Gemini SDK migration, secret redaction, and structured parsing.
"""

from __future__ import annotations

import pytest

from heaven.ai.llm_gateway import (
    LLMGateway,
    LLMRequest,
    LLMResponse,
    PROVIDER_PIP_PACKAGES,
    redact_secrets,
)


# ── Secret redaction (protects operator secrets before they hit a 3rd-party LLM) ──

def test_redact_secrets_strips_known_tokens():
    text = (
        "openai sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX1234567890 and "
        "aws AKIAIOSFODNN7EXAMPLE and url https://user:hunter2@db.internal/x"
    )
    out, count = redact_secrets(text)
    assert count >= 3
    assert "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "hunter2" not in out
    assert "[REDACTED:" in out


def test_redact_secrets_noop_on_clean_text():
    out, count = redact_secrets("just a normal finding description, nothing secret")
    assert count == 0
    assert out == "just a normal finding description, nothing secret"


# ── Provider selection ──

def test_auto_detects_gemini_from_env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "HEAVEN_LLM_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "AIzadummy-key-000000000000000000000000")
    gw = LLMGateway()
    assert gw.provider == "gemini"


def test_unavailable_without_key_returns_error_response(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    gw = LLMGateway(provider="anthropic", api_key="")
    assert gw.available is False
    resp = gw.complete(LLMRequest(prompt="hello"))
    assert isinstance(resp, LLMResponse)
    assert resp.ok() is False
    assert resp.error


# ── Gemini SDK migration: prefer the current `google-genai` SDK ──

def test_gemini_pip_hint_is_current_sdk():
    assert PROVIDER_PIP_PACKAGES["gemini"] == "google-genai"


def test_gemini_uses_new_sdk_when_available():
    pytest.importorskip("google.genai")  # current SDK
    gw = LLMGateway(provider="gemini", model="gemini-1.5-pro",
                    api_key="AIzadummy-key-000000000000000000000000")
    assert gw.available is True
    assert gw._gemini_sdk == "new"


# ── Structured-output parsing tolerates fenced JSON ──

def test_parse_structured_handles_code_fences():
    fenced = '```json\n{"a": 1, "b": "x"}\n```'
    data = LLMGateway._parse_structured(fenced, dict)  # dict → returns raw dict
    assert data == {"a": 1, "b": "x"}
