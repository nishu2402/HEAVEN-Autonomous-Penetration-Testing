"""Tests for heaven/ai/chat_assistant.py — the AI security assistant.

Verifies engagement grounding (on/off), the availability gate, and the
transcript folding. Uses a fake gateway — no real LLM call.
"""
from __future__ import annotations

from heaven.ai.chat_assistant import (
    ChatAssistant,
    _messages_to_prompt,
    build_engagement_context,
)
from heaven.ai.llm_gateway import LLMResponse


# ── fakes ──────────────────────────────────────────────────────────────────
class _F:
    def __init__(self, **k):
        self.__dict__.update(k)


class _Store:
    def list_findings(self, **k):
        return [
            _F(title="SQL injection in login", severity="critical", target="10.0.0.1",
               vuln_type="sqli", cve_id="", risk_score=9.1, confidence=0.95,
               status="open", evidence={}),
            _F(title="Missing HSTS", severity="low", target="10.0.0.2",
               vuln_type="hsts", cve_id="", risk_score=2.0, confidence=0.8,
               status="open", evidence={}),
        ]

    def list_scans(self, limit=1):
        return [{"target": "10.0.0.1", "status": "completed"}]

    def get_engagement(self):
        return _F(name="acme-corp")


class _GW:
    provider = "ollama"
    model = "qwen2.5:7b"
    _init_error = None

    def __init__(self, available=True):
        self._avail = available
        self.captured = None

    @property
    def available(self):
        return self._avail

    def complete(self, req):
        self.captured = req
        return LLMResponse(text="answer", provider=self.provider, model=self.model)


# ── transcript folding ──────────────────────────────────────────────────────
def test_messages_to_prompt_folds_roles():
    p = _messages_to_prompt([
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
        {"role": "user", "content": "next"},
    ])
    assert "User: hi" in p and "Assistant: hello" in p and p.rstrip().endswith("Assistant:")


# ── grounding ───────────────────────────────────────────────────────────────
def test_build_engagement_context_summarizes():
    ctx = build_engagement_context(_Store())
    assert "acme-corp" in ctx
    assert "Top findings" in ctx
    assert "SQL injection in login" in ctx
    assert "critical=1" in ctx


def test_build_engagement_context_none_store():
    assert build_engagement_context(None) == ""


# ── assistant behavior ──────────────────────────────────────────────────────
def test_reply_grounds_when_enabled():
    gw = _GW()
    a = ChatAssistant(gateway=gw)
    r = a.reply([{"role": "user", "content": "what's worst?"}], store=_Store(),
                include_context=True)
    assert r.text == "answer"
    assert "SQL injection in login" in (gw.captured.system or "")


def test_reply_no_grounding_when_disabled():
    gw = _GW()
    a = ChatAssistant(gateway=gw)
    a.reply([{"role": "user", "content": "hi"}], store=_Store(), include_context=False)
    assert "Top findings" not in (gw.captured.system or "")


def test_reply_unavailable_returns_helpful_error():
    gw = _GW(available=False)
    gw._init_error = "no LLM configured"
    a = ChatAssistant(gateway=gw)
    r = a.reply([{"role": "user", "content": "hi"}])
    assert not r.ok() and r.error


def test_stream_yields_nothing_when_unavailable():
    a = ChatAssistant(gateway=_GW(available=False))
    assert list(a.stream([{"role": "user", "content": "hi"}])) == []
