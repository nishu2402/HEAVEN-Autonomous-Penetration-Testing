"""Shared pytest fixtures + suite-wide isolation.

HEAVEN's CLI entrypoint (``heaven/cli/__init__.py``) calls
``load_dotenv(..., override=True)`` so that a developer's ``.env`` takes effect
for real ``heaven`` commands. Inside the test process, though, any CliRunner /
CLI-invoking test triggers that load and **mutates ``os.environ`` for the rest
of the process** — leaking a real ``.env`` LLM key into later tests. That makes
"no key → static fallback" assertions pass on CI (no ``.env`` key) but fail
locally in an order-dependent way once a developer configures a provider key.

The autouse fixture below clears the LLM provider env vars before every test so
key-presence is deterministic. Tests that need a key present set it themselves
via ``monkeypatch.setenv`` (which runs after this fixture), so they are
unaffected.
"""
from __future__ import annotations

import pytest

# Every env var that flips an AI layer from "static fallback" to "live LLM".
_LLM_ENV_VARS = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "HEAVEN_LLM_PROVIDER",
    "HEAVEN_LLM_MODEL",
)


@pytest.fixture(autouse=True)
def _isolate_llm_env(monkeypatch):
    """Guarantee no ambient/leaked LLM provider key is visible to a test unless
    that test sets one explicitly. Restored automatically after each test."""
    for var in _LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield
