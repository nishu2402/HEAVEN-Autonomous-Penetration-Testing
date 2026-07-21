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


@pytest.fixture(autouse=True)
def _isolate_data_dir(tmp_path, monkeypatch):
    """Point HEAVEN's data dir — engagements, generated reports and the audit
    trail — at a per-test temp directory so the suite never writes into the
    repository's real ``./data/``. Previously report/audit writers used a
    CWD-relative ``data/`` default, so running the tests appended test entries
    into a developer's real audit log and littered ``data/`` with report files.

    Tests that need a specific data dir still override ``HEAVEN_DATA_DIR``
    themselves (e.g. test_replay_stealth_persistence) — this only isolates the
    default. The config and audit-logger singletons are reset so the relocated
    dir takes effect immediately and does not leak across tests."""
    import heaven.config as cfg
    import heaven.security.audit as auditmod

    monkeypatch.setenv("HEAVEN_DATA_DIR", str(tmp_path / "heaven-data"))
    cfg._config = None
    auditmod._audit_logger = None
    yield
    cfg._config = None
    auditmod._audit_logger = None
