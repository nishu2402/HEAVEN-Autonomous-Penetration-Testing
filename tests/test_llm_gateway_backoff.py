"""Regression tests for the bounded AI retry/backoff (rate-limit circuit breaker).

The defect these pin: a scan fans dozens of LLM calls out sequentially (per-finding
FP review, vuln hypotheses, coverage grading, remediation). When the operator's key
is rate-limited/out-of-quota EVERY call 429s. Two things previously made that a
multi-minute drag instead of a fast fallback:

  1. the provider SDKs' OWN internal retry loops (Anthropic/OpenAI default
     ``max_retries=2``, google-genai's default retry set) re-sent each 429,
     honoring the response's multi-second ``Retry-After`` BEFORE the gateway ever
     saw the error;
  2. even after the gateway fast-failed a 429, the NEXT call round-tripped again —
     dozens of doomed calls back to back.

The fixes, pinned here:
  * SDK-internal retries are disabled at client init so the gateway is the sole
    retry controller (``max_retries=0`` / ``retry_options=attempts=1``);
  * the FIRST quota/429 error arms a short cooldown; subsequent calls within the
    window short-circuit straight to their non-LLM fallback with no network call.
    The window is sized from the server's ``Retry-After`` hint when present, else
    a bounded default, always clamped — and is disabled by
    ``HEAVEN_LLM_RATELIMIT_COOLDOWN=0``.
"""
from __future__ import annotations

import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from heaven.ai.llm_gateway import (
    MAX_OVERLOAD_COOLDOWN_S,
    LLMGateway,
    LLMRequest,
    _parse_retry_after,
)


# ── a controllable gateway that never touches the network ──────────────────────

def _gw() -> LLMGateway:
    """A gateway with a fake client and initialized breaker state, so we can drive
    ``_dispatch`` directly and assert breaker behavior without any real SDK."""
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "gemini"
    gw.model = "gemini-flash-latest"
    gw.api_key = "test"
    gw._init_error = None
    gw._client = object()
    gw.BASE_BACKOFF_S = 0.0  # no real sleeping in tests
    gw.MAX_BACKOFF_S = 0.0
    gw._ratelimited_until = 0.0
    gw._ratelimit_reason = ""
    gw._ratelimit_lock = threading.Lock()
    return gw


def _raise(msg: str):
    def _boom(prompt, system, req):  # type: ignore[no-untyped-def]
        raise RuntimeError(msg)
    return _boom


# ── Retry-After parsing across provider error shapes ───────────────────────────

@pytest.mark.parametrize("msg, want", [
    ("429 RESOURCE_EXHAUSTED. Quota exceeded; retry in 39s", 39.0),
    ("Rate limit reached. Please try again in 20s.", 20.0),
    ("... details { retryDelay: '40s' } ...", 40.0),
    ("HTTP 429 retry-after: 30", 30.0),
    ("429 too many requests (no hint)", None),
    ("503 UNAVAILABLE", None),
])
def test_parse_retry_after_shapes(msg: str, want: float | None) -> None:
    assert _parse_retry_after(msg) == want


# ── the breaker: first 429 arms cooldown, later calls short-circuit ────────────

def test_rate_limit_arms_cooldown_and_short_circuits(monkeypatch) -> None:
    monkeypatch.delenv("HEAVEN_LLM_RATELIMIT_COOLDOWN", raising=False)
    gw = _gw()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError("429 RESOURCE_EXHAUSTED. Quota exceeded; retry in 39s")

    gw._dispatch = boom  # type: ignore[assignment]

    r1 = gw.complete(LLMRequest(prompt="a"))   # dispatches, 429, arms cooldown
    r2 = gw.complete(LLMRequest(prompt="b"))   # short-circuits (no dispatch)
    r3 = gw.complete(LLMRequest(prompt="c"))   # short-circuits

    assert calls["n"] == 1, "only the first call may hit the network; rest short-circuit"
    assert not r1.ok() and "RESOURCE_EXHAUSTED" in r1.error
    for r in (r2, r3):
        assert not r.ok()
        assert "skipping LLM call" in r.error   # the breaker's short-circuit message
    # cooldown was sized from the "retry in 39s" hint (clamped well under the max)
    remaining = gw._ratelimited_until - time.monotonic()
    assert 30.0 < remaining <= 39.0


def test_cooldown_expires_and_calls_resume() -> None:
    gw = _gw()
    calls = {"n": 0}
    gw._dispatch = lambda p, s, r: (calls.__setitem__("n", calls["n"] + 1)  # type: ignore[assignment]
                                    or SimpleNamespace())
    # Pretend a cooldown was armed but has already elapsed.
    gw._ratelimited_until = time.monotonic() - 1.0
    gw._ratelimit_reason = "old 429"
    # A real dispatch return is a LLMResponse; use a minimal stand-in via monkeypatched _dispatch.

    def ok_dispatch(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        from heaven.ai.llm_gateway import LLMResponse
        return LLMResponse(text="hi", provider="gemini", model=gw.model)

    gw._dispatch = ok_dispatch  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="x"))
    assert calls["n"] == 1, "an expired cooldown must not block a fresh call"
    assert resp.ok() and resp.text == "hi"


def test_cooldown_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("HEAVEN_LLM_RATELIMIT_COOLDOWN", "0")
    gw = _gw()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError("429 RESOURCE_EXHAUSTED; retry in 39s")

    gw._dispatch = boom  # type: ignore[assignment]
    gw.complete(LLMRequest(prompt="a"))
    gw.complete(LLMRequest(prompt="b"))
    # With the breaker disabled every call is allowed to try (and fast-fail).
    assert calls["n"] == 2
    assert gw._ratelimited_until == 0.0


def test_persistent_overload_arms_short_cooldown(monkeypatch) -> None:
    """A 503/504 is transient and retried, but when it PERSISTS across the retry the
    provider is genuinely overloaded right now. Arm a SHORT, self-clearing cooldown
    so a bulk pass short-circuits to its non-LLM fallback instead of hammering a
    provider that cannot answer. The window stays well under the quota cooldown, so
    interactive use resumes in seconds — and it is NOT the quota breaker (a 504 is
    not a rate limit)."""
    monkeypatch.delenv("HEAVEN_LLM_OVERLOAD_COOLDOWN", raising=False)
    gw = _gw()
    gw._dispatch = _raise(  # type: ignore[assignment]
        "504 DEADLINE_EXCEEDED. Deadline expired before operation could complete.")
    resp = gw.complete(LLMRequest(prompt="a"))
    assert not resp.ok() and "DEADLINE_EXCEEDED" in resp.error
    remaining = gw._ratelimited_until - time.monotonic()
    assert 0.0 < remaining <= MAX_OVERLOAD_COOLDOWN_S, "short overload window, not a quota one"
    assert remaining < 30.0 + 1e-6
    assert gw._ratelimit_gate() is not None


def test_overload_retries_are_capped() -> None:
    """An overload/deadline is retried at most ONCE (2 dispatches), not the full
    budget — an interactive caller fails fast instead of waiting out 3x the timeout."""
    gw = _gw()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError("504 DEADLINE_EXCEEDED")

    gw._dispatch = boom  # type: ignore[assignment]
    gw.complete(LLMRequest(prompt="a"))
    assert calls["n"] == 2, "overload retried exactly once, then stops"


def test_one_off_overload_self_heals_without_cooldown() -> None:
    """A genuine one-off 503 clears on the single quick retry: the call succeeds and
    NO cooldown is armed (only a persistent overload arms one)."""
    gw = _gw()
    calls = {"n": 0}

    def flaky(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("503 UNAVAILABLE")
        from heaven.ai.llm_gateway import LLMResponse
        return LLMResponse(text="ok", provider="gemini", model=gw.model)

    gw._dispatch = flaky  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="a"))
    assert resp.ok() and resp.text == "ok"
    assert calls["n"] == 2, "retried once and succeeded"
    assert gw._ratelimited_until == 0.0, "a recovered one-off overload must not arm a cooldown"
    assert gw._ratelimit_gate() is None


def test_generic_transient_uses_full_retry_budget() -> None:
    """A non-overload transient error (e.g. connection reset) still gets the full
    retry budget — the cap is specific to overload/deadline, not all retryables."""
    gw = _gw()
    calls = {"n": 0}

    def boom(prompt, system, req):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        raise RuntimeError("connection reset by peer")

    gw._dispatch = boom  # type: ignore[assignment]
    gw.complete(LLMRequest(prompt="a"))
    assert calls["n"] == 3, "generic transient error keeps the full 3-attempt budget"
    assert gw._ratelimited_until == 0.0, "not an overload — no cooldown"


def test_auth_error_does_not_arm_cooldown() -> None:
    """An auth error fails fast per-call (no Retry-After backoff), so it should not
    arm the cooldown — only quota/rate-limit errors do."""
    gw = _gw()
    gw._dispatch = _raise("401 Unauthorized: invalid api key")  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="a"))
    assert not resp.ok()
    assert gw._ratelimited_until == 0.0
    assert gw._ratelimit_gate() is None


def test_arm_cooldown_survives_missing_lock() -> None:
    """A gateway built via ``__new__`` without breaker attributes (as some tests
    do) must arm the cooldown defensively instead of AttributeError-ing."""
    gw = LLMGateway.__new__(LLMGateway)
    gw.provider = "gemini"
    gw.model = "gemini-flash-latest"
    gw.api_key = "test"
    gw._init_error = None
    gw._client = object()
    gw.BASE_BACKOFF_S = 0.0
    gw.MAX_BACKOFF_S = 0.0
    # NOTE: deliberately no _ratelimited_until / _ratelimit_lock set.
    gw._dispatch = _raise("429 RESOURCE_EXHAUSTED; retry in 10s")  # type: ignore[assignment]
    resp = gw.complete(LLMRequest(prompt="a"))          # must not raise
    assert not resp.ok()
    assert gw._ratelimit_gate() is not None             # cooldown got armed anyway


# ── SDK-internal retries are disabled at client init ───────────────────────────

def test_gemini_client_disables_sdk_internal_retries() -> None:
    """The google-genai client must be built with retry_options attempts=1 so its
    own retry loop can't stall each 429 before the gateway sees it."""
    pytest.importorskip("google.genai")
    gw = LLMGateway(provider="gemini",
                    api_key="AIzadummy-key-000000000000000000000000")
    assert gw.available and gw._gemini_sdk == "new"
    http_opts = getattr(getattr(gw._client, "_api_client", None), "_http_options", None)
    retry_opts = getattr(http_opts, "retry_options", None)
    assert retry_opts is not None, "gemini client must set retry_options"
    assert getattr(retry_opts, "attempts", None) == 1, "attempts=1 disables SDK retries"


def _inject_fake_sdk(monkeypatch, module_name: str, class_name: str) -> dict[str, Any]:
    """Install a fake provider SDK module whose client class records its kwargs."""
    captured: dict[str, Any] = {}

    class _FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    fake_mod = SimpleNamespace(**{class_name: _FakeClient})
    monkeypatch.setitem(sys.modules, module_name, fake_mod)
    return captured


def test_anthropic_client_disables_sdk_internal_retries(monkeypatch) -> None:
    captured = _inject_fake_sdk(monkeypatch, "anthropic", "Anthropic")
    gw = LLMGateway(provider="anthropic", api_key="test")
    assert gw.available
    assert captured.get("max_retries") == 0, "anthropic client must set max_retries=0"


def test_openai_client_disables_sdk_internal_retries(monkeypatch) -> None:
    captured = _inject_fake_sdk(monkeypatch, "openai", "OpenAI")
    gw = LLMGateway(provider="openai", api_key="test")
    assert gw.available
    assert captured.get("max_retries") == 0, "openai client must set max_retries=0"
