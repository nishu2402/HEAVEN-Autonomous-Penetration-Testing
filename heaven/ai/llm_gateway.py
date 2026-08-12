"""
HEAVEN — Provider-agnostic LLM Gateway
Single interface over Anthropic Claude, OpenAI, and Google Gemini.

Why this module exists:
  Before this, ai_remediation.py called google-generativeai directly. That
  locked HEAVEN to one vendor, gave no caching, no retries, no secret
  redaction, and no audit trail — none of which is acceptable for a tool
  that ships its findings to a third-party LLM.

Design rules:
  - All provider SDKs are optional imports. Missing SDK => `available=False`,
    never an import error at module load.
  - Provider selected by HEAVEN_LLM_PROVIDER env var. Falls back to the first
    provider whose API key is present.
  - Secret redaction is ON by default. Disable per-request when the operator
    explicitly wants the LLM to see a finding's contents.
  - Every call is logged with provider, model, token counts, latency,
    redaction count — this lands in the audit log via the project logger.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterator, Optional, Type

from heaven.utils.logger import get_logger

logger = get_logger("ai.gateway")


# ═══════════════════════════════════════════
# PROVIDER DEFAULTS — keep current with Claude 4.x / GPT-4.x / Gemini 1.5+
# ═══════════════════════════════════════════

# Current-generation defaults. Pin a different one any time with HEAVEN_LLM_MODEL
# (env or Web-UI Settings). Google retires pinned Gemini versions on a rolling
# basis (1.5 gone in 2025; 2.5-flash later gated to "no longer available to new
# users" → live calls 404 even with a valid key), so the Gemini default is the
# rolling **gemini-flash-latest** alias, which always resolves to the current
# fast Flash model and never 404s as versions churn.
PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",     # balanced default; Opus 4.8 / Haiku 4.5 also valid
    "openai": "gpt-4o",
    "gemini": "gemini-flash-latest",    # rolling alias → current Flash; gemini-pro-latest for deeper reasoning
    # Local runtimes (no API key, no rate limits — see LOCAL_PROVIDERS below).
    # `ollama` defaults to a fast, accurate 7B: qwen2.5 follows instructions and
    # emits clean JSON, which is what HEAVEN's structured AI layers (FP review,
    # hypotheses, coverage) need. Override any time with HEAVEN_LLM_MODEL
    # (e.g. llama3.1:8b, qwen2.5:14b). `local` (a generic OpenAI-compatible
    # server: LM Studio / llama.cpp / vLLM / LocalAI) has no universal default —
    # the operator pins their served model id via HEAVEN_LLM_MODEL.
    "ollama": "qwen2.5:7b",
    "local": "",
}

PROVIDER_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    # Local runtimes: Ollama is keyless (""). A self-hosted OpenAI-compatible
    # endpoint may take an optional bearer token via HEAVEN_LLM_API_KEY.
    "ollama": "",
    "local": "HEAVEN_LLM_API_KEY",
}

# pip package name per provider — NOT always the provider name. In particular
# Gemini's SDK is `google-genai` (the current SDK; the older
# `google-generativeai` is deprecated but still accepted as a fallback), so
# "pip install gemini" is wrong. The local providers speak plain HTTP over
# `httpx` (already a base dependency), so no SDK is required for them.
PROVIDER_PIP_PACKAGES = {
    "anthropic": "anthropic",
    "openai": "openai",
    "gemini": "google-genai",
    "ollama": "httpx",
    "local": "httpx",
}

# ═══════════════════════════════════════════
# LOCAL LLM PROVIDERS (Ollama + generic OpenAI-compatible)
# ═══════════════════════════════════════════
#
# Cloud keys rate-limit; a local model does not. These two providers let HEAVEN
# run its whole AI layer against a model on the operator's own machine — fast,
# private (findings never leave the host), and free of quotas — with ZERO new
# Python dependencies (the transport is `httpx`, already in the base install).
# Both speak the OpenAI-compatible `/v1/chat/completions` schema, so a single
# `_call_local` dispatch covers Ollama, LM Studio, llama.cpp, vLLM and LocalAI.
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
LOCAL_PROVIDERS = frozenset({"ollama", "local"})


def _local_base_url(provider: str) -> str:
    """OpenAI-compatible base URL for a local provider (no trailing slash).

    ollama → ``HEAVEN_OLLAMA_HOST`` (default localhost:11434) + ``/v1``.
    local  → ``HEAVEN_LLM_BASE_URL`` verbatim (operator supplies the full base,
             e.g. ``http://localhost:1234/v1``).
    """
    if provider == "ollama":
        host = (os.environ.get("HEAVEN_OLLAMA_HOST") or DEFAULT_OLLAMA_HOST).strip().rstrip("/")
        return f"{host}/v1"
    if provider == "local":
        return (os.environ.get("HEAVEN_LLM_BASE_URL") or "").strip().rstrip("/")
    return ""

# Per-call network timeout (seconds) applied to every provider client. Without
# this a slow/hung provider call can run for minutes (observed 176s from a
# 3×-retried ~58s Gemini stall) — a terrible experience and, before the async
# offload, one that froze the whole web server. Overridable via env for slow
# links or big-reasoning models. Clamped to a sane floor.
DEFAULT_LLM_TIMEOUT_S = 60.0


def _llm_timeout_s() -> float:
    try:
        return max(5.0, float(os.environ.get("HEAVEN_LLM_TIMEOUT", DEFAULT_LLM_TIMEOUT_S)))
    except (TypeError, ValueError):
        return DEFAULT_LLM_TIMEOUT_S


# ═══════════════════════════════════════════
# RATE-LIMIT CIRCUIT BREAKER
# ═══════════════════════════════════════════
#
# A single scan fans a LOT of LLM calls out sequentially — per-finding FP review,
# vuln hypotheses, coverage grading, per-finding remediation. If the operator's
# key is rate-limited/out-of-quota, EVERY one of those calls 429s. Without a
# breaker each call still makes a full doomed round-trip (and, with provider-SDK
# internal retries, each stalls further honoring the 429's multi-second
# Retry-After) — turning a scan into minutes of sequential rate-limit waits
# (the observed ~8-minute DVWA drag). Two bounds fix this:
#   1. provider-SDK internal retries are disabled at client init (see
#      _init_client) so the gateway is the SOLE retry controller;
#   2. on the FIRST quota/429 error the gateway enters a short cooldown; further
#      calls during that window short-circuit straight to their non-LLM fallback
#      instead of round-tripping. Cooldown is sized from the server's own
#      Retry-After hint when present, else a bounded default, and always clamped.
# The window self-clears; a new key (env change) rebuilds the gateway and resets
# it. Set HEAVEN_LLM_RATELIMIT_COOLDOWN=0 to disable the breaker entirely.
DEFAULT_RATELIMIT_COOLDOWN_S = 20.0
MAX_RATELIMIT_COOLDOWN_S = 120.0


def _ratelimit_cooldown_s() -> float:
    """Default cooldown floor after a rate-limit error. 0 disables the breaker."""
    try:
        v = float(os.environ.get("HEAVEN_LLM_RATELIMIT_COOLDOWN", DEFAULT_RATELIMIT_COOLDOWN_S))
    except (TypeError, ValueError):
        return DEFAULT_RATELIMIT_COOLDOWN_S
    return max(0.0, v)


# Retry-After hints appear in provider error strings in several shapes:
#   Gemini:   "... retry in 39.2s"  /  "retryDelay: '40s'"
#   OpenAI:   "Please try again in 20s"  /  "retry-after: 30"
#   Anthropic:"... retry_after: 15"
# Best-effort parse of the first plausible seconds value; None if none found.
_RETRY_AFTER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"retry[_\- ]?after['\":=\s]+(\d+(?:\.\d+)?)", re.IGNORECASE),
    re.compile(r"retrydelay['\":=\s]+(\d+(?:\.\d+)?)\s*s", re.IGNORECASE),
    re.compile(r"retry(?:ing)?\s+in\s+(\d+(?:\.\d+)?)\s*(?:s|sec|seconds)", re.IGNORECASE),
    re.compile(r"try\s+again\s+in\s+(\d+(?:\.\d+)?)\s*(?:s|sec|seconds)", re.IGNORECASE),
)


def _parse_retry_after(text: str) -> Optional[float]:
    for pat in _RETRY_AFTER_PATTERNS:
        m = pat.search(text)
        if m:
            try:
                return float(m.group(1))
            except (TypeError, ValueError):
                continue
    return None


# Error-string tokens, split so the retry classifier and the rate-limit breaker
# share one source of truth and can't drift apart. Rate-limit/quota errors arm
# the cooldown; auth/bad-request errors are non-retryable but cheap (they fail
# instantly with no Retry-After backoff), so they don't arm the breaker.
_RATELIMIT_ERROR_TOKENS = (
    "resource_exhausted", "quota", "insufficient_quota",
    "rate limit", "rate_limit", "429", "too many requests",
)
_AUTH_ERROR_TOKENS = (
    "unauthorized", "401", "403", "permission denied",
    "api key not valid", "invalid api key", "invalid_api_key",
    "authentication", "invalid_request_error",
)


# ═══════════════════════════════════════════
# SECRET REDACTION
# Strips operator-side secrets BEFORE prompts hit a third-party LLM.
# This protects the operator's own credentials, not the targets' findings.
# ═══════════════════════════════════════════

# (pattern, label) — order matters; longer patterns first to avoid partial matches.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{40,}"), "anthropic-key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}"), "openai-project-key"),
    (re.compile(r"sk-[A-Za-z0-9]{40,}"), "openai-key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "aws-session-key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "github-pat"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{50,}"), "github-fine-grained-pat"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "gitlab-pat"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "slack-token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "google-api-key"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "jwt"),
    # Generic Bearer / Authorization header values
    (re.compile(r"(?i)(?:authorization:\s*bearer\s+)([A-Za-z0-9_\-.=]{20,})"), "bearer-token"),
    # Passwords embedded in URLs: scheme://user:pass@host
    (re.compile(r"://([^/:\s]+):([^@/\s]+)@"), "url-credential"),
]


def redact_secrets(text: str) -> tuple[str, int]:
    """
    Replace known secret patterns with [REDACTED:label].
    Returns (redacted_text, count).
    """
    count = 0
    out = text
    for pattern, label in _SECRET_PATTERNS:
        def _replace(_match: re.Match[str], _label: str = label) -> str:
            nonlocal count
            count += 1
            return f"[REDACTED:{_label}]"
        out = pattern.sub(_replace, out)
    return out, count


# ═══════════════════════════════════════════
# REQUEST / RESPONSE TYPES
# ═══════════════════════════════════════════


class LLMProviderError(RuntimeError):
    """Raised when an LLM call fails after exhausting retries."""


@dataclass
class LLMRequest:
    prompt: str
    system: Optional[str] = None
    max_tokens: int = 2048
    temperature: float = 0.2

    # When set, the gateway appends a JSON-schema instruction to `system`,
    # parses the response as JSON, and validates it against this Pydantic model.
    # Returns the validated instance in LLMResponse.structured.
    response_schema: Optional[Type[Any]] = None

    # Anthropic prompt-caching hint. When True, the system prompt is marked
    # with cache_control so repeated calls with the same system block are
    # billed as cache reads. No-op on non-Anthropic providers.
    cache_static_prefix: bool = False

    # Per-request override of the default redaction policy.
    redact_secrets: bool = True


@dataclass
class LLMResponse:
    text: str
    structured: Any = None
    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    latency_ms: float = 0.0
    redactions_applied: int = 0
    error: Optional[str] = None

    def ok(self) -> bool:
        return self.error is None and bool(self.text)


# ═══════════════════════════════════════════
# GATEWAY
# ═══════════════════════════════════════════


class LLMGateway:
    """
    Single entry point for all LLM calls.

    Usage:
        gw = get_gateway()                       # auto-select provider
        if gw.available:
            resp = gw.complete(LLMRequest(prompt="..."))
    """

    MAX_RETRIES = 3
    BASE_BACKOFF_S = 1.0
    MAX_BACKOFF_S = 15.0

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        allow_fallback: bool = True,
    ):
        self.provider = (provider or os.environ.get("HEAVEN_LLM_PROVIDER") or "").lower()
        if not self.provider:
            self.provider = self._auto_detect_provider()

        self.model = model or os.environ.get("HEAVEN_LLM_MODEL") or \
            PROVIDER_DEFAULT_MODELS.get(self.provider, "")
        self.api_key = api_key or os.environ.get(
            PROVIDER_KEY_ENVS.get(self.provider, ""), ""
        )
        self._client: Any = None
        self._init_error: Optional[str] = None
        self._gemini_sdk: Optional[str] = None  # "new" (google-genai) | "legacy"
        self._is_local = self.provider in LOCAL_PROVIDERS
        self._local_base: str = ""

        # Rate-limit circuit breaker state (see the module-level note). Monotonic
        # deadline until which calls short-circuit; guarded by a lock because the
        # threaded API server runs acomplete() concurrently on this singleton.
        self._ratelimited_until: float = 0.0
        self._ratelimit_reason: str = ""
        self._ratelimit_lock = threading.Lock()

        # Hybrid fallback: if the PRIMARY provider is unavailable or returns
        # nothing, transparently retry once on HEAVEN_LLM_FALLBACK_PROVIDER
        # (which needs its own key/endpoint). This lets a local-first setup keep
        # a cloud safety net, or a cloud-first setup fall back to a
        # no-rate-limit local model. The secondary gateway is built with
        # allow_fallback=False so it can never recurse.
        self._allow_fallback = allow_fallback
        self.fallback_provider = (
            (os.environ.get("HEAVEN_LLM_FALLBACK_PROVIDER") or "").lower()
            if allow_fallback else ""
        )
        if self.fallback_provider == self.provider:
            self.fallback_provider = ""  # a provider can't fall back to itself
        self._fallback_gw: Optional["LLMGateway"] = None

        # Cloud providers need a key; local runtimes are keyless (Ollama) or take
        # an optional token, so they initialize on provider alone.
        if self.provider and (self.api_key or self._is_local):
            self._init_client()

    @property
    def available(self) -> bool:
        return self._client is not None

    # ── client init per provider ──────────────────────────────────────────

    @staticmethod
    def _auto_detect_provider() -> str:
        # Cloud keys win first (an explicit key = intent to use that provider).
        for name in ("anthropic", "openai", "gemini"):
            if os.environ.get(PROVIDER_KEY_ENVS[name]):
                return name
        # Then a configured local runtime. Keyless, so we key off the endpoint
        # config rather than a secret; reachability is verified at call time /
        # by `heaven ai test`, never probed here (keeps gateway init cheap).
        if os.environ.get("HEAVEN_OLLAMA_HOST"):
            return "ollama"
        if os.environ.get("HEAVEN_LLM_BASE_URL"):
            return "local"
        return ""

    def _init_client(self) -> None:
        timeout_s = _llm_timeout_s()
        try:
            if self.provider == "anthropic":
                import anthropic  # type: ignore[import-not-found]
                # max_retries=0: the gateway is the SOLE retry controller. The
                # SDK default (2) retries 429s internally, honoring multi-second
                # Retry-After headers BEFORE we ever see the error — exactly the
                # hidden per-call stall that dragged rate-limited scans out.
                self._client = anthropic.Anthropic(
                    api_key=self.api_key, timeout=timeout_s, max_retries=0,
                )
            elif self.provider == "openai":
                import openai  # type: ignore[import-not-found]
                # See the anthropic note — disable the SDK's own 429 retry loop.
                self._client = openai.OpenAI(
                    api_key=self.api_key, timeout=timeout_s, max_retries=0,
                )
            elif self.provider == "gemini":
                # Prefer the current SDK (`google-genai`, imported as
                # `from google import genai`); fall back to the deprecated
                # `google-generativeai` if that's what's installed.
                try:
                    from google import genai as google_genai  # type: ignore[import-not-found]
                    # HttpOptions.timeout is in MILLISECONDS. Guard for older
                    # SDKs that lack it so a missing field never breaks init.
                    client_kwargs: dict[str, Any] = {"api_key": self.api_key}
                    try:
                        from google.genai import types as _genai_types  # type: ignore[import-not-found]
                        http_kwargs: dict[str, Any] = {"timeout": int(timeout_s * 1000)}
                        # attempts=1 disables the SDK's own retry loop (which
                        # otherwise retries 429s honoring their Retry-After) so
                        # the gateway is the sole retry controller. Guarded: not
                        # all SDK versions ship HttpRetryOptions.
                        _retry_opts = getattr(_genai_types, "HttpRetryOptions", None)
                        if _retry_opts is not None:
                            http_kwargs["retry_options"] = _retry_opts(attempts=1)
                        client_kwargs["http_options"] = _genai_types.HttpOptions(**http_kwargs)
                    except Exception:  # noqa: BLE001 — no HttpOptions/timeout/retry support
                        logger.debug("suppressed non-fatal exception", exc_info=True)
                    self._client = google_genai.Client(**client_kwargs)
                    self._gemini_sdk = "new"
                except ImportError:
                    import google.generativeai as legacy_genai  # type: ignore[import-not-found]
                    legacy_genai.configure(api_key=self.api_key)
                    self._client = legacy_genai.GenerativeModel(self.model)
                    self._gemini_sdk = "legacy"
            elif self.provider in LOCAL_PROVIDERS:
                # Local runtimes speak the OpenAI-compatible HTTP schema — no SDK,
                # just httpx (a base dependency). We keep the resolved base URL on
                # the instance and POST absolute URLs (avoids httpx base_url path-
                # join surprises where "/chat/completions" would drop "/v1").
                import httpx
                base = _local_base_url(self.provider)
                if not base:
                    self._init_error = (
                        "no local LLM endpoint configured — set HEAVEN_LLM_BASE_URL "
                        "for provider 'local' (e.g. http://localhost:1234/v1)"
                    )
                    return
                if self.provider == "local" and not self.model:
                    self._init_error = (
                        "no model set for provider 'local' — set HEAVEN_LLM_MODEL "
                        "to your served model id"
                    )
                    return
                headers: dict[str, str] = {}
                if self.api_key:  # optional bearer for a secured local endpoint
                    headers["Authorization"] = f"Bearer {self.api_key}"
                self._local_base = base
                self._client = httpx.Client(timeout=timeout_s, headers=headers)
            else:
                self._init_error = f"unknown provider '{self.provider}'"
        except ImportError as e:
            pkg = PROVIDER_PIP_PACKAGES.get(self.provider, self.provider)
            self._init_error = (
                f"SDK not installed for {self.provider}: {e} "
                f"(install with: pip install {pkg})"
            )
            logger.warning(
                f"LLM provider '{self.provider}' selected but SDK not installed — "
                f"install with: pip install {pkg}"
            )
        except Exception as e:
            self._init_error = f"client init failed: {e}"
            logger.error(f"LLM gateway init failed for {self.provider}: {e}")

    # ── public completion API ─────────────────────────────────────────────

    def complete(self, req: LLMRequest) -> LLMResponse:
        """Synchronous completion with retries, redaction, audit logging, and
        (optional) hybrid fallback to HEAVEN_LLM_FALLBACK_PROVIDER.

        If the primary provider is unavailable or returns nothing and a fallback
        provider is configured & available, one retry is made on the fallback —
        so a local-first setup keeps a cloud safety net (and vice-versa)."""
        resp = self._complete_once(req)
        if resp.ok() or not self._should_fallback(resp):
            return resp
        fb = self._fallback_complete(req)
        return fb if (fb is not None and fb.ok()) else resp

    def _complete_once(self, req: LLMRequest) -> LLMResponse:
        """One completion against THIS gateway's own provider (no fallback)."""
        if not self.available:
            return LLMResponse(
                text="", provider=self.provider, model=self.model,
                error=self._init_error or "gateway not initialized",
            )

        # Circuit breaker: a recent 429 means the key is rate-limited — don't
        # round-trip a doomed call, fall back immediately (see module note).
        gate = self._ratelimit_gate()
        if gate is not None:
            logger.debug(f"LLM call short-circuited by rate-limit cooldown: {gate}")
            return LLMResponse(
                text="", provider=self.provider, model=self.model, error=gate,
            )

        prompt, system, redactions = self._prepare(req)
        start = time.time()

        last_error: Optional[Exception] = None
        retried = False
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._dispatch(prompt, system, req)
                resp.latency_ms = (time.time() - start) * 1000
                resp.redactions_applied = redactions
                self._audit(req, resp)
                if req.response_schema is not None and resp.text:
                    resp.structured = self._parse_structured(resp.text, req.response_schema)
                return resp
            except Exception as e:
                last_error = e
                # Quota-exhaustion, rate-limit, auth and bad-request errors will
                # NOT clear on our few-seconds backoff (a 429 often says "retry
                # in 39s"). Retrying just makes an interactive call wait out 3
                # attempts before failing — worse than failing fast and letting
                # the caller fall back (e.g. remediation → knowledge base). Only
                # retry genuinely transient server/network errors.
                # A local endpoint that isn't up won't come up on a 1s backoff —
                # fail fast so we fall back (to non-LLM, or the hybrid provider)
                # instead of burning the retry budget.
                if getattr(self, "_is_local", False) and self._is_local_unreachable(e):
                    logger.warning(f"local LLM unreachable, not retrying: {e}")
                    break
                if not self._is_retryable(e):
                    # Arm the cooldown on a rate-limit/quota error so the rest of
                    # the scan's LLM calls skip the network and fall back fast.
                    if self._is_ratelimit_error(e):
                        self._arm_ratelimit_cooldown(e)
                    logger.warning(f"LLM call failed (non-retryable, not retrying): {e}")
                    break
                if attempt < self.MAX_RETRIES - 1:
                    retried = True
                    delay = min(
                        self.BASE_BACKOFF_S * (2 ** attempt) + random.uniform(0, 1),  # nosec B311
                        self.MAX_BACKOFF_S,
                    )
                    logger.warning(
                        f"LLM call failed (attempt {attempt + 1}/{self.MAX_RETRIES}): "
                        f"{e}. Retrying in {delay:.1f}s"
                    )
                    time.sleep(delay)

        latency_ms = (time.time() - start) * 1000
        prefix = "exhausted retries" if retried else "LLM call failed"
        err = LLMResponse(
            text="", provider=self.provider, model=self.model,
            latency_ms=latency_ms, redactions_applied=redactions,
            error=f"{prefix}: {last_error}",
        )
        self._audit(req, err)
        return err

    async def acomplete(self, req: LLMRequest) -> LLMResponse:
        """Async wrapper — runs the sync provider call in a thread."""
        import asyncio
        return await asyncio.to_thread(self.complete, req)

    # ── streaming (for the chat assistant) ────────────────────────────────

    def stream(self, req: LLMRequest) -> Iterator[str]:
        """Yield answer text incrementally.

        Every provider 'streams': native token streaming where supported, else a
        single chunk (the full completion). Honors the rate-limit breaker and the
        hybrid fallback exactly like `complete()` (both routed through it)."""
        if not self.available or self._ratelimit_gate() is not None:
            resp = self.complete(req)  # init-error / short-circuit / fallback path
            if resp.text:
                yield resp.text
            return
        prompt, system, _ = self._prepare(req)
        try:
            produced = False
            for piece in self._dispatch_stream(prompt, system, req):
                if piece:
                    produced = True
                    yield piece
            if produced:
                return
        except Exception as e:  # noqa: BLE001 — any streaming failure → non-stream fallback
            logger.warning(f"LLM streaming failed ({e}); falling back to non-streaming")
            if self._is_ratelimit_error(e):
                self._arm_ratelimit_cooldown(e)
        # Non-streaming fallback: covers an empty/failed stream AND the hybrid
        # cloud/local fallback (complete() applies it).
        resp = self.complete(req)
        if resp.text:
            yield resp.text

    async def astream(self, req: LLMRequest) -> AsyncIterator[str]:
        """Async token stream — bridges the sync generator to asyncio via a
        background thread + queue, so the WS chat endpoint streams without
        blocking the event loop."""
        import asyncio
        import threading as _threading
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        def _produce() -> None:
            try:
                for piece in self.stream(req):
                    loop.call_soon_threadsafe(queue.put_nowait, piece)
            except Exception as e:  # noqa: BLE001 — surface, never hang the consumer
                loop.call_soon_threadsafe(queue.put_nowait, f"[stream error: {e}]")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, sentinel)

        _threading.Thread(target=_produce, name="llm-astream", daemon=True).start()
        while True:
            item = await queue.get()
            if item is sentinel:
                break
            yield item

    def _dispatch_stream(self, prompt: str, system: Optional[str],
                         req: LLMRequest) -> Iterator[str]:
        """Provider-native token stream. Raises for providers that can't stream
        (the caller catches and falls back to a single-chunk completion)."""
        if self.provider in LOCAL_PROVIDERS:
            yield from self._stream_local(prompt, system, req)
            return
        if self.provider == "openai":
            messages: list[dict[str, str]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            stream = self._client.chat.completions.create(
                model=self.model, messages=messages, stream=True,
                max_tokens=req.max_tokens, temperature=req.temperature,
            )
            for chunk in stream:
                choice = chunk.choices[0] if chunk.choices else None
                delta = getattr(choice, "delta", None) if choice else None
                piece = getattr(delta, "content", None) if delta else None
                if piece:
                    yield piece
            return
        if self.provider == "anthropic":
            kwargs: dict[str, Any] = {
                "model": self.model, "max_tokens": req.max_tokens,
                "temperature": req.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                kwargs["system"] = system
            with self._client.messages.stream(**kwargs) as s:
                for piece in s.text_stream:
                    if piece:
                        yield piece
            return
        if self.provider == "gemini" and self._gemini_sdk == "new":
            from google.genai import types  # type: ignore[import-not-found]
            cfg_kwargs: dict[str, Any] = dict(
                max_output_tokens=req.max_tokens, temperature=req.temperature,
                system_instruction=system or None,
            )
            thinking = getattr(types, "ThinkingConfig", None)
            config = (
                types.GenerateContentConfig(thinking_config=thinking(thinking_budget=0), **cfg_kwargs)
                if thinking is not None else types.GenerateContentConfig(**cfg_kwargs)
            )
            for ev in self._client.models.generate_content_stream(
                model=self.model, contents=prompt, config=config,
            ):
                piece = getattr(ev, "text", "") or ""
                if piece:
                    yield piece
            return
        raise LLMProviderError(f"streaming not supported for provider '{self.provider}'")

    def _stream_local(self, prompt: str, system: Optional[str],
                      req: LLMRequest) -> Iterator[str]:
        """SSE token stream from an OpenAI-compatible local endpoint."""
        import json as _json
        import httpx
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self.model, "messages": messages,
            "temperature": req.temperature, "max_tokens": req.max_tokens,
            "stream": True,
        }
        url = f"{self._local_base}/chat/completions"
        try:
            with self._client.stream("POST", url, json=payload) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data:"):   # strip the SSE prefix
                        line = line[5:].strip()
                    if not line or line == "[DONE]":
                        continue
                    try:
                        obj = _json.loads(line)
                    except ValueError:
                        continue
                    choices = obj.get("choices") or []
                    delta = (choices[0].get("delta") if choices else {}) or {}
                    piece = delta.get("content")
                    if piece:
                        yield piece
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.PoolTimeout) as e:
            raise LLMProviderError(
                f"local LLM unreachable at {self._local_base}: {e}"
            ) from e

    # ── internals ────────────────────────────────────────────────────────

    def _prepare(self, req: LLMRequest) -> tuple[str, Optional[str], int]:
        prompt = req.prompt
        system = req.system
        redactions = 0
        if req.redact_secrets:
            prompt, c1 = redact_secrets(prompt)
            redactions += c1
            if system:
                system, c2 = redact_secrets(system)
                redactions += c2
        if req.response_schema is not None:
            schema_hint = self._schema_hint(req.response_schema)
            system = (system or "") + "\n\n" + schema_hint
        return prompt, system, redactions

    @staticmethod
    def _schema_hint(schema: Type[Any]) -> str:
        # Pydantic v2 provides model_json_schema(); fall back to a generic
        # instruction if the type isn't a Pydantic model.
        try:
            schema_dict = schema.model_json_schema()  # type: ignore[attr-defined]
            return (
                "Respond ONLY with a single JSON object matching this schema. "
                "No prose, no markdown fences. Schema:\n"
                + json.dumps(schema_dict)
            )
        except AttributeError:
            return "Respond ONLY with a single JSON object. No prose, no markdown fences."

    @staticmethod
    def _parse_structured(text: str, schema: Type[Any]) -> Any:
        # Tolerate fenced output (```json ... ```) defensively.
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```\s*$", "", cleaned)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise LLMProviderError(f"response not valid JSON: {e}") from e
        try:
            return schema.model_validate(data)  # type: ignore[attr-defined]
        except AttributeError:
            return data  # Not a Pydantic model — return raw dict
        except Exception as e:
            raise LLMProviderError(f"response failed schema validation: {e}") from e

    def _dispatch(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        if self.provider == "anthropic":
            return self._call_anthropic(prompt, system, req)
        if self.provider == "openai":
            return self._call_openai(prompt, system, req)
        if self.provider == "gemini":
            return self._call_gemini(prompt, system, req)
        if self.provider in LOCAL_PROVIDERS:
            return self._call_local(prompt, system, req)
        raise LLMProviderError(f"no dispatcher for provider '{self.provider}'")

    def _call_anthropic(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            if req.cache_static_prefix:
                kwargs["system"] = [{
                    "type": "text", "text": system,
                    "cache_control": {"type": "ephemeral"},
                }]
            else:
                kwargs["system"] = system

        result = self._client.messages.create(**kwargs)
        text = "".join(
            block.text for block in result.content if getattr(block, "type", "") == "text"
        )
        usage = getattr(result, "usage", None)
        err: Optional[str] = None
        if not text:
            stop = getattr(result, "stop_reason", None)
            err = (f"empty response (stop_reason={stop})" if stop
                   else "empty response from Anthropic")
        return LLMResponse(
            text=text, provider="anthropic", model=self.model,
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
            cached_tokens=getattr(usage, "cache_read_input_tokens", 0) if usage else 0,
            error=err,
        )

    def _call_openai(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        base: dict[str, Any] = {"model": self.model, "messages": messages}
        try:
            result = self._client.chat.completions.create(
                **base, max_tokens=req.max_tokens, temperature=req.temperature,
            )
        except Exception as e:  # noqa: BLE001
            # Reasoning models (o1/o3/gpt-5 family) rename max_tokens →
            # max_completion_tokens and only accept the default temperature.
            # Detect that specific rejection and retry so a pinned newer model
            # works instead of silently failing every AI call.
            msg = str(e).lower()
            if "max_completion_tokens" in msg or ("temperature" in msg and "unsupported" in msg) \
                    or "max_tokens" in msg:
                result = self._client.chat.completions.create(
                    **base, max_completion_tokens=req.max_tokens,
                )
            else:
                raise
        choice = result.choices[0] if result.choices else None
        message = getattr(choice, "message", None) if choice else None
        text = (getattr(message, "content", None) or "") if message else ""
        usage = getattr(result, "usage", None)
        err: Optional[str] = None
        if not text:
            refusal = getattr(message, "refusal", None) if message else None
            finish = getattr(choice, "finish_reason", None) if choice else None
            if refusal:
                err = f"model refused: {refusal}"
            elif finish and finish != "stop":
                err = f"empty response (finish_reason={finish})"
            else:
                err = "empty response from OpenAI"
        return LLMResponse(
            text=text, provider="openai", model=self.model,
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            error=err,
        )

    def _call_gemini(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        # `system` is the PREPARED system prompt from _prepare(): redacted and,
        # for structured requests, carrying the JSON-schema instruction. Using
        # it (not the raw req.system) is what makes response_schema work on
        # Gemini — without the schema hint the model free-forms and structured
        # parsing yields empty/degenerate objects.
        if self._gemini_sdk == "new":
            # Current SDK (`google-genai`): client-based, supports a real
            # system_instruction rather than prepending it to the prompt.
            from google.genai import types  # type: ignore[import-not-found]

            # CRITICAL: Gemini 2.5 models (which "gemini-flash-latest" resolves
            # to) run an internal "thinking" pass by DEFAULT that spends the
            # output-token budget on hidden reasoning BEFORE emitting any visible
            # text. With HEAVEN's bounded max_output_tokens that regularly
            # consumes the *entire* budget, so `.text` comes back empty
            # (finish_reason=MAX_TOKENS) and every AI feature silently falls back
            # to its non-LLM path — the exact "AI does nothing / only generic
            # remediation" symptom. Disable thinking so the full budget produces
            # answer text: faster, cheaper, and never empty.
            base_kwargs: dict[str, Any] = dict(
                max_output_tokens=req.max_tokens,
                temperature=req.temperature,
                system_instruction=system or None,
            )
            thinking_cfg = getattr(types, "ThinkingConfig", None)
            if thinking_cfg is not None:
                config = types.GenerateContentConfig(
                    thinking_config=thinking_cfg(thinking_budget=0), **base_kwargs,
                )
            else:  # older SDK without ThinkingConfig — nothing to disable
                config = types.GenerateContentConfig(**base_kwargs)
            try:
                result = self._client.models.generate_content(
                    model=self.model, contents=prompt, config=config,
                )
            except Exception:
                # A few models (e.g. gemini-2.5-pro) reject a zero thinking
                # budget. Retry with thinking left on but a larger budget so its
                # reasoning tokens don't starve the visible answer.
                config = types.GenerateContentConfig(
                    max_output_tokens=max(req.max_tokens, 2048) + 1024,
                    temperature=req.temperature,
                    system_instruction=system or None,
                )
                result = self._client.models.generate_content(
                    model=self.model, contents=prompt, config=config,
                )
        else:
            # Legacy SDK (`google-generativeai`): no distinct system message in
            # the basic API, so prepend it to the user prompt instead.
            full_prompt = (system + "\n\n" + prompt) if system else prompt
            result = self._client.generate_content(
                full_prompt,
                generation_config={
                    "max_output_tokens": req.max_tokens,
                    "temperature": req.temperature,
                },
            )

        # `.text` is a property that can be None (or warn) when a response has no
        # text part — safety block, or MAX_TOKENS with nothing but thinking. Read
        # it defensively and, when empty, surface *why* so the caller sees a real
        # reason instead of a silent blank (which just looks like "AI is broken").
        try:
            text = getattr(result, "text", "") or ""
        except Exception:  # noqa: BLE001 — malformed candidate, treat as empty
            text = ""
        usage = getattr(result, "usage_metadata", None)
        err: Optional[str] = None
        if not text:
            err = self._gemini_empty_reason(result)
        return LLMResponse(
            text=text, provider="gemini", model=self.model,
            input_tokens=getattr(usage, "prompt_token_count", 0) if usage else 0,
            output_tokens=getattr(usage, "candidates_token_count", 0) if usage else 0,
            error=err,
        )

    def _call_local(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        """Call an OpenAI-compatible local endpoint (Ollama / LM Studio /
        llama.cpp / vLLM / LocalAI) over plain HTTP.

        Structured output rides the existing schema-hint-in-system +
        JSON-parse path (see `_prepare`/`_parse_structured`) — no provider-native
        JSON mode, so this one code path works across every local server. A dead
        endpoint raises a distinct 'unreachable' error so `complete()` fails fast
        (and falls back) instead of retrying."""
        import httpx
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
            "stream": False,
        }
        url = f"{self._local_base}/chat/completions"
        try:
            r = self._client.post(url, json=payload)
            r.raise_for_status()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.PoolTimeout) as e:
            raise LLMProviderError(
                f"local LLM unreachable at {self._local_base} — is the server "
                f"running? (start Ollama, or run `heaven ai setup`): {e}"
            ) from e
        except httpx.HTTPStatusError as e:
            body = ""
            try:
                body = e.response.text[:300]
            except Exception:  # noqa: BLE001 — best-effort error body
                logger.debug("suppressed non-fatal exception", exc_info=True)
            raise LLMProviderError(f"local LLM HTTP {e.response.status_code}: {body}") from e
        data = r.json()
        choices = data.get("choices") or []
        message = (choices[0].get("message") if choices else {}) or {}
        text = (message.get("content") or "").strip()
        usage = data.get("usage") or {}
        err: Optional[str] = None
        if not text:
            finish = choices[0].get("finish_reason") if choices else None
            err = (f"empty response from local model (finish_reason={finish})"
                   if finish else "empty response from local model")
        return LLMResponse(
            text=text, provider=self.provider, model=self.model,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            error=err,
        )

    @staticmethod
    def _gemini_empty_reason(result: Any) -> str:
        """Best-effort explanation for an empty Gemini response."""
        feedback = getattr(result, "prompt_feedback", None)
        block = getattr(feedback, "block_reason", None) if feedback else None
        if block:
            return f"prompt blocked by safety filter ({block})"
        candidates = getattr(result, "candidates", None) or []
        if candidates:
            finish = getattr(candidates[0], "finish_reason", None)
            if finish is not None:
                name = getattr(finish, "name", str(finish))
                if name == "MAX_TOKENS":
                    return ("response truncated before any text (MAX_TOKENS) — "
                            "raise max_tokens")
                if name not in ("STOP", "FINISH_REASON_UNSPECIFIED"):
                    return f"response stopped: {name}"
        return "empty response from Gemini"

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        """Whether an LLM error is worth retrying on a short backoff.

        Retry genuinely transient conditions (500/502/503/504, model overloaded,
        deadline/timeout, connection reset). Do NOT retry quota-exhaustion, rate
        limits, auth failures or malformed requests — those won't recover in a
        few seconds, so retrying only delays an inevitable fallback. Errantly
        classifying is low-risk: worst case is one extra fallback vs. a few
        wasted retries.
        """
        msg = str(exc).lower()
        return not any(
            tok in msg for tok in (_RATELIMIT_ERROR_TOKENS + _AUTH_ERROR_TOKENS)
        )

    @staticmethod
    def _is_ratelimit_error(exc: Exception) -> bool:
        """Whether an error is a quota/rate-limit (429) — the class that arms the
        cooldown breaker. A subset of the non-retryable set (auth errors are
        non-retryable too, but fail instantly, so they don't warrant a cooldown)."""
        msg = str(exc).lower()
        return any(tok in msg for tok in _RATELIMIT_ERROR_TOKENS)

    @staticmethod
    def _is_local_unreachable(exc: Exception) -> bool:
        """Whether an error means a LOCAL endpoint isn't answering (server down,
        connection refused, timed out). Used only on the local path to fail fast
        rather than retry a server that won't come up in a second."""
        msg = str(exc).lower()
        return any(tok in msg for tok in (
            "unreachable", "connection refused", "connecterror", "connecttimeout",
            "failed to establish", "no route to host", "connection reset",
            "timed out", "read timeout", "name or service not known",
            "nodename nor servname", "all connection attempts failed",
        ))

    # ── hybrid fallback ──────────────────────────────────────────────────────

    def _should_fallback(self, resp: LLMResponse) -> bool:
        """Fall back only when this gateway allows it, a fallback provider is
        configured, and the primary result is not usable."""
        if resp.ok():
            return False
        if not getattr(self, "_allow_fallback", False):
            return False
        return bool(getattr(self, "fallback_provider", ""))

    def _get_fallback_gateway(self) -> Optional["LLMGateway"]:
        """Lazily build (and cache) the secondary gateway. Built with
        allow_fallback=False so it can never recurse into another fallback."""
        if getattr(self, "_fallback_gw", None) is not None:
            return self._fallback_gw
        prov = getattr(self, "fallback_provider", "")
        if not prov:
            return None
        try:
            gw = LLMGateway(provider=prov, allow_fallback=False)
        except Exception:  # noqa: BLE001 — a broken fallback must never crash the primary
            logger.debug("fallback gateway init failed", exc_info=True)
            return None
        self._fallback_gw = gw
        return gw

    def _fallback_complete(self, req: LLMRequest) -> Optional[LLMResponse]:
        gw = self._get_fallback_gateway()
        if gw is None or not gw.available:
            return None
        logger.info(f"LLM falling back to '{gw.provider}' ({gw.model})")
        return gw.complete(req)

    # ── rate-limit circuit breaker ────────────────────────────────────────

    def _ratelimit_gate(self) -> Optional[str]:
        """If a rate-limit cooldown is active, return the short-circuit message
        (so the caller falls back immediately); otherwise None. Read defensively
        so gateways built via ``__new__`` in tests never AttributeError."""
        until = getattr(self, "_ratelimited_until", 0.0)
        if until <= 0.0:
            return None
        remaining = until - time.monotonic()
        if remaining <= 0.0:
            return None
        reason = getattr(self, "_ratelimit_reason", "") or "rate limited"
        return (f"rate-limited: skipping LLM call for {remaining:.0f}s "
                f"(cooldown after: {reason})")

    def _arm_ratelimit_cooldown(self, exc: Exception) -> None:
        """Enter a cooldown after a rate-limit error so the rest of a scan's
        LLM calls short-circuit instead of each round-tripping a doomed 429.
        Window = server Retry-After hint when present, else the default floor,
        always clamped to MAX_RATELIMIT_COOLDOWN_S. HEAVEN_LLM_RATELIMIT_COOLDOWN=0
        disables the breaker."""
        cooldown = _ratelimit_cooldown_s()
        if cooldown <= 0.0:
            return
        hint = _parse_retry_after(str(exc))
        window = min(hint if hint is not None else cooldown, MAX_RATELIMIT_COOLDOWN_S)
        window = max(window, 1.0)
        lock = getattr(self, "_ratelimit_lock", None)
        if lock is not None:
            with lock:
                self._ratelimited_until = time.monotonic() + window
                self._ratelimit_reason = str(exc)[:200]
        else:  # __new__-built test double without a lock
            self._ratelimited_until = time.monotonic() + window
            self._ratelimit_reason = str(exc)[:200]
        logger.warning(
            f"LLM rate-limited — pausing LLM calls for {window:.0f}s "
            f"(further calls fall back to non-LLM paths): {exc}"
        )

    def _audit(self, req: LLMRequest, resp: LLMResponse) -> None:
        """Emit one structured log line per call — picked up by the audit handler."""
        logger.info(
            f"llm_call provider={resp.provider} model={resp.model} "
            f"in_tok={resp.input_tokens} out_tok={resp.output_tokens} "
            f"cached_tok={resp.cached_tokens} latency_ms={resp.latency_ms:.0f} "
            f"redactions={resp.redactions_applied} ok={resp.ok()}"
        )


# ═══════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════
#
# The gateway is a process-wide singleton, but a long-running `heaven serve`
# lets the operator add/replace an API key at runtime (Settings page,
# `heaven config set`). A naive cache-forever singleton would keep serving the
# stale (often empty) client until the next restart — the classic "I added my
# key but the AI still does nothing" bug. So the cache is keyed on a fingerprint
# of the env vars that DEFINE the gateway: whenever any of them changes, the
# next get_gateway() transparently rebuilds. That makes a saved key take effect
# on the very next AI call with no restart and without relying on any caller
# remembering to invoke reset_gateway(). A lock keeps it correct under the
# threaded API server (acomplete → asyncio.to_thread runs calls concurrently).

# Env vars whose value determines which client get_gateway() builds. If any of
# these changes, the cached gateway is stale and must be rebuilt.
_GATEWAY_ENV_KEYS = (
    "HEAVEN_LLM_PROVIDER",
    "HEAVEN_LLM_MODEL",
    "HEAVEN_OLLAMA_HOST",           # local: Ollama endpoint
    "HEAVEN_LLM_BASE_URL",          # local: generic OpenAI-compatible endpoint
    "HEAVEN_LLM_FALLBACK_PROVIDER", # hybrid fallback target
    # Cloud keys + HEAVEN_LLM_API_KEY (local bearer). The "" for keyless Ollama
    # is filtered out — it's not a real env var.
    *(e for e in PROVIDER_KEY_ENVS.values() if e),
)

_gateway: Optional[LLMGateway] = None
_gateway_fingerprint: Optional[str] = None
_gateway_lock = threading.Lock()


def _env_fingerprint() -> str:
    """Hash of the gateway-defining env vars. Hashed (not stored raw) so no key
    value lingers in a module global; only used to detect change, never logged."""
    h = hashlib.sha256()
    for key in _GATEWAY_ENV_KEYS:
        h.update(key.encode())
        h.update(b"=")
        h.update((os.environ.get(key) or "").encode())
        h.update(b"\x00")
    return h.hexdigest()


def get_gateway() -> LLMGateway:
    """Process-wide gateway that self-heals when its env changes.

    Rebuilds automatically whenever a provider/model/key env var differs from
    when the cached instance was built, so a key saved at runtime takes effect
    on the next call — no restart, no reliance on an explicit reset. Thread-safe.
    """
    global _gateway, _gateway_fingerprint
    fingerprint = _env_fingerprint()
    with _gateway_lock:
        if _gateway is None or _gateway_fingerprint != fingerprint:
            _gateway = LLMGateway()
            _gateway_fingerprint = fingerprint
        return _gateway


def reset_gateway() -> None:
    """Drop the cached gateway so the next get_gateway() rebuilds from scratch.

    Self-healing already covers env changes; this stays as an explicit, immediate
    invalidation (used by apply_settings and the test-LLM endpoint) and by tests.
    """
    global _gateway, _gateway_fingerprint
    with _gateway_lock:
        _gateway = None
        _gateway_fingerprint = None
