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
from typing import Any, Optional, Type

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
}

PROVIDER_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
}

# pip package name per provider — NOT always the provider name. In particular
# Gemini's SDK is `google-genai` (the current SDK; the older
# `google-generativeai` is deprecated but still accepted as a fallback), so
# "pip install gemini" is wrong.
PROVIDER_PIP_PACKAGES = {
    "anthropic": "anthropic",
    "openai": "openai",
    "gemini": "google-genai",
}

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

        if self.provider and self.api_key:
            self._init_client()

    @property
    def available(self) -> bool:
        return self._client is not None

    # ── client init per provider ──────────────────────────────────────────

    @staticmethod
    def _auto_detect_provider() -> str:
        for name, env in PROVIDER_KEY_ENVS.items():
            if os.environ.get(env):
                return name
        return ""

    def _init_client(self) -> None:
        timeout_s = _llm_timeout_s()
        try:
            if self.provider == "anthropic":
                import anthropic  # type: ignore[import-not-found]
                self._client = anthropic.Anthropic(api_key=self.api_key, timeout=timeout_s)
            elif self.provider == "openai":
                import openai  # type: ignore[import-not-found]
                self._client = openai.OpenAI(api_key=self.api_key, timeout=timeout_s)
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
                        client_kwargs["http_options"] = _genai_types.HttpOptions(
                            timeout=int(timeout_s * 1000),
                        )
                    except Exception:  # noqa: BLE001 — no HttpOptions/timeout support
                        pass
                    self._client = google_genai.Client(**client_kwargs)
                    self._gemini_sdk = "new"
                except ImportError:
                    import google.generativeai as legacy_genai  # type: ignore[import-not-found]
                    legacy_genai.configure(api_key=self.api_key)
                    self._client = legacy_genai.GenerativeModel(self.model)
                    self._gemini_sdk = "legacy"
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
        """Synchronous completion with retries, redaction, and audit logging."""
        if not self.available:
            return LLMResponse(
                text="", provider=self.provider, model=self.model,
                error=self._init_error or "gateway not initialized",
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
                if not self._is_retryable(e):
                    logger.warning(f"LLM call failed (non-retryable, not retrying): {e}")
                    break
                if attempt < self.MAX_RETRIES - 1:
                    retried = True
                    delay = min(
                        self.BASE_BACKOFF_S * (2 ** attempt) + random.uniform(0, 1),
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
        non_retryable = (
            "resource_exhausted", "quota", "insufficient_quota",
            "rate limit", "rate_limit", "429", "too many requests",
            "unauthorized", "401", "403", "permission denied",
            "api key not valid", "invalid api key", "invalid_api_key",
            "authentication", "invalid_request_error",
        )
        return not any(tok in msg for tok in non_retryable)

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
    *PROVIDER_KEY_ENVS.values(),  # ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
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
