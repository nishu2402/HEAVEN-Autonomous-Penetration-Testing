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

import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Type

from heaven.utils.logger import get_logger

logger = get_logger("ai.gateway")


# ═══════════════════════════════════════════
# PROVIDER DEFAULTS — keep current with Claude 4.x / GPT-4.x / Gemini 1.5+
# ═══════════════════════════════════════════

PROVIDER_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",   # balanced default; Opus 4.7 / Haiku 4.5 also valid
    "openai": "gpt-4o",
    "gemini": "gemini-1.5-pro",
}

PROVIDER_KEY_ENVS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


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
        try:
            if self.provider == "anthropic":
                import anthropic  # type: ignore[import-not-found]
                self._client = anthropic.Anthropic(api_key=self.api_key)
            elif self.provider == "openai":
                import openai  # type: ignore[import-not-found]
                self._client = openai.OpenAI(api_key=self.api_key)
            elif self.provider == "gemini":
                import google.generativeai as genai  # type: ignore[import-not-found]
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            else:
                self._init_error = f"unknown provider '{self.provider}'"
        except ImportError as e:
            self._init_error = f"SDK not installed for {self.provider}: {e}"
            logger.warning(
                f"LLM provider '{self.provider}' selected but SDK not installed — "
                f"install with: pip install {self.provider}"
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
                if attempt < self.MAX_RETRIES - 1:
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
        err = LLMResponse(
            text="", provider=self.provider, model=self.model,
            latency_ms=latency_ms, redactions_applied=redactions,
            error=f"exhausted retries: {last_error}",
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
            return self._call_gemini(prompt, req)
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
        return LLMResponse(
            text=text, provider="anthropic", model=self.model,
            input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
            cached_tokens=getattr(usage, "cache_read_input_tokens", 0) if usage else 0,
        )

    def _call_openai(self, prompt: str, system: Optional[str], req: LLMRequest) -> LLMResponse:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        result = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=req.max_tokens,
            temperature=req.temperature,
        )
        text = result.choices[0].message.content or ""
        usage = getattr(result, "usage", None)
        return LLMResponse(
            text=text, provider="openai", model=self.model,
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
        )

    def _call_gemini(self, prompt: str, req: LLMRequest) -> LLMResponse:
        # Gemini doesn't have a distinct "system" message in the basic API;
        # prepend it to the user prompt instead.
        full_prompt = prompt
        if req.system:
            full_prompt = req.system + "\n\n" + prompt
        config = {"max_output_tokens": req.max_tokens, "temperature": req.temperature}
        result = self._client.generate_content(full_prompt, generation_config=config)
        text = getattr(result, "text", "") or ""
        usage = getattr(result, "usage_metadata", None)
        return LLMResponse(
            text=text, provider="gemini", model=self.model,
            input_tokens=getattr(usage, "prompt_token_count", 0) if usage else 0,
            output_tokens=getattr(usage, "candidates_token_count", 0) if usage else 0,
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

_gateway: Optional[LLMGateway] = None


def get_gateway() -> LLMGateway:
    """Lazy-initialized process-wide gateway. Re-reads env on first call."""
    global _gateway
    if _gateway is None:
        _gateway = LLMGateway()
    return _gateway


def reset_gateway() -> None:
    """Force re-initialization on next get_gateway() call. For tests."""
    global _gateway
    _gateway = None
