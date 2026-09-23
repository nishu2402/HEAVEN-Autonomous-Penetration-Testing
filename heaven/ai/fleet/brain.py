"""HEAVEN — Agent Fleet intelligence ladder (FleetBrain).

Every fleet role asks the ``FleetBrain`` for reasoning. The brain resolves the
best *available* intelligence tier and always keeps a deterministic floor, so a
role can call it unconditionally and simply fall back to its rule-based path when
the brain reports it is unavailable. This is what makes the fleet run with zero
keys and zero stress: no brain is ever required.

Tiers (see the approved plan):
  * Tier 0 · deterministic — no LLM configured or the breaker is armed. The brain
    reports ``available == False`` and roles use their rule-based path.
  * Tier 1 · local — a keyless local runtime (Ollama / OpenAI-compatible) is the
    configured provider. Private, rate-limit-free.
  * Tier 4 · cloud — a cloud key is already present; used sparingly (the
    Coordinator's creative planning + the final narrative), never required.

Tiers 2 (one-tap local install) and 3 (bundled model) are UX affordances that
*produce* a Tier 1 runtime; they are not separate runtime states. ``describe``
reports whether a local brain could be enabled so the CLI/UI can offer it.

The brain enforces a process-wide cap on concurrent LLM calls
(``HEAVEN_FLEET_LLM_CONCURRENCY``) so a large logical fleet never fans out into a
storm of provider calls. The gateway's own rate-limit breaker is the backstop.
Nothing here raises into a caller: a failed brain call returns a not-ok response.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from heaven.ai.llm_gateway import (
    LOCAL_PROVIDERS,
    LLMGateway,
    LLMRequest,
    LLMResponse,
    get_gateway,
)
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.brain")

# Providers that require a key and reach an external service. deepseek speaks the
# OpenAI-compatible HTTP path but is still a remote, keyed provider (Tier 4).
CLOUD_PROVIDERS = frozenset({"anthropic", "openai", "gemini", "deepseek"})

TIER_DETERMINISTIC = 0
TIER_LOCAL = 1
TIER_CLOUD = 4


def _fleet_llm_concurrency() -> int:
    """Max concurrent brain calls fleet-wide. Small by default so 70-100 logical
    agents never become 70-100 simultaneous provider calls. A local model can
    take a higher value; a cloud key should stay low. Mirrors the bounded
    ``HEAVEN_FP_REVIEW_CONCURRENCY`` pattern."""
    try:
        return max(1, min(32, int(os.environ.get("HEAVEN_FLEET_LLM_CONCURRENCY", "4"))))
    except (TypeError, ValueError):
        return 4


class FleetBrain:
    """Shared reasoning gate for the whole fleet. Construct one per run and pass
    it to every role. Cheap to build: no network I/O at init."""

    def __init__(self, gateway: Optional[LLMGateway] = None, metrics=None):
        self.gateway = gateway or get_gateway()
        self.metrics = metrics
        self._sem: Optional[asyncio.Semaphore] = None
        self._concurrency = _fleet_llm_concurrency()

    # ── tier resolution ───────────────────────────────────────────────────
    @property
    def tier(self) -> int:
        """The configured runtime tier. Cheap; reflects configuration, not a live
        reachability probe (call-time failures degrade gracefully to Tier 0)."""
        gw = self.gateway
        if not gw.available:
            return TIER_DETERMINISTIC
        provider = getattr(gw, "provider", "") or ""
        if provider in LOCAL_PROVIDERS:
            return TIER_LOCAL
        if provider in CLOUD_PROVIDERS:
            return TIER_CLOUD
        return TIER_DETERMINISTIC

    @property
    def available(self) -> bool:
        """True when a brain is configured and not currently rate-limited. A role
        may still get a not-ok response at call time; it must handle that by
        falling back to its rule-based path."""
        return self.tier != TIER_DETERMINISTIC and not getattr(self.gateway, "rate_limited", False)

    def describe(self) -> dict:
        """Honest, offline-safe status for ``heaven doctor`` / API health / UI.

        Does a light local-reachability probe only when a local runtime *could*
        be relevant, so the operator sees a truthful 'AI optional' picture."""
        gw = self.gateway
        tier = self.tier
        label = {TIER_DETERMINISTIC: "deterministic", TIER_LOCAL: "local", TIER_CLOUD: "cloud"}[tier]
        info = {
            "tier": tier,
            "label": label,
            "provider": getattr(gw, "provider", "") or "",
            "model": getattr(gw, "model", "") or "",
            "available": self.available,
            "rate_limited": bool(getattr(gw, "rate_limited", False)),
            "concurrency": self._concurrency,
            "local_enabled": False,
            "local_can_enable": False,
        }
        # Report whether a local brain is present or could be one-tap enabled, so
        # the CLI/UI can offer Tier 2 without the fleet ever blocking on it.
        try:
            from heaven.ai import local_llm
            status = local_llm.local_status("ollama")
            info["local_enabled"] = bool(status.get("reachable") and status.get("models"))
            info["local_can_enable"] = bool(status.get("installed")) or bool(status.get("reachable"))
        except Exception:  # noqa: BLE001 — status is best-effort; never break describe()
            logger.debug("local_status probe failed in describe()", exc_info=True)
        return info

    # ── reasoning ─────────────────────────────────────────────────────────
    def _ensure_sem(self) -> asyncio.Semaphore:
        # Created lazily so it binds to the running event loop.
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._concurrency)
        return self._sem

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold one unit of the fleet-wide LLM concurrency budget. Roles wrap any
        direct call into an underlying agent (ReconAgent / VulnHypothesisAgent /
        AttackChainPlanner) in this so a large fleet never bursts past the cap the
        way ``think`` already does for its own calls."""
        sem = self._ensure_sem()
        async with sem:
            yield

    async def think(self, req: LLMRequest) -> LLMResponse:
        """Run one reasoning request through the bounded gate.

        Returns a not-ok :class:`LLMResponse` (never raises) when no brain is
        available or the call fails, so callers uniformly fall back to rules."""
        if not self.available:
            return LLMResponse(
                text="", provider=getattr(self.gateway, "provider", "") or "",
                model=getattr(self.gateway, "model", "") or "",
                error="no brain available (deterministic tier)",
            )
        async with self.slot():
            try:
                resp = await self.gateway.acomplete(req)
            except Exception as e:  # noqa: BLE001 — a brain failure must not abort a role
                logger.debug("brain think() failed: %s", e, exc_info=True)
                resp = LLMResponse(
                    text="", provider=getattr(self.gateway, "provider", "") or "",
                    model=getattr(self.gateway, "model", "") or "", error=str(e),
                )
        if self.metrics is not None:
            try:
                self.metrics.brain(ok=resp.ok(), tokens=int(getattr(resp, "output_tokens", 0) or 0))
            except Exception:  # noqa: BLE001
                logger.debug("metrics.brain record failed", exc_info=True)
        return resp
