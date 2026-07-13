"""
HEAVEN — AI Remediation Generator
Generates patch code for vulnerabilities via the provider-agnostic LLM gateway
(Anthropic / OpenAI / Gemini). Provider is selected by HEAVEN_LLM_PROVIDER or
auto-detected from the first API key present.
"""

from __future__ import annotations

from typing import Any, Optional

from heaven.ai import LLMGateway, LLMRequest
from heaven.devsecops.vuln_kb import remediation_text
from heaven.utils.logger import get_logger

logger = get_logger("devsecops.ai_remediation")


_REMEDIATION_SYSTEM = (
    "You are an expert DevSecOps engineer responding to a vulnerability "
    "discovered by an authorized penetration test. Produce specific, "
    "immediately-actionable remediation steps. Include code snippets where "
    "they help (Terraform, Nginx config, Python, IAM policy, etc.). "
    "Do not hedge. Do not suggest the operator 'consult a security expert'."
)


class AIRemediationEngine:
    """Generates remediation code for a vulnerability finding.

    The public API is unchanged from the original Gemini-only version:
    callers construct an instance and call .generate_patch(vuln_dict).
    Provider routing happens transparently inside the LLM gateway.
    """

    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None):
        # api_key parameter retained for backwards compatibility. If supplied,
        # it overrides the env-var-driven gateway and forces a fresh gateway
        # instance scoped to this engine.
        if api_key or provider:
            self._gateway: LLMGateway = LLMGateway(provider=provider, api_key=api_key)
        else:
            from heaven.ai import get_gateway
            self._gateway = get_gateway()

        self.available = self._gateway.available
        if not self.available:
            logger.warning(
                "AI Remediation gateway unavailable — set ANTHROPIC_API_KEY, "
                "OPENAI_API_KEY, or GEMINI_API_KEY (and install the matching SDK)."
            )

    def generate_patch(self, vuln: dict[str, Any]) -> str:
        """Return a remediation string for the given vulnerability dict.

        The fallback (used when no LLM is configured or a call fails) is not a
        generic one-liner: it is a full, class-accurate write-up built in-house
        from HEAVEN's vulnerability knowledge base, so remediation is excellent
        with *or* without an API key. Callers never see an exception.
        """
        text, _used_ai = self.generate_patch_with_source(vuln)
        return text

    def generate_patch_with_source(self, vuln: dict[str, Any]) -> tuple[str, bool]:
        """Like :meth:`generate_patch` but also reports whether the LLM actually
        produced the text (``True``) or the knowledge-base fallback did
        (``False``). Lets callers label output honestly instead of assuming
        "gateway available" == "AI wrote this" — a transient API failure falls
        back to the KB, and the UI should say so rather than claim AI output.
        """
        fallback = vuln.get("patch") or remediation_text(vuln)
        if not self.available:
            return fallback, False

        title = vuln.get("title", vuln.get("type", "Unknown"))
        desc = vuln.get("description", "")
        target = vuln.get("target", "")

        prompt = (
            f"Target: {target}\n"
            f"Vulnerability: {title}\n"
            f"Description: {desc}\n\n"
            f"Provide the remediation steps."
        )

        logger.info(f"Requesting AI remediation for {title}")
        resp = self._gateway.complete(LLMRequest(
            prompt=prompt,
            system=_REMEDIATION_SYSTEM,
            max_tokens=1024,
            temperature=0.2,
            cache_static_prefix=True,  # system prompt is identical across calls
        ))

        if not resp.ok():
            logger.error(f"AI remediation failed: {resp.error}")
            return fallback, False
        return resp.text, True
