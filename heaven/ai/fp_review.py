"""
HEAVEN — LLM-augmented false-positive review (Layer E)

Adds an optional second-opinion pass to the existing rule-based FP
suppressor in `heaven/vulnscan/fp_suppress.py`. Only fires on
*borderline* findings (configurable confidence band, default 0.4–0.7)
to keep latency and cost bounded.

The LLM gets the finding's evidence blob (request, response, payload,
match pattern) and decides:
  - keep:   true / false
  - confidence_delta: signed shift to apply to the existing confidence
  - reasoning: one paragraph, logged for audit

The verdict is *advisory* — it nudges the existing confidence, never
overrides a hard FP suppression. The deterministic rules remain
authoritative for any high-confidence FP signal.
"""

from __future__ import annotations

from typing import Optional

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover
    HAS_PYDANTIC = False
    BaseModel = object  # type: ignore[misc,assignment]

    def Field(*_a, **_kw):  # type: ignore[no-redef,misc,assignment]
        """Stub used when pydantic is not installed; returns None."""
        return None

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, get_gateway
from heaven.utils.logger import get_logger

logger = get_logger("ai.fp_review")


# Borderline band: only review findings inside this confidence range.
DEFAULT_REVIEW_BAND = (0.40, 0.70)


class FPReviewVerdict(BaseModel):  # type: ignore[misc]
    keep: bool = Field(description="True = finding stands, False = treat as false positive")
    confidence_delta: float = Field(
        default=0.0, ge=-0.4, le=0.4,
        description="Signed shift to apply to existing confidence (clamped). "
                    "Positive when LLM is more confident than rules; negative when less.",
    )
    reasoning: str = Field(default="", description="Why")
    notable_signals: list[str] = Field(
        default_factory=list,
        description="Specific signals in the evidence that drove the verdict",
    )


_REVIEW_SYSTEM = """\
You are a senior offensive-security analyst doing a final FP review on
a candidate vulnerability before it lands in a pen-test report.

You will see:
  - The candidate finding's metadata (vuln_type, target, severity, confidence)
  - The evidence blob (request sent, response received, payload, match pattern)
  - The reasons the rule-based suppressor already noted

Decide:
  - keep=true if the evidence genuinely supports the vulnerability claim
  - keep=false if it's a false positive (dynamic content, WAF noise,
    coincidental string match, baseline mismatch, etc.)
  - confidence_delta: a small adjustment (-0.4 to +0.4) reflecting how
    sure you are. Don't swing wildly — the existing confidence already
    incorporates baseline-jitter analysis.

Output one FPReviewVerdict JSON object. Be specific about the signals
you saw — vague reasoning is unhelpful to the operator who reviews this
later. Authorization is established; no legal caveats needed.
"""


class FPReviewer:
    """LLM-driven FP review wrapper. Cheap when disabled, useful when enabled."""

    MAX_TOKENS = 600  # short responses — keep cost down

    def __init__(self, gateway: Optional[LLMGateway] = None,
                 review_band: tuple[float, float] = DEFAULT_REVIEW_BAND):
        self.gateway = gateway or get_gateway()
        self.review_band = review_band

    @property
    def available(self) -> bool:
        return self.gateway.available and HAS_PYDANTIC

    def in_band(self, confidence: float) -> bool:
        lo, hi = self.review_band
        return lo <= confidence < hi

    async def review(self, finding: dict) -> Optional[FPReviewVerdict]:
        """Return a verdict, or None if the finding is out of band / LLM unavailable."""
        if not self.available:
            return None
        conf = float(finding.get("confidence", 0))
        if not self.in_band(conf):
            return None

        prompt = self._build_prompt(finding)
        req = LLMRequest(
            prompt=prompt,
            system=_REVIEW_SYSTEM,
            max_tokens=self.MAX_TOKENS,
            temperature=0.1,
            response_schema=FPReviewVerdict,
            cache_static_prefix=True,
        )
        resp = await self.gateway.acomplete(req)
        if not resp.ok() or resp.structured is None:
            logger.warning(f"fp review failed: {resp.error}")
            return None

        verdict: FPReviewVerdict = resp.structured
        logger.info(
            f"fp_review target={finding.get('target', '')[:60]!r} "
            f"vuln_type={finding.get('vuln_type', '')} keep={verdict.keep} "
            f"delta={verdict.confidence_delta:+.2f}"
        )
        return verdict

    @staticmethod
    def apply(finding: dict, verdict: FPReviewVerdict) -> dict:
        """Apply the verdict in-place. Mirrors fp_suppress.apply_verdict shape."""
        old_conf = float(finding.get("confidence", 0))
        new_conf = max(0.0, min(1.0, old_conf + verdict.confidence_delta))
        finding["confidence"] = round(new_conf, 3)
        finding["llm_review_kept"] = verdict.keep
        finding["llm_review_reasoning"] = verdict.reasoning
        finding["llm_review_signals"] = verdict.notable_signals
        if not verdict.keep:
            finding["suppressed"] = True
            finding["result"] = "false_positive"
        return finding

    # ── prompt assembly ──────────────────────────────────────────────────

    @staticmethod
    def _build_prompt(finding: dict) -> str:
        import json
        compact = {
            "vuln_type": finding.get("vuln_type") or finding.get("type", ""),
            "target":    finding.get("target", ""),
            "severity":  finding.get("severity", ""),
            "confidence_so_far": finding.get("confidence", 0),
            "evidence":  finding.get("evidence", {}),
            "fp_check_reasons": finding.get("fp_check_reasons", []),
            "title":     finding.get("title", "")[:200],
        }
        # Truncate huge evidence blobs to keep cost bounded
        ev = compact["evidence"]
        if isinstance(ev, dict):
            for k, v in list(ev.items()):
                if isinstance(v, str) and len(v) > 2000:
                    ev[k] = v[:2000] + "...(truncated)"
        return (
            "Candidate finding:\n```json\n"
            + json.dumps(compact, indent=2, default=str)[:4000]
            + "\n```\n\nReview this. Output an FPReviewVerdict JSON object."
        )


# ═══════════════════════════════════════════
# CONVENIENCE
# Used by vulnscan/fp_suppress.py via late import to avoid forcing
# the AI namespace as a hard dep of vulnscan.
# ═══════════════════════════════════════════


async def review_borderline_findings(
    findings: list[dict],
    review_band: tuple[float, float] = DEFAULT_REVIEW_BAND,
) -> list[dict]:
    """Run the LLM reviewer over every borderline finding in-place.

    Returns the same list (mutated). Non-borderline findings pass
    through unchanged. Safe to call when LLM is unavailable — does
    nothing in that case.
    """
    reviewer = FPReviewer(review_band=review_band)
    if not reviewer.available:
        return findings
    for f in findings:
        verdict = await reviewer.review(f)
        if verdict is not None:
            reviewer.apply(f, verdict)
    return findings
