"""
HEAVEN — Attack-chain reasoning via LLM

Takes the asset graph + finding list and asks an LLM to propose an
ordered chain of steps from initial access to objective. Returns a
typed AttackPlan that wires into the existing scoring/reporting
infrastructure in `heaven/vulnscan/attack_chain.py` and
`heaven/mitre/kill_chain.py`.

This module does NOT replace those — they remain the deterministic
scoring layer. This module produces *creative* candidate chains that
the deterministic layer can then validate.

Design:
  - Single LLM call (no tool use loop). The reasoning fits in one
    prompt because chain depth is bounded (~5 steps typical).
  - Structured output via Pydantic — every plan validates against the
    same schema, so reporters can render it without per-LLM quirks.
  - When LLM is unavailable, returns an empty plan with explanation,
    not an exception. Callers gate behaviour on `plan.steps`.
"""

from __future__ import annotations

from typing import Optional

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover
    HAS_PYDANTIC = False
    BaseModel = object  # type: ignore[misc,assignment]
    Field = lambda *a, **kw: None  # type: ignore[misc,assignment]

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, get_gateway
from heaven.utils.logger import get_logger

logger = get_logger("ai.attack_planner")


class AttackStep(BaseModel):  # type: ignore[misc]
    order: int = Field(description="1-indexed step number in the chain")
    technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g., T1190 Exploit Public-Facing App)"
    )
    description: str = Field(description="Concrete action — e.g., 'Exploit SSRF on /api/proxy?url='")
    target_host: str = Field(description="Hostname/IP this step targets")
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Capability tokens required from prior steps — e.g., 'internal-network-access'",
    )
    provides: list[str] = Field(
        default_factory=list,
        description="Capability tokens this step grants if successful",
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Planner's confidence this step will succeed",
    )


class AttackPlan(BaseModel):  # type: ignore[misc]
    name: str = Field(description="Short label — e.g., 'SSRF → MongoDB exfil'")
    objective: str = Field(description="What the chain achieves if successful")
    steps: list[AttackStep] = Field(default_factory=list)
    estimated_success: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Planner's overall estimate that the full chain works",
    )
    risk_to_target: str = Field(
        default="low",
        description="How disruptive: low / medium / high. Operator-visible.",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="Distinct MITRE tactic names spanned (e.g., 'Initial Access', 'Lateral Movement')",
    )
    reasoning: str = Field(default="", description="Why these steps in this order")


class PlannerOutput(BaseModel):  # type: ignore[misc]
    """LLM emits this — a list of candidate plans ranked by estimated_success."""
    plans: list[AttackPlan] = Field(default_factory=list)
    no_chain_possible: bool = Field(
        default=False,
        description="True when the findings don't support any chain — operator should expand scan",
    )
    reasoning: str = Field(default="")


_PLANNER_SYSTEM = """\
You are an offensive-security strategist inside HEAVEN's authorized
penetration-testing pipeline. Your job: given a list of confirmed
findings across an asset graph, propose 1-3 ordered attack chains
from initial access to a concrete objective.

A good chain:
  - Uses ONLY findings present in the input (don't invent CVEs).
  - Lists 2-5 ordered steps. Longer chains are usually less likely.
  - Tags each step with the matching MITRE ATT&CK technique ID.
  - Tracks prerequisites/provides — step N's prerequisites must be
    provided by step <N (or be 'internet-access' for step 1).
  - Honestly reports estimated_success and risk_to_target. Don't pad.
  - Names the objective in business terms ('exfiltrate user PII',
    'gain domain admin', 'pivot to internal AWS account') not jargon.

When no plausible chain exists from the given findings, set
no_chain_possible=true and explain. Don't fabricate.

Output: a PlannerOutput JSON object, plans sorted by estimated_success
descending. Authorization is already established — no legal caveats.
"""


class AttackChainPlanner:
    """Single-turn LLM planner that turns finding lists into AttackPlans."""

    MAX_TOKENS = 3000

    def __init__(self, gateway: Optional[LLMGateway] = None):
        self.gateway = gateway or get_gateway()

    @property
    def available(self) -> bool:
        return self.gateway.available and HAS_PYDANTIC

    async def plan(
        self,
        findings: list[dict],
        assets: Optional[list[dict]] = None,
        objective_hint: str = "",
        max_plans: int = 3,
    ) -> PlannerOutput:
        """Generate up to max_plans attack chains from the given findings.

        Args:
            findings: list of HEAVEN finding dicts (target, vuln_type, severity, evidence, ...)
            assets:  optional asset graph context — hosts, services, trust relationships
            objective_hint: free-text steer for the planner ('aim for AD compromise')
            max_plans: cap on number of chains returned
        """
        if not self.available:
            return PlannerOutput(
                no_chain_possible=False,
                reasoning="LLM gateway unavailable; deterministic kill-chain analyzer still runs.",
            )
        if not findings:
            return PlannerOutput(
                no_chain_possible=True,
                reasoning="No findings supplied — cannot plan a chain.",
            )

        prompt = self._build_prompt(findings, assets or [], objective_hint, max_plans)
        req = LLMRequest(
            prompt=prompt,
            system=_PLANNER_SYSTEM,
            max_tokens=self.MAX_TOKENS,
            temperature=0.3,  # mild creativity but not chaos
            response_schema=PlannerOutput,
            cache_static_prefix=True,
        )
        resp = await self.gateway.acomplete(req)
        if not resp.ok() or resp.structured is None:
            logger.warning(f"attack-chain planner failed: {resp.error}")
            return PlannerOutput(
                no_chain_possible=False,
                reasoning=f"planner error: {resp.error}",
            )
        output: PlannerOutput = resp.structured
        # Truncate to max_plans even if model returned more
        output.plans = output.plans[:max_plans]
        logger.info(
            f"attack-chain planner: {len(output.plans)} plan(s), "
            f"{sum(len(p.steps) for p in output.plans)} step(s) total"
        )
        return output

    def _build_prompt(
        self,
        findings: list[dict],
        assets: list[dict],
        objective_hint: str,
        max_plans: int,
    ) -> str:
        import json
        # Compact each finding to the planner-relevant fields
        compact_findings = [
            {
                "target": f.get("target") or f.get("url", ""),
                "vuln_type": f.get("vuln_type") or f.get("type", ""),
                "severity": f.get("severity", ""),
                "cve_id": f.get("cve_id", ""),
                "title": (f.get("title") or "")[:140],
                "confidence": f.get("confidence", 0),
            }
            for f in findings[:80]  # cap; large lists are summarised
        ]
        parts = [
            f"Findings ({len(findings)} total, showing top {len(compact_findings)}):",
            "```json",
            json.dumps(compact_findings, indent=2)[:8000],
            "```",
        ]
        if assets:
            parts.append("\nAsset context:")
            parts.append("```json")
            parts.append(json.dumps(assets[:30], indent=2)[:3000])
            parts.append("```")
        if objective_hint:
            parts.append(f"\nOperator objective hint: {objective_hint}")
        parts.append(
            f"\nReturn at most {max_plans} plans. PlannerOutput JSON now."
        )
        return "\n".join(parts)


# ═══════════════════════════════════════════
# INTEGRATION WITH EXISTING KILL CHAIN
# ═══════════════════════════════════════════


def plan_to_killchain_findings(plan: AttackPlan) -> list[dict]:
    """Convert an AttackPlan to the dict shape `KillChainAnalyzer.ingest()` expects.

    The deterministic analyzer in `heaven/mitre/kill_chain.py` is the source
    of truth for phase-coverage scoring. By converting our LLM plan into its
    input shape, we let the same downstream reporter render both.
    """
    out: list[dict] = []
    for step in plan.steps:
        out.append({
            "type": step.technique_id,
            "vuln_type": step.technique_id,
            "title": step.description,
            "severity": "high",  # planner steps default to actionable severity
            "target": step.target_host,
            "cve_id": "",
            "_attack_plan_step": True,  # marker so the analyzer can attribute
            "_plan_name": plan.name,
            "_confidence": step.confidence,
        })
    return out
