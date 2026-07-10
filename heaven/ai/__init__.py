"""
HEAVEN — AI namespace
Provider-agnostic LLM gateway and higher-level AI workflows.

The classical-ML risk model (NVD_model.pkl) lives in heaven.ml — that's
supervised regression. This namespace is for generative / agentic AI:
LLM gateway, recon parsing, attack-chain planning, FP triage.
"""

from heaven.ai.llm_gateway import (
    LLMGateway,
    LLMRequest,
    LLMResponse,
    LLMProviderError,
    get_gateway,
)
from heaven.ai.recon_agent import AssetProfile, ReconAgent
from heaven.ai.attack_chain_planner import (
    AttackChainPlanner, AttackPlan, AttackStep, PlannerOutput,
    plan_to_killchain_findings,
)
from heaven.ai.fp_review import (
    FPReviewer, FPReviewVerdict, review_borderline_findings,
)
from heaven.ai.vuln_hypothesis import (
    HypothesisOutput, VulnHypothesis, VulnHypothesisAgent, verify_hypotheses,
)

__all__ = [
    "LLMGateway", "LLMRequest", "LLMResponse", "LLMProviderError", "get_gateway",
    "ReconAgent", "AssetProfile",
    "AttackChainPlanner", "AttackPlan", "AttackStep", "PlannerOutput",
    "plan_to_killchain_findings",
    "FPReviewer", "FPReviewVerdict", "review_borderline_findings",
    "VulnHypothesisAgent", "VulnHypothesis", "HypothesisOutput", "verify_hypotheses",
]
