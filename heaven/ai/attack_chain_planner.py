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

    def Field(*_a, **_kw):  # type: ignore[no-redef,misc,assignment]
        """Stub used when pydantic is not installed; returns None."""
        return None

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


# ═══════════════════════════════════════════════════════════════════════════
# DETERMINISTIC PLANNER — always available, no LLM required.
#
# Maps each finding's vulnerability class to its MITRE technique + kill-chain
# stage, then assembles per-host ordered chains and (where the surface allows)
# a cross-host lateral chain. Every step is grounded in a real finding — no
# fabricated CVEs or invented services. The LLM planner, when a key is present,
# proposes *creative* alternatives on top of this baseline.
# ═══════════════════════════════════════════════════════════════════════════

# vuln-class keyword → (technique_id, mitre_tactic, stage_rank, provides, base_conf)
# stage_rank orders steps within a chain (lower = earlier in the kill chain).
_TECHNIQUE_RULES: list[tuple[tuple[str, ...], str, str, int, str, float]] = [
    # (keywords, technique_id, tactic, stage_rank, provides_token, base_confidence)
    (("sql_injection", "sqli", "sql injection"), "T1190", "Initial Access", 2, "database-access", 0.8),
    (("command_injection", "rce", "remote_code", "os_command", "code_execution"),
     "T1190", "Initial Access", 2, "code-execution", 0.85),
    (("ssrf", "server_side_request"), "T1190", "Initial Access", 2, "internal-network-access", 0.7),
    (("xxe", "xml_external"), "T1190", "Initial Access", 2, "file-read", 0.7),
    (("lfi", "local_file", "path_traversal", "directory_traversal"),
     "T1083", "Discovery", 2, "file-read", 0.7),
    (("rfi", "remote_file"), "T1190", "Initial Access", 2, "code-execution", 0.75),
    (("deserial", "insecure_deserial"), "T1190", "Initial Access", 2, "code-execution", 0.75),
    (("upload", "file_upload", "unrestricted_upload"),
     "T1190", "Initial Access", 2, "code-execution", 0.7),
    (("default_cred", "weak_cred", "weak_password", "default_password", "guessable"),
     "T1078", "Initial Access", 2, "valid-account", 0.8),
    (("auth_bypass", "broken_auth", "authentication_bypass", "missing_auth", "unauthenticated"),
     "T1078", "Initial Access", 2, "valid-account", 0.7),
    (("idor", "bola", "broken_object", "access_control"),
     "T1190", "Initial Access", 2, "unauthorized-data", 0.65),
    (("xss", "cross_site_script"), "T1059.007", "Execution", 3, "client-session", 0.55),
    (("csrf", "cross_site_request"), "T1189", "Execution", 3, "forced-action", 0.45),
    (("open_redirect",), "T1204", "Execution", 3, "phishing-pivot", 0.4),
    (("jwt", "token"), "T1550", "Defense Evasion", 3, "forged-token", 0.55),
    (("cors",), "T1190", "Initial Access", 2, "cross-origin-data", 0.5),
    (("exposed_admin", "admin_panel", "management_interface"),
     "T1133", "Initial Access", 1, "admin-surface", 0.55),
    (("directory_listing", "dir_listing", "sensitive_file", "backup_file", "exposed_file",
      "information_disclosure", "info_disclosure"),
     "T1083", "Discovery", 1, "sensitive-info", 0.55),
    (("exposed_database", "database_exposure", "mongodb", "redis", "elasticsearch"),
     "T1210", "Initial Access", 2, "database-access", 0.7),
    (("subdomain_takeover",), "T1584", "Resource Development", 1, "controlled-subdomain", 0.6),
    (("smb", "eternalblue", "ms17"), "T1210", "Lateral Movement", 5, "remote-host", 0.7),
    (("rdp",), "T1021.001", "Lateral Movement", 5, "remote-host", 0.55),
    (("ssh",), "T1021.004", "Lateral Movement", 5, "remote-host", 0.55),
    (("outdated", "vulnerable_service", "known_vuln", "cve", "vulnerable_component",
      "vulnerable_dependency", "outdated_software"),
     "T1190", "Initial Access", 2, "service-exploit", 0.6),
    (("missing_security_header", "security_header", "clickjack", "hsts", "csp"),
     "T1190", "Initial Access", 4, "weakened-posture", 0.3),
    (("ssl", "tls", "certificate", "cipher"), "T1040", "Collection", 4, "traffic-intercept", 0.35),
]

# Objective phrasing per the highest-value capability a chain provides.
_OBJECTIVE_BY_TOKEN = {
    "code-execution": "Achieve remote code execution on the target host",
    "database-access": "Access and exfiltrate database contents",
    "internal-network-access": "Pivot into the internal network via SSRF",
    "valid-account": "Authenticate as a legitimate user and access protected functionality",
    "file-read": "Read sensitive server-side files",
    "remote-host": "Move laterally to an adjacent host",
    "unauthorized-data": "Access another user's data (broken access control)",
    "admin-surface": "Reach an exposed administrative interface",
    "sensitive-info": "Harvest exposed sensitive information",
    "database-exploit": "Compromise an exposed data store",
}

_SEV_WEIGHT = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "info": 0.2}


def _classify_finding(f: dict) -> Optional[tuple[str, str, int, str, float]]:
    """Map one finding to (technique_id, tactic, stage_rank, provides, base_conf).

    Returns ``None`` for findings with no offensive semantics (they still count
    toward context but don't become a chain step).
    """
    hay = " ".join(str(f.get(k, "")) for k in ("vuln_type", "type", "title", "cve_id")).lower()
    if not hay.strip():
        return None
    for keywords, tech, tactic, rank, provides, base in _TECHNIQUE_RULES:
        if any(k in hay for k in keywords):
            return tech, tactic, rank, provides, base
    return None


def _host_of_finding(f: dict) -> str:
    from urllib.parse import urlparse
    t = str(f.get("target") or f.get("url") or f.get("host") or "").strip()
    if not t:
        return "unknown-host"
    if "://" in t:
        return (urlparse(t).hostname or t).strip() or "unknown-host"
    return t.split("/", 1)[0].split(":", 1)[0].strip() or "unknown-host"


def build_deterministic_plans(
    findings: list[dict],
    assets: Optional[list[dict]] = None,
    objective_hint: str = "",
    max_plans: int = 3,
) -> "PlannerOutput":
    """Assemble grounded attack chains from findings without any LLM.

    One chain per host (steps ordered by kill-chain stage, deduped by
    technique), plus a cross-host lateral chain when a host yields code
    execution / valid credentials and another host is reachable.
    """
    if not HAS_PYDANTIC:
        return PlannerOutput(no_chain_possible=True, reasoning="pydantic unavailable")
    if not findings:
        return PlannerOutput(no_chain_possible=True,
                             reasoning="No findings supplied — cannot plan a chain.")

    # Group classifiable findings by host.
    by_host: dict[str, list[tuple[dict, tuple[str, str, int, str, float]]]] = {}
    for f in findings:
        cls = _classify_finding(f)
        if cls is None:
            continue
        by_host.setdefault(_host_of_finding(f), []).append((f, cls))

    if not by_host:
        return PlannerOutput(
            no_chain_possible=True,
            reasoning=("Findings are informational/hardening-class only (no directly "
                       "exploitable step) — expand the scan surface for a chain."),
        )

    plans: list[AttackPlan] = []
    for host, items in by_host.items():
        # Dedupe by (technique, capability) so distinct offensive outcomes stay
        # separate steps (SQLi→db-access and IDOR→unauthorized-data both map to
        # T1190 but are different steps), keeping the highest-confidence instance.
        best_by_tech: dict[tuple[str, str], tuple[dict, tuple[str, str, int, str, float]]] = {}
        for f, cls in items:
            key = (cls[0], cls[3])
            prev = best_by_tech.get(key)
            conf = float(f.get("confidence") or 0) or cls[4]
            prev_conf = (float(prev[0].get("confidence") or 0) or prev[1][4]) if prev else -1
            if conf > prev_conf:
                best_by_tech[key] = (f, cls)

        ordered = sorted(best_by_tech.values(), key=lambda ic: (ic[1][2], -(_SEV_WEIGHT.get(
            str(ic[0].get("severity", "")).lower(), 0.2))))
        steps: list[AttackStep] = []
        provided: list[str] = ["internet-access"]
        confs: list[float] = []
        tactics: list[str] = []
        for order, (f, cls) in enumerate(ordered, start=1):
            tech, tactic, _rank, provides, base = cls
            conf = round(min(0.95, (float(f.get("confidence") or 0) or base)), 2)
            confs.append(conf)
            if tactic not in tactics:
                tactics.append(tactic)
            desc = (f.get("title") or f.get("vuln_type") or tech)
            steps.append(AttackStep(
                order=order, technique_id=tech, description=str(desc)[:180],
                target_host=host,
                prerequisites=[provided[-1]] if order > 1 else ["internet-access"],
                provides=[provides], confidence=conf,
            ))
            provided.append(provides)
        if not steps:
            continue
        # Chain success ≈ mean step confidence discounted by chain length
        # (each extra dependency is another thing that can fail). Honest, bounded.
        mean_conf = sum(confs) / len(confs)
        est = round(min(0.9, mean_conf * (0.9 ** (len(steps) - 1))), 2)
        top_sev = max((str(f.get("severity", "")).lower() for f, _ in items),
                      key=lambda s: _SEV_WEIGHT.get(s, 0), default="low")
        risk = "high" if top_sev in ("critical", "high") else (
            "medium" if top_sev == "medium" else "low")
        final_token = steps[-1].provides[0] if steps[-1].provides else ""
        objective = objective_hint or _OBJECTIVE_BY_TOKEN.get(
            final_token, f"Compromise {host} via the confirmed findings")
        plans.append(AttackPlan(
            name=f"{host}: {steps[0].technique_id} → {steps[-1].technique_id}",
            objective=objective, steps=steps, estimated_success=est,
            risk_to_target=risk, mitre_tactics=tactics,
            reasoning=(f"Deterministic chain built from {len(steps)} confirmed finding(s) "
                       f"on {host}, ordered by kill-chain stage."),
        ))

    # Cross-host lateral chain: a host that grants code-exec/credentials → another host.
    if len(by_host) > 1:
        pivot_hosts = [h for h, items in by_host.items()
                       if any(cls[3] in ("code-execution", "valid-account", "internal-network-access")
                              for _f, cls in items)]
        others = [h for h in by_host if h not in pivot_hosts]
        if pivot_hosts and others:
            src, dst = pivot_hosts[0], others[0]
            lat_steps = [
                AttackStep(order=1, technique_id="T1190", description=f"Gain foothold on {src}",
                           target_host=src, prerequisites=["internet-access"],
                           provides=["foothold"], confidence=0.6),
                AttackStep(order=2, technique_id="T1021", description=f"Move laterally to {dst}",
                           target_host=dst, prerequisites=["foothold"],
                           provides=["remote-host"], confidence=0.45),
            ]
            plans.append(AttackPlan(
                name=f"Lateral: {src} → {dst}", objective=f"Pivot from {src} to {dst}",
                steps=lat_steps, estimated_success=0.4, risk_to_target="high",
                mitre_tactics=["Initial Access", "Lateral Movement"],
                reasoning="Cross-host chain: one host yields a foothold enabling lateral movement.",
            ))

    plans.sort(key=lambda p: p.estimated_success, reverse=True)
    return PlannerOutput(
        plans=plans[:max_plans], no_chain_possible=not plans,
        reasoning=(f"{len(plans)} deterministic chain(s) built from "
                   f"{len(findings)} finding(s) across {len(by_host)} host(s)."),
    )


class AttackChainPlanner:
    """Single-turn LLM planner that turns finding lists into AttackPlans.

    Always returns grounded chains: a deterministic builder runs unconditionally,
    and the LLM (when a key is configured) layers creative alternatives on top.
    """

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
        # Deterministic baseline always runs — the planner produces grounded
        # chains from real findings whether or not an LLM key is configured.
        deterministic = build_deterministic_plans(findings, assets, objective_hint, max_plans)

        if not findings:
            return deterministic  # no_chain_possible, nothing to enrich
        if not self.available:
            return deterministic

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
            # LLM failed — fall back to the grounded deterministic chains rather
            # than showing the operator an error with no plans.
            logger.warning(f"attack-chain planner LLM failed: {resp.error}; using deterministic")
            deterministic.reasoning += f" (LLM enrichment skipped: {resp.error})"
            return deterministic
        output: PlannerOutput = resp.structured
        # If the LLM proposed nothing usable, keep the deterministic chains.
        if not output.plans:
            return deterministic
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
