"""
HEAVEN — LLM vulnerability-hypothesis agent (propose → verify).

This sits between recon and vuln-scanning and answers a different question than
the other AI layers: *given what we observe, which vulnerability classes are
worth actively probing, and where?* The LLM proposes a ranked list of
hypotheses; HEAVEN then **verifies each one with a real detector** and reports
only the confirmed findings.

The honesty guarantee is the whole point: the model never produces a finding.
It only decides which deterministic probe to point where. Every reported result
comes from :mod:`heaven.vulnscan` running a genuine oracle — so the LLM can
widen coverage ("try SSTI on the templated `name` field") without ever letting
an unverified guess into a report.

Degrades gracefully: no LLM key → ``available`` is False and ``propose`` returns
an empty list, so the rest of the pipeline is unaffected. Active verification is
gated on ``authorized`` (same posture as ``--i-have-authorization``).
"""
from __future__ import annotations

from typing import Any, Optional

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, get_gateway
from heaven.utils.logger import get_logger

logger = get_logger("ai.hypothesis")

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover
    HAS_PYDANTIC = False

    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*_a: Any, **_kw: Any) -> Any:  # type: ignore[no-redef,misc,assignment]
        return None


class VulnHypothesis(BaseModel):  # type: ignore[misc]
    """One thing the model thinks is worth probing."""
    vuln_class: str = Field(description="e.g. sqli, xss, ssrf, ssti, xxe, lfi, "
                                        "cmdi, graphql_introspection, cors, open_redirect")
    target_url: str = Field(description="Absolute URL to probe")
    param: str = Field(default="", description="Parameter to focus on, if any")
    rationale: str = Field(default="", description="Why this is plausible (one line)")
    prior: float = Field(default=0.5, ge=0.0, le=1.0,
                         description="Model's prior likelihood, 0..1")


class HypothesisOutput(BaseModel):  # type: ignore[misc]
    hypotheses: list[VulnHypothesis] = Field(default_factory=list)
    reasoning: str = Field(default="")


# ── which detector verifies which class ──

_INJECTION = {"sqli", "sql_injection", "blind_sqli", "xss", "reflected_xss",
              "stored_xss", "dom_xss", "lfi", "rfi", "path_traversal", "cmdi",
              "command_injection", "os_command_injection", "ssti",
              "server_side_template_injection"}
_OOB = {"ssrf", "server_side_request_forgery", "xxe", "xml_external_entity"}
_MISCONFIG = {"graphql", "graphql_introspection", "cors", "open_redirect",
              "jwt", "jwt_none_alg", "insecure_cookies", "security_headers",
              "security_misconfiguration"}


def _family(vuln_class: str) -> str:
    c = (vuln_class or "").lower()
    if c in _INJECTION:
        return "injection"
    if c in _OOB:
        return "oob"
    if c in _MISCONFIG:
        return "misconfig"
    return "unknown"


_SYSTEM = """\
You are a web-application penetration-testing strategist. Given a target's
observed technology stack and endpoints, propose a RANKED list of vulnerability
classes worth ACTIVELY testing, and exactly where.

Rules:
- Propose only classes a scanner can verify with an HTTP probe: sqli, xss, lfi,
  rfi, cmdi, ssti, ssrf, xxe, graphql_introspection, cors, open_redirect, jwt.
- Point each hypothesis at a concrete URL (+ parameter when relevant).
- `prior` is your honest likelihood (0..1) that a probe confirms it.
- You are ONLY prioritising what to test. You are NOT asserting a vulnerability
  exists — a deterministic probe will confirm or reject each hypothesis.
- Prefer high-value, plausible hypotheses over an exhaustive dump.
"""


class VulnHypothesisAgent:
    """LLM proposes vuln-class hypotheses; :func:`verify_hypotheses` confirms them."""

    MAX_TOKENS = 2000

    def __init__(self, gateway: Optional[LLMGateway] = None):
        self.gateway = gateway or get_gateway()

    @property
    def available(self) -> bool:
        return self.gateway.available and HAS_PYDANTIC

    async def propose(self, profile: dict, endpoints: list[dict],
                      max_hypotheses: int = 8) -> HypothesisOutput:
        """Ask the LLM for a ranked list of vuln-class hypotheses to test."""
        if not self.available:
            return HypothesisOutput(reasoning="LLM gateway unavailable")

        prompt = self._build_prompt(profile, endpoints, max_hypotheses)
        req = LLMRequest(
            prompt=prompt, system=_SYSTEM, max_tokens=self.MAX_TOKENS,
            temperature=0.4, response_schema=HypothesisOutput,
            cache_static_prefix=True,
        )
        resp = await self.gateway.acomplete(req)
        if not resp.ok() or resp.structured is None:
            logger.warning(f"hypothesis agent failed: {resp.error}")
            return HypothesisOutput(reasoning=f"agent error: {resp.error}")
        out: HypothesisOutput = resp.structured
        out.hypotheses = out.hypotheses[:max_hypotheses]
        logger.info("hypothesis agent proposed %d hypothesis(es)", len(out.hypotheses))
        return out

    @staticmethod
    def _build_prompt(profile: dict, endpoints: list[dict], max_hypotheses: int) -> str:
        tech = ", ".join(profile.get("tech_stack", []) or []) or "unknown"
        waf = profile.get("waf_detected") or "none detected"
        ep_lines = []
        for ep in endpoints[:40]:
            url = ep.get("url", "")
            params = ep.get("params") or ep.get("parameters") or []
            if isinstance(params, dict):
                params = list(params.keys())
            ep_lines.append(f"- {url}  params={list(params)[:8]}")
        eps = "\n".join(ep_lines) or "- (no parameterised endpoints discovered)"
        return (
            f"Target technology stack: {tech}\n"
            f"WAF/IDS: {waf}\n\n"
            f"Discovered endpoints:\n{eps}\n\n"
            f"Propose up to {max_hypotheses} ranked hypotheses (highest prior first)."
        )


async def verify_hypotheses(
    hypotheses: list[Any],
    *,
    authorized: bool,
    oast: Any = None,
    timeout: float = 12.0,
    max_targets: int = 25,
) -> dict[str, Any]:
    """Verify each hypothesis with a REAL detector; return only confirmed findings.

    ``hypotheses`` items may be :class:`VulnHypothesis` objects or plain dicts
    with ``vuln_class`` / ``target_url`` / ``param`` keys.

    Returns ``{"findings": [...], "verified": int, "rejected": int,
    "probed_targets": int}``. Every finding is produced by a genuine oracle in
    :mod:`heaven.vulnscan`; the triggering hypothesis is attached under
    ``evidence.llm_hypothesis`` purely for transparency.
    """
    if not authorized:
        logger.info("verify_hypotheses skipped: not authorized for active probing.")
        return {"findings": [], "verified": 0, "rejected": 0,
                "probed_targets": 0, "skipped": "authorization required"}

    # Normalise + group by (url, family).
    norm: list[dict] = []
    for h in hypotheses:
        d = h.model_dump() if hasattr(h, "model_dump") else dict(h)
        url = d.get("target_url") or d.get("url")
        if url:
            norm.append({"vuln_class": d.get("vuln_class", ""), "url": url,
                         "param": d.get("param", ""), "rationale": d.get("rationale", ""),
                         "prior": d.get("prior", 0.5)})

    groups: dict[tuple[str, str], dict] = {}
    for h in norm:
        key = (h["url"], _family(h["vuln_class"]))
        groups.setdefault(key, h)  # remember one hypothesis per (url, family)
    if len(groups) > max_targets:
        groups = dict(list(groups.items())[:max_targets])

    findings: list[dict] = []
    for (url, family), hyp in groups.items():
        try:
            produced = await _run_family_verifier(family, url, oast, timeout)
        except Exception as e:  # noqa: BLE001 - one probe failing never aborts the run
            logger.debug("verifier %s failed on %s: %s", family, url, e)
            produced = []
        for f in produced:
            ev = f.setdefault("evidence", {})
            ev["llm_hypothesis"] = {
                "vuln_class": hyp["vuln_class"],
                "rationale": hyp["rationale"],
                "prior": hyp["prior"],
            }
            f["source"] = f.get("source") or "llm_hypothesis_verified"
        findings.extend(produced)

    verified = len(findings)
    rejected = max(0, len(groups) - len({(f.get("target"), f.get("vuln_type")) for f in findings}))
    logger.info("hypothesis verify: %d confirmed from %d probed target(s)",
                verified, len(groups))
    return {"findings": findings, "verified": verified,
            "rejected": rejected, "probed_targets": len(groups)}


async def _run_family_verifier(family: str, url: str, oast: Any,
                               timeout: float) -> list[dict]:
    """Dispatch to the real detector for a hypothesis family."""
    if family == "injection":
        # Mirror the real pipeline: crawl the URL to discover its params/forms,
        # build injection targets, then run the genuine oracles.
        from heaven.recon.web_crawler import crawl_targets
        from heaven.vulnscan.injection_scanner import (
            build_injection_targets, scan_for_injections,
        )
        crawl = await crawl_targets([url])
        urls, forms = build_injection_targets(
            crawl.get("endpoints", []), seed_urls=[url])
        res = await scan_for_injections(urls or [url], forms_by_url=forms)
        return res.get("findings", [])
    if family == "oob":
        from heaven.vulnscan.oob_scanner import scan_oob
        res = await scan_oob([url], oast=oast)
        return res.get("findings", [])
    if family == "misconfig":
        from heaven.vulnscan.misconfig_scanner import scan_misconfig
        res = await scan_misconfig([url], timeout=timeout)
        return res.get("findings", [])
    return []
