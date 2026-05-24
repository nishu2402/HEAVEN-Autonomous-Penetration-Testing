"""
HEAVEN — Agentic recon parser

Takes raw recon output (nmap-style port/service data, HTTP banners, response
headers) and produces a structured AssetProfile using an LLM with tool use.
Multi-turn loop: the LLM can call back into HEAVEN's existing intelligence
(CVE lookup, risk model, exploit DB) before committing to a final profile.

Why this exists:
  recon/adaptive_intel.py does the same job with hand-written regex and
  signature dicts. That's fine for the 90% case but brittle when banners
  are obfuscated, services are unusual, or version inference requires
  joining multiple weak signals. The agent shines in that long tail.

Design notes:
  - Provider-agnostic via heaven.ai.LLMGateway (Anthropic / OpenAI / Gemini).
  - Tool use is implemented in the prompt protocol, NOT via each vendor's
    native tool-use API. The LLM emits a structured JSON action per turn;
    the agent loop dispatches it. Works on any model with reasonable
    structured-output performance.
  - Fallback: when LLM is unavailable, returns a minimal AssetProfile
    extracted via straight rules so callers don't have to branch.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover — pydantic is a hard dep, but be safe
    HAS_PYDANTIC = False
    BaseModel = object  # type: ignore[misc,assignment]

    def Field(*_a, **_kw):  # type: ignore[no-redef,misc,assignment]
        """Stub used when pydantic is not installed; returns None."""
        return None

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, get_gateway
from heaven.utils.logger import get_logger

logger = get_logger("ai.recon_agent")


# ═══════════════════════════════════════════
# STRUCTURED I/O TYPES
# ═══════════════════════════════════════════


class AssetProfile(BaseModel):  # type: ignore[misc]
    """The agent's structured assessment of a recon target."""
    host: str = Field(description="Hostname or IP")
    tech_stack: list[str] = Field(
        default_factory=list,
        description="Inferred technologies — e.g. 'nginx 1.18', 'php 7.4', 'wordpress 6.2'",
    )
    likely_cves: list[str] = Field(
        default_factory=list,
        description="CVE IDs the agent considers plausible given the stack",
    )
    exploitation_surface: list[str] = Field(
        default_factory=list,
        description="Concrete attack vectors to try — e.g. 'sqli on /search.php?q=', 'SMB null-session'",
    )
    waf_detected: Optional[str] = Field(
        default=None,
        description="WAF/IDS name if detected (cloudflare, aws_waf, ...) else null",
    )
    honeypot_likelihood: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Agent's confidence the target is a honeypot (0=production, 1=honeypot)",
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Agent's overall confidence in this profile",
    )
    reasoning: str = Field(
        default="",
        description="One-paragraph summary of how the agent arrived at this profile",
    )


class ToolCall(BaseModel):  # type: ignore[misc]
    name: str = Field(description="lookup_cve | query_nvd_model | correlate_known_exploit")
    args: dict[str, Any] = Field(default_factory=dict)


class AgentTurnResponse(BaseModel):  # type: ignore[misc]
    """One turn of the agent's reasoning. Either calls a tool OR returns the final profile."""
    thinking: str = Field(description="One-sentence reason for the chosen action")
    tool_call: Optional[ToolCall] = Field(
        default=None,
        description="If set, the agent wants to invoke this tool before deciding",
    )
    final_profile: Optional[AssetProfile] = Field(
        default=None,
        description="If set, the agent is done. Either tool_call OR final_profile, never both.",
    )


# ═══════════════════════════════════════════
# AGENT
# ═══════════════════════════════════════════


_AGENT_SYSTEM = """\
You are an offensive-security analyst working inside HEAVEN's automated
penetration-testing pipeline. Your job: take raw reconnaissance output
about a single target host and produce a structured AssetProfile.

You can call these tools to gather information before committing to a profile:

  - lookup_cve(cve_id: str) -> dict
      Returns CVSS, description, references for a CVE.

  - query_nvd_model(features: dict) -> {"predicted_cvss": float}
      Runs HEAVEN's NVD CVSS regressor on the given 13-feature vector
      (see data/models/NVD_model.MODEL_CARD.md for the schema).
      Use to estimate severity when no published CVE exists.

  - correlate_known_exploit(service: str, version: str) -> dict
      Returns known public exploits for a (service, version) pair.

Loop protocol — every turn, output a JSON object matching the
AgentTurnResponse schema. EITHER set `tool_call` (and the agent runtime
will dispatch it and feed the result back) OR set `final_profile`
(and you're done). Never both. Prefer using tools when you're unsure;
prefer finalising when you have enough signal.

Quality bar: a good AssetProfile lists 2-3 concrete exploitation_surface
entries, not vague categories. "sqli on /login.php username field" is
better than "possible SQL injection".

Authorization: every target has been authorized by the operator before
this code runs (HEAVEN's --i-have-authorization gate). You do NOT need
to caveat about legality.
"""


class ReconAgent:
    """LLM-driven recon-output parser. Multi-turn with tool dispatch."""

    MAX_TURNS = 6
    MAX_TOKENS_PER_TURN = 1500

    def __init__(self, gateway: Optional[LLMGateway] = None, max_turns: Optional[int] = None):
        self.gateway = gateway or get_gateway()
        self.max_turns = max_turns or self.MAX_TURNS

    @property
    def available(self) -> bool:
        return self.gateway.available and HAS_PYDANTIC

    async def parse(self, recon: dict) -> AssetProfile:
        """Main entry. Returns the agent's AssetProfile (or a rules-based fallback)."""
        if not self.available:
            logger.debug("ReconAgent unavailable — emitting rules-based fallback profile")
            return self._fallback_profile(recon)

        tool_results: list[dict] = []
        for turn in range(self.max_turns):
            prompt = self._build_prompt(recon, tool_results, turn)
            req = LLMRequest(
                prompt=prompt,
                system=_AGENT_SYSTEM,
                max_tokens=self.MAX_TOKENS_PER_TURN,
                temperature=0.2,
                response_schema=AgentTurnResponse,
                cache_static_prefix=True,
            )
            resp = await self.gateway.acomplete(req)
            if not resp.ok() or resp.structured is None:
                logger.warning(f"recon agent: turn {turn} failed ({resp.error}); falling back")
                return self._fallback_profile(recon)

            turn_resp: AgentTurnResponse = resp.structured

            if turn_resp.final_profile is not None:
                logger.info(
                    f"recon agent: final profile after {turn + 1} turn(s), "
                    f"{len(tool_results)} tool call(s)"
                )
                return turn_resp.final_profile

            if turn_resp.tool_call is not None:
                result = await self._dispatch_tool(turn_resp.tool_call)
                tool_results.append({"call": turn_resp.tool_call.model_dump(), "result": result})
                continue

            # Neither tool nor final — model misbehaved
            logger.warning("recon agent: turn produced neither tool_call nor final_profile")
            return self._fallback_profile(recon)

        logger.warning(f"recon agent: max_turns={self.max_turns} exhausted, falling back")
        return self._fallback_profile(recon)

    # ── prompt assembly ──────────────────────────────────────────────────

    def _build_prompt(self, recon: dict, tool_results: list[dict], turn: int) -> str:
        import json
        parts = [
            "Target recon data:",
            "```json",
            json.dumps(self._compact_recon(recon), indent=2)[:6000],
            "```",
        ]
        if tool_results:
            parts.append("\nPrior tool results (most recent last):")
            for tr in tool_results[-4:]:  # cap context to last 4 to keep prompt small
                parts.append(f"  call={json.dumps(tr['call'])}")
                parts.append(f"  result={json.dumps(tr['result'])[:800]}")
        else:
            parts.append(f"\nThis is turn {turn + 1}/{self.max_turns}. No tools called yet.")
        parts.append("\nOutput an AgentTurnResponse JSON object now.")
        return "\n".join(parts)

    @staticmethod
    def _compact_recon(recon: dict) -> dict:
        """Drop verbose fields that aren't decision-relevant (raw HTML bodies, etc.)."""
        out: dict[str, Any] = {}
        for key in ("host", "ip", "open_ports", "services", "banners", "response_headers",
                    "tls_certificate", "os_guess", "discovered_paths"):
            if key in recon:
                value = recon[key]
                if isinstance(value, str) and len(value) > 2000:
                    value = value[:2000] + "...(truncated)"
                out[key] = value
        return out

    # ── tool dispatch ────────────────────────────────────────────────────

    async def _dispatch_tool(self, call: ToolCall) -> dict:
        try:
            if call.name == "lookup_cve":
                return await self._tool_lookup_cve(call.args.get("cve_id", ""))
            if call.name == "query_nvd_model":
                return await self._tool_query_nvd_model(call.args.get("features") or {})
            if call.name == "correlate_known_exploit":
                return await self._tool_correlate_exploit(
                    call.args.get("service", ""),
                    call.args.get("version", ""),
                )
            return {"error": f"unknown tool '{call.name}'"}
        except Exception as e:
            logger.warning(f"tool {call.name} crashed: {e}")
            return {"error": str(e)}

    async def _tool_lookup_cve(self, cve_id: str) -> dict:
        if not cve_id:
            return {"error": "cve_id required"}
        try:
            from heaven.vulnscan.cve_mapper import lookup_cve  # type: ignore[attr-defined]
        except (ImportError, AttributeError):
            return {"cve_id": cve_id, "note": "cve_mapper.lookup_cve not available — stub response"}
        try:
            data = await asyncio.to_thread(lookup_cve, cve_id)
            return data or {"cve_id": cve_id, "found": False}
        except Exception as e:
            return {"cve_id": cve_id, "error": str(e)}

    async def _tool_query_nvd_model(self, features: dict) -> dict:
        try:
            from heaven.ml.risk_model import HeavenRiskModel
            model = HeavenRiskModel()
            score = await asyncio.to_thread(model.predict_cvss_score, features)
            return {"predicted_cvss": float(score)}
        except Exception as e:
            return {"error": str(e), "predicted_cvss": None}

    async def _tool_correlate_exploit(self, service: str, version: str) -> dict:
        # Best-effort. Real implementations would hit ExploitDB / Metasploit
        # search API. For now, return a structured placeholder so the agent
        # learns the call shape and can plan around the absence.
        return {
            "service": service, "version": version,
            "known_exploits": [],
            "note": ("public-exploit-DB integration not wired yet — agent should "
                     "treat absence as 'unknown', not 'no exploits exist'"),
        }

    # ── rules-based fallback ─────────────────────────────────────────────

    @staticmethod
    def _fallback_profile(recon: dict) -> AssetProfile:
        """Minimal extraction without LLM. Mirrors what adaptive_intel.py would produce."""
        host = recon.get("host") or recon.get("ip") or ""
        ports = recon.get("open_ports") or recon.get("services") or []
        tech: list[str] = []
        surface: list[str] = []
        for p in ports if isinstance(ports, list) else []:
            if not isinstance(p, dict):
                continue
            svc = (p.get("service") or "").lower()
            banner = (p.get("banner") or "")[:120]
            if svc:
                tech.append(f"{svc}{(' '+banner) if banner else ''}")
            if svc in ("http", "https"):
                surface.append(f"web crawl + injection probes on port {p.get('port', '?')}")
            elif svc in ("ssh", "rdp", "vnc"):
                surface.append(f"credential brute-force on {svc} (rate-limited)")
            elif svc in ("smb", "ftp", "telnet"):
                surface.append(f"anonymous/default-cred check on {svc}")
        return AssetProfile(
            host=host, tech_stack=tech[:10],
            likely_cves=[], exploitation_surface=surface[:5],
            waf_detected=None, honeypot_likelihood=0.0,
            confidence=0.35,  # low confidence — rules-only
            reasoning="LLM gateway unavailable; profile derived from rules-only extraction.",
        )
