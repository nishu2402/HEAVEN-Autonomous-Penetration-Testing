"""HEAVEN — post-exploitation session orchestration.

A :class:`PostExSession` represents one compromised host plus the credentials
that got HEAVEN there. It runs the full post-exploitation playbook in order and
returns a single, report-ready structure:

  1. **Enumerate**    — :class:`~heaven.postex.enum_engine.LinuxEnumEngine`
                        (self-contained privesc discovery, MITRE-tagged).
  2. **Loot**         — :class:`~heaven.postex.loot.LootHarvester`
                        (reusable credentials feeding the lateral loop).
  3. **Analyse (AI)** — optional LLM step that *ranks and explains* the escalation
                        paths the deterministic engine already found and suggests
                        pivot targets. The model never invents a finding — it
                        prioritises what the oracle proved, exactly like the
                        vuln-hypothesis agent. No LLM key → step is skipped.

The result carries an ATT&CK kill-chain (tactics/techniques touched) so the
report and the Navigator layer show a real post-access story, not a flat list.
Everything is authorization-gated and degrades gracefully with no ``asyncssh``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, get_gateway
from heaven.mitre.attack_mapper import TACTIC_NAMES, Tactic
from heaven.postex.enum_engine import EnumResult, LinuxEnumEngine
from heaven.postex.loot import LootHarvester, LootResult
from heaven.postex.win_enum_engine import WinEnumResult, WindowsEnumEngine
from heaven.utils.logger import get_logger

logger = get_logger("postex.session")


def _result_text(data: Any) -> str:
    """Coerce SSH command stdout (str or bytes) to text."""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data or ""

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover
    HAS_PYDANTIC = False

    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*_a: Any, **_kw: Any) -> Any:  # type: ignore[no-redef,misc,assignment]
        return None


# ATT&CK tactic order for kill-chain sequencing.
_TACTIC_ORDER = [
    Tactic.RECONNAISSANCE, Tactic.RESOURCE_DEV, Tactic.INITIAL_ACCESS,
    Tactic.EXECUTION, Tactic.PERSISTENCE, Tactic.PRIV_ESCALATION,
    Tactic.DEFENSE_EVASION, Tactic.CREDENTIAL_ACCESS, Tactic.DISCOVERY,
    Tactic.LATERAL_MOVEMENT, Tactic.COLLECTION, Tactic.C2,
    Tactic.EXFILTRATION, Tactic.IMPACT,
]
_TACTIC_RANK = {TACTIC_NAMES[t]: i for i, t in enumerate(_TACTIC_ORDER)}


class PostExAnalysis(BaseModel):  # type: ignore[misc]
    """LLM prioritisation of the deterministic findings (advice, not findings)."""
    top_vector_title: str = Field(
        default="", description="Exact title of the single best escalation path "
                                "from the provided list (must be one of them)")
    rationale: str = Field(default="", description="Why it's the best path (2-3 lines)")
    recommended_next_steps: list[str] = Field(
        default_factory=list, description="Concrete operator next actions")
    pivot_targets: list[str] = Field(
        default_factory=list, description="Hosts/services worth pivoting to")


@dataclass
class PostExReport:
    """Post-exploitation report.

    ``reusable_credentials`` (in-memory plaintext) is stored **outside** the
    dataclass field list — set via the property/setter after construction.
    This means ``dataclasses.asdict()``, ``dataclasses.fields()`` and the
    default ``__repr__`` cannot see it, so reflection-based serializers can
    never accidentally leak plaintext. Sanctioned serializers: :meth:`to_dict`.
    """

    host: str
    user: str
    success: bool
    facts: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    loot: dict[str, Any] = field(default_factory=dict)
    harvested_credentials: int = 0
    kill_chain: list[dict[str, Any]] = field(default_factory=list)
    ai_analysis: Optional[dict[str, Any]] = None
    error: str = ""

    def __post_init__(self) -> None:
        # In-memory (user, password) pairs for the lateral loop. Held OUTSIDE
        # the dataclass field list so `dataclasses.asdict()` / `fields()` /
        # default `repr()` cannot leak plaintext.
        self._reusable_credentials: list[tuple[str, str]] = []

    @property
    def reusable_credentials(self) -> list[tuple[str, str]]:
        """Snapshot copy of the in-memory reusable-credential list.

        Not a dataclass field; see class docstring. Callers get a defensive
        copy so downstream mutation cannot poison the report.
        """
        return list(self._reusable_credentials)

    @reusable_credentials.setter
    def reusable_credentials(self, value: list[tuple[str, str]]) -> None:
        self._reusable_credentials = [tuple(v) for v in value]  # type: ignore[misc]

    def wipe_secrets(self) -> None:
        """Zero the in-memory reusable-credential list. Call once the lateral
        loop has consumed them so nothing lingers in memory longer than needed.
        """
        self._reusable_credentials = []

    def __repr__(self) -> str:
        return (
            f"PostExReport(host={self.host!r}, user={self.user!r}, "
            f"success={self.success!r}, findings={len(self.findings)}, "
            f"reusable_credentials=<{len(self._reusable_credentials)} redacted>, "
            f"kill_chain={len(self.kill_chain)} tactics)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "user": self.user, "success": self.success,
            "facts": self.facts, "findings": self.findings, "loot": self.loot,
            "harvested_credentials": self.harvested_credentials,
            "kill_chain": self.kill_chain, "ai_analysis": self.ai_analysis,
            "finding_count": len(self.findings), "error": self.error,
        }


class PostExSession:
    """One compromised host → the full post-exploitation playbook."""

    def __init__(
        self, host: str, username: str, *, password: Optional[str] = None,
        private_key: Optional[str] = None, port: int = 22,
        authorized: bool = False, gateway: Optional[LLMGateway] = None,
        target_os: str = "auto",
    ):
        self.host = host
        self.username = username
        self.password = password
        self.private_key = private_key
        self.port = port
        self.authorized = authorized
        self.gateway = gateway or get_gateway()
        # "auto" | "linux" | "windows" — chooses the enumeration engine.
        self.target_os = (target_os or "auto").lower()

    async def run_full_postex(
        self, *, enable_loot: bool = True, ai_analysis: bool = True,
    ) -> PostExReport:
        if not self.authorized:
            return PostExReport(self.host, self.username, success=False,
                                error="aborted: session not authorized")

        # 1. Pick the OS-appropriate enumeration engine.
        os_kind = self.target_os
        if os_kind == "auto":
            os_kind = await self._detect_os()

        enum: EnumResult | WinEnumResult
        if os_kind == "windows":
            enum = await WindowsEnumEngine(authorized=True).enumerate(
                self.host, self.username, password=self.password,
                private_key=self.private_key, port=self.port)
        else:
            enum = await LinuxEnumEngine(authorized=True).enumerate(
                self.host, self.username, password=self.password,
                private_key=self.private_key, port=self.port)
        if not enum.success:
            return PostExReport(self.host, self.username, success=False,
                                error=enum.error)

        findings = enum.to_findings()

        # 2. Harvest reusable secrets. The loot battery is POSIX (cat/find/grep),
        #    so it only runs against Linux/Unix hosts; Windows credential
        #    locations are surfaced as enum findings instead.
        loot: Optional[LootResult] = None
        if enable_loot and os_kind != "windows":
            loot = await LootHarvester(authorized=True).harvest(
                self.host, self.username, password=self.password,
                private_key=self.private_key, port=self.port)
            findings.extend(loot.to_findings())

        facts_dict = enum.facts.to_dict()
        facts_dict["platform"] = os_kind
        report = PostExReport(
            host=self.host, user=self.username, success=True,
            facts=facts_dict,
            findings=findings,
            loot=loot.to_dict() if loot else {},
            harvested_credentials=(
                len(loot.harvested_credentials()) if loot else 0),
            kill_chain=build_kill_chain(findings),
        )
        # SSH-reusable creds only. Set via the property setter — the plaintext
        # lives outside the dataclass field list so it cannot be reached by
        # dataclasses.asdict() / fields() / default repr().
        if loot:
            report.reusable_credentials = loot.harvested_credentials(
                service_hint="ssh")

        # 3. AI prioritisation (optional, advice-only).
        if ai_analysis and self.available_ai and enum.vectors:
            report.ai_analysis = await self._ai_prioritize(enum, report.kill_chain)

        logger.info("postex %s@%s: %d finding(s), %d cred(s), %d kill-chain tactic(s)",
                    self.username, self.host, len(findings),
                    report.harvested_credentials, len(report.kill_chain))
        return report

    @property
    def available_ai(self) -> bool:
        return bool(self.gateway and self.gateway.available and HAS_PYDANTIC)

    async def _detect_os(self) -> str:
        """One lightweight SSH probe → 'windows' or 'linux'.

        ``uname -s`` prints the kernel name on Linux/Unix and fails (empty
        stdout) on a Windows ``cmd.exe`` shell, so its output disambiguates the
        two without a second heuristic. Any error defaults to 'linux'.
        """
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError:
            return "linux"
        client_keys = [self.private_key] if self.private_key else None
        try:
            async with asyncssh.connect(  # type: ignore[attr-defined]
                self.host, port=self.port, username=self.username,
                password=self.password, client_keys=client_keys,
                known_hosts=None,
            ) as conn:
                r = await conn.run("uname -s", check=False, timeout=15)
                out = (_result_text(r.stdout)).lower()
                if any(k in out for k in ("linux", "darwin", "bsd", "sunos", "aix")):
                    return "linux"
                return "windows"
        except Exception as e:
            logger.debug("OS detection failed (%s) — defaulting to linux", e)
            return "linux"

    async def _ai_prioritize(
        self, enum: EnumResult | WinEnumResult, kill_chain: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Ask the LLM to rank/explain the *already-found* vectors. Advice only."""
        vector_lines = "\n".join(
            f"- [{v['severity']}] {v['title']} — {v.get('abuse', '')}"
            for v in enum.vectors)
        facts = enum.facts
        # HostFacts (Linux) and WinHostFacts differ in a couple of fields.
        version = getattr(facts, "kernel", "") or getattr(facts, "build", "")
        uid = getattr(facts, "uid", None)
        account = (f"uid={uid}" if uid is not None
                   else ("admin" if getattr(facts, "is_admin", False) else "standard user"))
        prompt = (
            f"Host: {facts.hostname} ({facts.os}, version {version}), "
            f"current user '{facts.username}' ({account}, "
            f"groups: {', '.join(facts.groups)}).\n"
            f"Listening ports: {facts.listening_ports}. "
            f"Interfaces: {facts.interfaces}.\n\n"
            f"HEAVEN's deterministic engine confirmed these privilege-escalation "
            f"vectors on this host:\n{vector_lines}\n\n"
            "Pick the SINGLE best escalation path from the list above (use its "
            "exact title), explain why in 2-3 lines, list concrete next operator "
            "actions, and name any listening services/interfaces worth pivoting "
            "to. Do NOT invent vectors that are not in the list."
        )
        req = LLMRequest(
            prompt=prompt,
            system=("You are a senior red-team operator prioritising a foothold. "
                    "You only reason about the evidence provided; you never "
                    "fabricate access you cannot see."),
            temperature=0.3, max_tokens=1024, response_schema=PostExAnalysis,
        )
        try:
            resp = await self.gateway.acomplete(req)
        except Exception as e:
            logger.debug("postex AI analysis failed: %s", e)
            return {"available": False, "error": str(e)}
        analysis = resp.structured
        if analysis is None:
            return {"available": False, "error": resp.error or "no structured output"}

        # Honesty guard: the model's chosen title must be one we actually found.
        valid_titles = {v["title"] for v in enum.vectors}
        top = analysis.top_vector_title if analysis.top_vector_title in valid_titles else ""
        return {
            "available": True,
            "provider": resp.provider, "model": resp.model,
            "top_vector": top,
            "top_vector_hallucinated": bool(
                analysis.top_vector_title and not top),
            "rationale": analysis.rationale,
            "recommended_next_steps": list(analysis.recommended_next_steps)[:8],
            "pivot_targets": list(analysis.pivot_targets)[:8],
        }


def build_kill_chain(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group MITRE-tagged findings into an ordered ATT&CK kill-chain."""
    by_tactic: dict[str, dict[str, Any]] = {}
    for f in findings:
        mitre_block = f.get("mitre") or {}
        techniques = mitre_block.get("techniques", [])
        for tech in techniques:
            tactic = tech.get("tactic", "")
            if not tactic:
                continue
            slot = by_tactic.setdefault(tactic, {
                "tactic": tactic,
                "rank": _TACTIC_RANK.get(tactic, 99),
                "techniques": {},
            })
            slot["techniques"][tech["id"]] = tech["name"]
    chain = []
    for slot in sorted(by_tactic.values(), key=lambda s: s["rank"]):
        chain.append({
            "tactic": slot["tactic"],
            "techniques": [
                {"id": tid, "name": name}
                for tid, name in sorted(slot["techniques"].items())
            ],
        })
    return chain


__all__ = ["PostExSession", "PostExReport", "PostExAnalysis", "build_kill_chain"]
