"""HEAVEN — AI security assistant (chatbot).

A provider-agnostic conversational assistant on top of the LLM gateway. It works
with any configured provider — a local Ollama/OpenAI-compatible model (private,
no rate limits) or a cloud key — and can be *grounded* in the operator's active
engagement (top findings, asset counts, last scan) so it answers about THEIR
results, not generically.

Design contract (same as every other AI layer): the assistant only *assists*. It
reasons over findings the deterministic detectors produced; it never invents a
finding or claims a confirmation that isn't in the data. Operator secrets are
redacted before any prompt leaves the process (harmless locally, essential for a
cloud fallback).
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator, Optional

from heaven.ai.llm_gateway import LLMGateway, LLMRequest, LLMResponse, get_gateway
from heaven.utils.logger import get_logger

logger = get_logger("ai.chat")

SECURITY_SYSTEM_PROMPT = (
    "You are HEAVEN's security assistant — an expert offensive-security and "
    "vulnerability-management analyst embedded in an AUTHORIZED penetration-"
    "testing platform. Help the operator understand findings, prioritize "
    "remediation, plan next authorized testing steps, explain CVEs/CWEs/attack "
    "chains, and interpret scan output.\n"
    "Rules:\n"
    "- The operator is an authorized tester working on systems they have "
    "permission to assess. Answer offensive-security questions directly and "
    "practically.\n"
    "- Ground answers in the engagement context when it is provided; cite the "
    "specific finding/host/CVE you're referring to. If the context doesn't "
    "contain something, say so — never fabricate findings, hosts, CVEs, CVSS "
    "scores, or confirmation status.\n"
    "- Be concise and actionable. Prefer concrete commands, config, and code "
    "fixes over generic advice. Use Markdown.\n"
    "- Do not provide help for clearly illegal, non-consensual, or destructive "
    "activity against third parties; keep guidance within authorized testing."
)

# Keep grounding compact so it never blows the local model's context window.
_MAX_CONTEXT_CHARS = 4000
_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _finding_to_dict(f: Any) -> dict:
    """Best-effort finding → dict (Finding objects or already-dicts)."""
    if isinstance(f, dict):
        return f
    if hasattr(f, "model_dump"):
        try:
            return f.model_dump()  # type: ignore[no-any-return]
        except Exception:  # noqa: BLE001
            logger.debug("model_dump failed on finding", exc_info=True)
    return {k: getattr(f, k) for k in (
        "id", "title", "severity", "vuln_type", "target", "cve_id",
        "risk_score", "confidence", "status", "evidence",
    ) if hasattr(f, k)}


def build_engagement_context(store: Any, *, max_findings: int = 40) -> str:
    """Compact, read-only summary of the engagement for grounding, or ``""``.

    Accepts any store exposing ``list_findings`` / ``list_scans`` /
    ``get_engagement`` (the CLI's ``EngagementStore`` and the API's read store
    both qualify). Never raises."""
    if store is None:
        return ""
    try:
        findings = store.list_findings(limit=max(max_findings * 5, 200))
    except Exception:  # noqa: BLE001 — grounding is best-effort, never fatal
        logger.debug("engagement grounding: list_findings failed", exc_info=True)
        return ""

    lines: list[str] = []

    # Engagement name (optional).
    try:
        eng = store.get_engagement()
        name = getattr(eng, "name", None) if eng else None
        if name:
            lines.append(f"Engagement: {name}")
    except Exception:  # noqa: BLE001
        logger.debug("engagement grounding: get_engagement failed", exc_info=True)

    # Last scan (optional).
    try:
        scans = store.list_scans(limit=1) or []
        if scans:
            s = scans[0]
            tgt = s.get("target") or s.get("targets") or ""
            st = s.get("status") or ""
            lines.append(f"Last scan: {tgt} — {st}".rstrip(" —"))
    except Exception:  # noqa: BLE001
        logger.debug("engagement grounding: list_scans failed", exc_info=True)

    if not findings:
        lines.append("No findings recorded yet in this engagement.")
        return "\n".join(lines)[:_MAX_CONTEXT_CHARS]

    dicts = [_finding_to_dict(f) for f in findings]

    # Severity breakdown + confirmed count.
    sev_counts: dict[str, int] = {}
    confirmed = 0
    try:
        from heaven.utils.cvss import is_confirmed_finding
    except Exception:  # noqa: BLE001
        is_confirmed_finding = None  # type: ignore[assignment]
    for d in dicts:
        sev = str(d.get("severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if is_confirmed_finding is not None:
            try:
                if is_confirmed_finding(d):
                    confirmed += 1
            except Exception:  # noqa: BLE001 — confirmation is best-effort
                logger.debug("is_confirmed_finding failed on a grounding finding", exc_info=True)
    breakdown = ", ".join(f"{s}={sev_counts[s]}" for s in _SEV_ORDER if sev_counts.get(s))
    lines.append(f"Findings: {len(dicts)} total ({breakdown}); confirmed={confirmed}")

    # Distinct targets.
    targets = sorted({str(d.get("target") or "").strip() for d in dicts if d.get("target")})
    if targets:
        shown = ", ".join(targets[:12])
        more = f" (+{len(targets) - 12} more)" if len(targets) > 12 else ""
        lines.append(f"Hosts/targets ({len(targets)}): {shown}{more}")

    # Top findings by severity then risk_score.
    rank = {s: i for i, s in enumerate(reversed(_SEV_ORDER))}
    dicts.sort(
        key=lambda d: (
            rank.get(str(d.get("severity") or "info").lower(), 0),
            float(d.get("risk_score") or 0),
        ),
        reverse=True,
    )
    lines.append("Top findings:")
    for d in dicts[:max_findings]:
        title = str(d.get("title") or d.get("vuln_type") or "finding").strip()
        sev = str(d.get("severity") or "info").lower()
        tgt = str(d.get("target") or "").strip()
        cve = str(d.get("cve_id") or "").strip()
        tag = f" [{cve}]" if cve else ""
        row = f"- [{sev}] {title}{tag}" + (f" @ {tgt}" if tgt else "")
        lines.append(row)

    return "\n".join(lines)[:_MAX_CONTEXT_CHARS]


def _messages_to_prompt(messages: list[dict]) -> str:
    """Fold a chat history into a single transcript prompt (provider-agnostic —
    the gateway takes one prompt + one system string)."""
    parts: list[str] = []
    for m in messages or []:
        role = str(m.get("role") or "user").lower()
        content = str(m.get("content") or "").strip()
        if not content or role == "system":
            continue
        speaker = "Assistant" if role == "assistant" else "User"
        parts.append(f"{speaker}: {content}")
    parts.append("Assistant:")
    return "\n\n".join(parts)


class ChatAssistant:
    """Grounded, provider-agnostic security chatbot over the LLM gateway."""

    def __init__(self, gateway: Optional[LLMGateway] = None):
        self._gateway = gateway

    @property
    def gateway(self) -> LLMGateway:
        # Fall back to the self-healing singleton so a key/provider change (or a
        # freshly-started Ollama) is picked up without rebuilding the assistant.
        return self._gateway or get_gateway()

    @property
    def available(self) -> bool:
        return self.gateway.available

    def _system(self, store: Any, include_context: bool) -> str:
        parts = [SECURITY_SYSTEM_PROMPT]
        if include_context and store is not None:
            ctx = build_engagement_context(store)
            if ctx:
                parts.append(
                    "## Active engagement context (read-only, from the operator's "
                    "own authorized scans)\n" + ctx
                )
        return "\n\n".join(parts)

    def reply(self, messages: list[dict], *, store: Any = None,
              include_context: bool = True, max_tokens: int = 1024) -> LLMResponse:
        """One non-streaming reply. Returns an LLMResponse (``.ok()`` False when
        no LLM is configured or the call fails — caller shows a friendly note)."""
        gw = self.gateway
        if not gw.available:
            return LLMResponse(
                text="", provider=gw.provider, model=gw.model,
                error=gw._init_error or "no LLM configured — add a key or run `heaven ai setup`",
            )
        req = LLMRequest(
            prompt=_messages_to_prompt(messages),
            system=self._system(store, include_context),
            max_tokens=max_tokens, temperature=0.2,
        )
        return gw.complete(req)

    def stream(self, messages: list[dict], *, store: Any = None,
               include_context: bool = True, max_tokens: int = 1024) -> Iterator[str]:
        """Stream reply tokens. Yields nothing when no LLM is configured."""
        gw = self.gateway
        if not gw.available:
            return
        req = LLMRequest(
            prompt=_messages_to_prompt(messages),
            system=self._system(store, include_context),
            max_tokens=max_tokens, temperature=0.2,
        )
        yield from gw.stream(req)

    async def astream(self, messages: list[dict], *, store: Any = None,
                      include_context: bool = True,
                      max_tokens: int = 1024) -> "AsyncIterator[str]":
        """Async token stream for the WS chat endpoint. Yields nothing when no
        LLM is configured."""
        gw = self.gateway
        if not gw.available:
            return
        req = LLMRequest(
            prompt=_messages_to_prompt(messages),
            system=self._system(store, include_context),
            max_tokens=max_tokens, temperature=0.2,
        )
        async for piece in gw.astream(req):
            yield piece
