"""HEAVEN — Agent Fleet blackboard.

The fleet coordinates through shared state, not by agents chatting to each other.
That shared state is the per-engagement SQLite store (the confirmed findings) plus
the cross-engagement knowledge graph (which techniques have worked on similar
targets before). This adapter is the single read/write seam between the roles and
that state, so roles stay pure and the storage details live in one place.

Everything here is offline-safe and best-effort: a missing store or a failed query
degrades to empty rather than raising, exactly as the existing autonomous loop
does. The blackboard never invents a finding — it only reads what deterministic
oracles have already confirmed and writes back oracle-verified results.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

from heaven.ai.fleet.roles import AgentTask, FleetState
from heaven.utils.logger import get_logger

logger = get_logger("ai.fleet.blackboard")


def _finding_to_dict(f: Any) -> dict[str, Any]:
    """Compact a :class:`heaven.engagement.Finding` (or a dict) into the shape a
    role reasons over and an LLM prompt can consume directly."""
    if isinstance(f, dict):
        get = f.get
    else:
        def get(k, default=None):
            return getattr(f, k, default)
    return {
        "id": get("id", "") or "",
        "target": get("target", "") or "",
        "vuln_type": get("vuln_type", "") or "",
        "title": get("title", "") or "",
        "severity": (get("severity", "") or "info"),
        "confidence": float(get("confidence", 0.0) or 0.0),
        "cve_id": get("cve_id", "") or "",
        "status": get("status", "") or "",
        "evidence": get("evidence", {}) or {},
    }


class Blackboard:
    """Read/write seam over the engagement store + knowledge graph.

    ``store`` is a :class:`heaven.engagement.EngagementStore` or ``None`` for a
    stateless dry run. All methods tolerate ``store is None``.
    """

    def __init__(self, store: Any = None, *, engagement_name: str = ""):
        self.store = store
        self.engagement_name = engagement_name

    # ── reads ─────────────────────────────────────────────────────────────
    def findings(self, *, limit: int = 10000) -> list[dict[str, Any]]:
        if self.store is None:
            return []
        try:
            rows = self.store.list_findings(limit=limit)
        except Exception:  # noqa: BLE001 — a read must never break a run
            logger.debug("blackboard.findings read failed", exc_info=True)
            return []
        return [_finding_to_dict(r) for r in rows]

    def finding_ids(self) -> set[str]:
        return {f["id"] for f in self.findings() if f.get("id")}

    def _scope_entries(self, *, in_scope_only: bool = True) -> list[tuple[str, str]]:
        """(target, kind) for each in-scope row; ``kind`` is 'host'/'domain'/…
        ('' when unknown). Kept internal so scope reads share one query and the
        scope guard can honour a deliberately domain-wide entry."""
        if self.store is None:
            return []
        try:
            entries = self.store.list_scope(in_scope_only=in_scope_only)
        except Exception:  # noqa: BLE001
            logger.debug("blackboard.scope read failed", exc_info=True)
            return []
        out: list[tuple[str, str]] = []
        for e in entries:
            if isinstance(e, dict):
                t, k = e.get("target", ""), e.get("kind", "")
            else:
                t, k = getattr(e, "target", ""), getattr(e, "kind", "")
            if t:
                out.append((str(t), str(k or "")))
        return out

    def scope(self, *, in_scope_only: bool = True) -> list[str]:
        return [t for (t, _k) in self._scope_entries(in_scope_only=in_scope_only)]

    def scope_domains(self, *, in_scope_only: bool = True) -> list[str]:
        """Targets the operator scoped **subdomain-wide** (an entry whose kind is
        'domain', or explicit wildcard syntax). The fleet's scope guard grants
        those subtrees — and only those — so discovered subdomains of a deliberately
        named domain stay in scope while a lone-host engagement never expands."""
        out: list[str] = []
        for (t, k) in self._scope_entries(in_scope_only=in_scope_only):
            if k == "domain" or t.startswith("*.") or t.startswith("."):
                out.append(t)
        return out

    def snapshot(
        self,
        *,
        seed_targets: Optional[dict[str, list[str]]] = None,
        objective: str = "",
        iteration: int = 0,
        active_mode: str = "full",
        history: Optional[list[AgentTask]] = None,
        authorized: bool = False,
    ) -> FleetState:
        """Build the read-only :class:`FleetState` roles see this iteration."""
        return FleetState(
            findings=self.findings(),
            scope=self.scope(),
            scope_domains=self.scope_domains(),
            seed_targets=dict(seed_targets or {}),
            objective=objective,
            iteration=iteration,
            active_mode=active_mode,
            history=list(history or []),
            authorized=authorized,
        )

    # ── writes ────────────────────────────────────────────────────────────
    def record_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> int:
        """Persist oracle-verified findings to the engagement store. Returns the
        count written. Best-effort per finding so one bad row never drops the rest.

        This is the ONLY path by which a fleet run adds findings, and it is only
        ever called with output a deterministic oracle already confirmed."""
        if self.store is None or not findings:
            return 0
        written = 0
        for f in findings:
            try:
                self.store.upsert_finding(scan_id, f)
                written += 1
            except Exception:  # noqa: BLE001 — persist the rest even if one fails
                logger.debug("blackboard.record_findings upsert failed", exc_info=True)
        return written

    # ── cross-engagement memory ───────────────────────────────────────────
    def technique_priors(self, profile: Any, *, top_n: int = 5) -> list[dict[str, Any]]:
        """Best-effort technique success priors for a target profile, used by the
        Coordinator to bias next-step selection. Empty on any failure."""
        try:
            from heaven.ai.knowledge_graph import get_knowledge_graph
            kg = get_knowledge_graph()
            ranked = kg.rank_techniques(profile, top_n=top_n)
        except Exception:  # noqa: BLE001 — memory is an optimization, never required
            logger.debug("technique_priors failed", exc_info=True)
            return []
        out: list[dict[str, Any]] = []
        for r in ranked:
            out.append({
                "technique": getattr(r, "technique", ""),
                "posterior_success_rate": float(getattr(r, "posterior_success_rate", 0.0) or 0.0),
                "evidence_count": int(getattr(r, "evidence_count", 0) or 0),
            })
        return out


def host_of(target: str) -> str:
    """Bare host for a URL/host target — shared helper for role spawners."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlparse(t).hostname or t).lower()
    return t.split("/", 1)[0].split(":", 1)[0].lower()
