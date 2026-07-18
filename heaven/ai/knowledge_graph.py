"""
HEAVEN — Cross-engagement knowledge graph

SQLite-backed memory of (target_profile, technique, outcome) tuples.
Each scan that completes adds rows; the autonomous planner queries the
graph at planning time to bias next-step selection toward techniques
that have worked on similar targets in the past.

Schema (intentionally tiny — premature ML feature design is the bug to
avoid):

    target_profile(
        id, fingerprint, os, web_tech, ad_domain, cloud,
        first_seen, last_seen
    )
    -- fingerprint is a stable hash of (os, web_tech, top open ports)

    attempt(
        id, target_profile_id, technique, tactic_phase,
        outcome,            -- "success" | "failure" | "inconclusive"
        confidence_delta,   -- how much we updated our prior
        finding_id,         -- nullable — link to the engagement finding
        engagement_name,
        observed_at
    )

    technique_stat(
        technique, attempts, successes, last_success
    )
    -- materialised view; rebuilt after every record_attempt call

Query API:
    rank_techniques(profile, top_n=5)
        → [(technique, posterior_success_rate, evidence_count), ...]
    record_attempt(profile, technique, outcome, ...)
        → updates both raw and materialised tables

This is decision-support, not auto-targeting: the planner gets advice
but still makes the call. The DB lives at ~/.heaven/knowledge.db by
default (one file shared across all engagements on a host).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from heaven.utils.logger import get_logger

logger = get_logger("ai.knowledge_graph")


_DEFAULT_DB = Path.home() / ".heaven" / "knowledge.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS target_profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE NOT NULL,
    os TEXT DEFAULT '',
    web_tech TEXT DEFAULT '',
    ad_domain TEXT DEFAULT '',
    cloud TEXT DEFAULT '',
    open_ports_top TEXT DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attempt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_profile_id INTEGER NOT NULL REFERENCES target_profile(id),
    technique TEXT NOT NULL,
    tactic_phase TEXT DEFAULT '',
    outcome TEXT NOT NULL CHECK (outcome IN ('success','failure','inconclusive')),
    confidence_delta REAL DEFAULT 0.0,
    finding_id TEXT DEFAULT '',
    engagement_name TEXT DEFAULT '',
    observed_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempt_profile ON attempt(target_profile_id);
CREATE INDEX IF NOT EXISTS idx_attempt_technique ON attempt(technique);

CREATE TABLE IF NOT EXISTS technique_stat (
    technique TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 0,
    successes INTEGER DEFAULT 0,
    last_success REAL DEFAULT 0
);
"""


# ═══════════════════════════════════════════
# TYPES
# ═══════════════════════════════════════════


@dataclass
class TargetProfile:
    """Fingerprintable description of a scanned target."""
    os: str = ""
    web_tech: str = ""            # comma-separated stack labels (e.g. "php,wordpress")
    ad_domain: str = ""           # populated for AD recon targets
    cloud: str = ""               # "aws" | "gcp" | "azure" | ""
    open_ports_top: list[int] = field(default_factory=list)  # top 10 from nmap

    def fingerprint(self) -> str:
        """Stable hash so two scans of the "same kind of box" map together."""
        parts = [
            self.os.lower(),
            ",".join(sorted(self.web_tech.lower().split(","))),
            self.ad_domain.lower(),
            self.cloud.lower(),
            ",".join(str(p) for p in sorted(self.open_ports_top[:10])),
        ]
        return hashlib.sha1("|".join(parts).encode("utf-8"), usedforsecurity=False).hexdigest()[:16]

    def to_row(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint(),
            "os": self.os, "web_tech": self.web_tech,
            "ad_domain": self.ad_domain, "cloud": self.cloud,
            "open_ports_top": ",".join(str(p) for p in self.open_ports_top[:10]),
        }


@dataclass
class TechniqueRanking:
    """Output of rank_techniques(): one technique with its Bayesian-smoothed prior."""
    technique: str
    posterior_success_rate: float    # Beta(alpha+successes, beta+failures)/total
    evidence_count: int              # local + global attempt count
    last_success_at: float = 0.0


# ═══════════════════════════════════════════
# STORE
# ═══════════════════════════════════════════


class KnowledgeGraph:
    """Cross-engagement memory store. Process-wide singleton ok."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path(os.environ.get("HEAVEN_KNOWLEDGE_DB",
                                                       str(_DEFAULT_DB)))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    # ── Profiles ─────────────────────────────────────────────────────────

    def upsert_profile(self, profile: TargetProfile) -> int:
        now = time.time()
        row = profile.to_row()
        with self._conn() as c:
            existing = c.execute(
                "SELECT id FROM target_profile WHERE fingerprint = ?",
                (row["fingerprint"],),
            ).fetchone()
            if existing:
                c.execute(
                    "UPDATE target_profile SET last_seen = ? WHERE id = ?",
                    (now, existing["id"]),
                )
                return int(existing["id"])
            cur = c.execute(
                """INSERT INTO target_profile
                   (fingerprint, os, web_tech, ad_domain, cloud, open_ports_top,
                    first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["fingerprint"], row["os"], row["web_tech"], row["ad_domain"],
                 row["cloud"], row["open_ports_top"], now, now),
            )
            return int(cur.lastrowid or 0)

    # ── Attempts ─────────────────────────────────────────────────────────

    def record_attempt(
        self, profile: TargetProfile, technique: str,
        outcome: str, *,
        tactic_phase: str = "",
        confidence_delta: float = 0.0,
        finding_id: str = "",
        engagement_name: str = "",
    ) -> None:
        """Record a single attempt. `outcome` must be in {success, failure, inconclusive}."""
        if outcome not in ("success", "failure", "inconclusive"):
            raise ValueError(f"outcome must be success|failure|inconclusive, got {outcome!r}")
        profile_id = self.upsert_profile(profile)
        now = time.time()
        with self._conn() as c:
            c.execute(
                """INSERT INTO attempt
                   (target_profile_id, technique, tactic_phase, outcome,
                    confidence_delta, finding_id, engagement_name, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (profile_id, technique, tactic_phase, outcome, confidence_delta,
                 finding_id, engagement_name, now),
            )
            # Materialise into technique_stat
            c.execute(
                "INSERT INTO technique_stat (technique, attempts, successes, last_success) "
                "VALUES (?, 1, ?, ?) "
                "ON CONFLICT(technique) DO UPDATE SET "
                "  attempts = attempts + 1, "
                "  successes = successes + excluded.successes, "
                "  last_success = MAX(last_success, excluded.last_success)",
                (technique, 1 if outcome == "success" else 0,
                 now if outcome == "success" else 0),
            )

    # ── Queries ──────────────────────────────────────────────────────────

    def rank_techniques(
        self, profile: TargetProfile, top_n: int = 5,
        beta_prior_strength: float = 4.0,
    ) -> list[TechniqueRanking]:
        """Beta-smoothed posterior success rate per technique against this
        profile (local) + the global stat as a fallback prior.
        """
        fp = profile.fingerprint()
        with self._conn() as c:
            # Local — attempts against profiles with matching fingerprint
            local = c.execute(
                """SELECT a.technique,
                          SUM(CASE WHEN a.outcome='success' THEN 1 ELSE 0 END) AS s,
                          COUNT(*) AS n,
                          MAX(CASE WHEN a.outcome='success' THEN a.observed_at ELSE 0 END) AS last_s
                   FROM attempt a
                   JOIN target_profile tp ON tp.id = a.target_profile_id
                   WHERE tp.fingerprint = ?
                   GROUP BY a.technique""",
                (fp,),
            ).fetchall()
            local_map = {r["technique"]: r for r in local}

            # Global — technique_stat as a prior
            globals_ = c.execute(
                "SELECT technique, attempts, successes, last_success FROM technique_stat"
            ).fetchall()

        rankings: list[TechniqueRanking] = []
        for g in globals_:
            tech = g["technique"]
            global_s = g["successes"]
            global_n = g["attempts"]
            global_rate = (global_s + 1) / (global_n + 2) if global_n else 0.5

            local_row = local_map.get(tech)
            if local_row:
                local_s, local_n = local_row["s"], local_row["n"]
                # Beta prior: pseudo-observations centred at the global rate
                alpha = beta_prior_strength * global_rate
                beta = beta_prior_strength * (1 - global_rate)
                posterior = (local_s + alpha) / (local_n + alpha + beta)
                evidence = local_n + global_n
                last_s = float(local_row["last_s"] or 0)
            else:
                posterior = global_rate
                evidence = global_n
                last_s = float(g["last_success"] or 0)
            rankings.append(TechniqueRanking(
                technique=tech, posterior_success_rate=posterior,
                evidence_count=int(evidence), last_success_at=last_s,
            ))

        # Cold-start: no global stats yet → return empty so the planner falls
        # back to its own priors
        if not rankings:
            return []

        rankings.sort(key=lambda r: (r.posterior_success_rate, r.evidence_count), reverse=True)
        return rankings[:top_n]

    def stats(self) -> dict[str, Any]:
        """Aggregate counts — useful for `heaven coverage` and debugging."""
        with self._conn() as c:
            profiles = c.execute("SELECT COUNT(*) AS n FROM target_profile").fetchone()["n"]
            attempts = c.execute("SELECT COUNT(*) AS n FROM attempt").fetchone()["n"]
            successes = c.execute(
                "SELECT COUNT(*) AS n FROM attempt WHERE outcome='success'"
            ).fetchone()["n"]
            top_techniques = c.execute(
                "SELECT technique, attempts, successes FROM technique_stat "
                "ORDER BY successes DESC LIMIT 10"
            ).fetchall()
        return {
            "profiles": profiles, "attempts": attempts, "successes": successes,
            "top_techniques": [
                {"technique": r["technique"], "attempts": r["attempts"],
                 "successes": r["successes"]}
                for r in top_techniques
            ],
        }


# ═══════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════

_kg: Optional[KnowledgeGraph] = None


def get_knowledge_graph() -> KnowledgeGraph:
    global _kg
    if _kg is None:
        _kg = KnowledgeGraph()
    return _kg


# ═══════════════════════════════════════════
# POPULATION — called after every scan completes
# ═══════════════════════════════════════════

def _host_of(target: str) -> str:
    from urllib.parse import urlparse
    t = str(target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    return t.split("/", 1)[0].split(":", 1)[0].lower()


def record_findings_to_knowledge(
    findings: list[dict],
    assets: Optional[list[dict]] = None,
    engagement_name: str = "",
    graph: Optional[KnowledgeGraph] = None,
) -> int:
    """Populate the knowledge graph from one completed scan's findings.

    Builds a :class:`TargetProfile` per host (OS + web stack + top open ports
    from the asset inventory), then records one attempt per finding keyed to
    that profile — ``success`` for a validated/high-confidence finding (the
    technique demonstrably worked against this kind of target), ``inconclusive``
    otherwise. This is what turns the Knowledge Graph from a permanently-empty
    store into a live, learning one. Returns the number of attempts recorded.

    Never raises: knowledge capture is best-effort and must not fail a scan.
    """
    kg = graph or get_knowledge_graph()
    assets = assets or []

    # Per-host context from the asset inventory (OS, service stack, open ports).
    host_ctx: dict[str, dict] = {}
    for a in assets:
        if not isinstance(a, dict):
            continue
        h = _host_of(a.get("ip") or a.get("host") or "")
        if not h:
            continue
        ctx = host_ctx.setdefault(h, {"os": "", "ports": set(), "tech": set()})
        ctx["os"] = ctx["os"] or str(a.get("os") or a.get("os_guess") or "")
        for p in (a.get("open_ports") or a.get("ports") or []):
            if isinstance(p, dict):
                try:
                    ctx["ports"].add(int(p.get("port")))
                except (TypeError, ValueError):
                    pass
                prod = str(p.get("product") or p.get("service") or "").strip().lower()
                if prod:
                    ctx["tech"].add(prod.split()[0])
            elif isinstance(p, int):
                ctx["ports"].add(p)

    recorded = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        technique = str(f.get("vuln_type") or f.get("type") or "").strip()
        if not technique:
            continue
        h = _host_of(f.get("target") or f.get("url") or f.get("host") or "")
        ctx = host_ctx.get(h, {"os": "", "ports": set(), "tech": set()})
        profile = TargetProfile(
            os=str(ctx.get("os") or ""),
            web_tech=",".join(sorted(ctx.get("tech") or [])),
            open_ports_top=sorted(ctx.get("ports") or [])[:10],
        )
        try:
            conf = float(f.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0.0
        validated = bool(f.get("validated") or f.get("verified") or f.get("exploited"))
        outcome = "success" if (validated or conf >= 0.7) else "inconclusive"
        try:
            kg.record_attempt(
                profile, technique, outcome,
                tactic_phase=str(f.get("severity") or ""),
                confidence_delta=conf,
                finding_id=str(f.get("id") or ""),
                engagement_name=engagement_name,
            )
            recorded += 1
        except Exception:  # noqa: BLE001 — best-effort learning
            logger.debug("knowledge record_attempt failed", exc_info=True)
    if recorded:
        logger.info("knowledge graph: recorded %d attempt(s) from scan", recorded)
    return recorded
