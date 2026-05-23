"""
HEAVEN — Priors trainer

Aggregates findings from engagement DBs into empirical Bayesian priors
that replace (or smooth over) the bootstrap values in
`data/models/priors_bootstrap.json`.

Output: `data/models/priors_learned.json` — same schema as the bootstrap,
plus a `_provenance` block recording how many engagements / findings
contributed.

Honest scoping:
  - SERVICE_PRIORS — learned (Bayesian-smoothed against bootstrap prior)
  - VALUE_WEIGHTS, EFFECTIVENESS_MATRIX, WAF_BYPASS_PRIORITY,
    CALIBRATION_CURVE, SOURCE_WEIGHTS — passed through from bootstrap
    with a note. These require richer telemetry the engagement DB
    doesn't yet capture (payload-level attribution, isotonic regression
    on labeled FP data). Marked clearly in the output file so future
    work knows what's empirically derived vs. inherited.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from heaven.utils.logger import get_logger

logger = get_logger("ml.train_priors")


# Pseudo-observation count for the Beta prior. Higher = bootstrap values
# dominate longer. 10 is a reasonable default; users can override via
# the CLI flag --prior-strength.
DEFAULT_PRIOR_STRENGTH = 10.0


# Port → canonical service name mapping. Mirrors the small subset used in
# SERVICE_PRIORS — the rest of the well-known ports map to services we
# don't prior on, which we lump into "other".
PORT_TO_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp",
    993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http", 8443: "https", 8888: "http",
    9200: "elasticsearch", 27017: "mongodb",
    # Container/CI surface
    2375: "docker", 2376: "docker", 6443: "kubernetes",
    9090: "grafana", 3000: "grafana", 8081: "jenkins", 50000: "jenkins",
}


@dataclass
class PriorsTrainingResult:
    engagement_count: int
    finding_count: int
    services_observed: int
    service_priors_updated: int      # how many service entries got a non-bootstrap value
    out_path: Path
    summary: dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════
# DB aggregation
# ═══════════════════════════════════════════


def _service_from_url(url: str) -> str:
    """Best-effort: extract service name from a URL or host:port string."""
    if not url:
        return ""
    if "://" not in url and ":" in url and "/" not in url:
        url = "tcp://" + url
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        return ""
    port = parsed.port
    if port is None:
        # Infer from scheme
        port = {"http": 80, "https": 443, "ftp": 21, "ssh": 22}.get(parsed.scheme, 0)
    return PORT_TO_SERVICE.get(port, "other")


def _read_engagement_findings(db_path: Path) -> tuple[int, list[tuple[str, str]]]:
    """Return (host_count_distinct, list of (target_host_or_service, vuln_type))."""
    if not db_path.exists():
        return 0, []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT target, vuln_type FROM findings")
        rows = [(r["target"], r["vuln_type"]) for r in cur if r["target"]]
        # Distinct host count via the scope table — the canonical denominator
        cur2 = conn.execute("SELECT COUNT(DISTINCT target) FROM scope WHERE in_scope = 1")
        n_hosts = int(cur2.fetchone()[0] or 0)
        conn.close()
        return n_hosts, rows
    except sqlite3.OperationalError as e:
        logger.warning(f"could not read {db_path}: {e}")
        return 0, []


def aggregate_findings(engagement_paths: list[Path]) -> tuple[dict[str, int], dict[str, int], int]:
    """Walk every engagement DB, return (service_finding_count, service_host_count, total_engagements_with_data)."""
    findings_per_service: dict[str, int] = defaultdict(int)
    hosts_per_service: dict[str, int] = defaultdict(int)
    engagements_with_data = 0

    for db in engagement_paths:
        n_hosts, rows = _read_engagement_findings(db)
        if not rows:
            continue
        engagements_with_data += 1

        # Hosts per service — best-effort distribution. We don't know which
        # of the engagement's hosts ran which service, so we approximate:
        # each service that produced findings is credited with one host per
        # finding observed (caps at n_hosts).
        per_service_findings: dict[str, int] = defaultdict(int)
        for target, vuln in rows:
            svc = _service_from_url(target)
            if not svc or svc == "other":
                continue
            per_service_findings[svc] += 1
            findings_per_service[svc] += 1

        for svc, n in per_service_findings.items():
            hosts_per_service[svc] += min(n, max(n_hosts, 1))

    return dict(findings_per_service), dict(hosts_per_service), engagements_with_data


# ═══════════════════════════════════════════
# Bayesian smoothing
# ═══════════════════════════════════════════


def _smoothed_posterior(prior: float, observations_pos: int, observations_total: int,
                         strength: float = DEFAULT_PRIOR_STRENGTH) -> float:
    """
    Beta-prior smoothing: posterior = (α + obs_pos) / (α + β + obs_total)
    with α = prior * strength, β = (1 - prior) * strength.

    With strength=10 the bootstrap value contributes 10 pseudo-observations,
    so the posterior only shifts meaningfully after a comparable amount
    of real data has accumulated.
    """
    alpha = prior * strength
    beta = (1 - prior) * strength
    return (alpha + observations_pos) / (alpha + beta + observations_total)


# ═══════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════


def train_priors(
    engagement_paths: list[Path],
    bootstrap_path: Path,
    out_path: Path,
    prior_strength: float = DEFAULT_PRIOR_STRENGTH,
) -> PriorsTrainingResult:
    """Aggregate, smooth, and emit a learned priors file."""
    if not bootstrap_path.exists():
        raise FileNotFoundError(f"bootstrap priors not found: {bootstrap_path}")

    bootstrap = json.loads(bootstrap_path.read_text(encoding="utf-8"))

    findings_per_svc, hosts_per_svc, eng_with_data = aggregate_findings(engagement_paths)
    total_findings = sum(findings_per_svc.values())

    # Smooth each service prior
    learned_service_priors: dict[str, float] = {}
    updated_count = 0
    for svc, bootstrap_p in bootstrap.get("service_priors", {}).items():
        n_pos = findings_per_svc.get(svc, 0)
        n_total = hosts_per_svc.get(svc, 0)
        if n_total > 0:
            posterior = _smoothed_posterior(bootstrap_p, n_pos, n_total, prior_strength)
            learned_service_priors[svc] = round(posterior, 3)
            updated_count += 1
        else:
            learned_service_priors[svc] = bootstrap_p

    learned: dict[str, Any] = {
        "_schema": "heaven.ai.priors.v1",
        "_provenance": {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "engagement_count": len(engagement_paths),
            "engagements_with_data": eng_with_data,
            "finding_count": total_findings,
            "prior_strength": prior_strength,
            "bootstrap_source": str(bootstrap_path),
            "service_priors_updated": updated_count,
        },
        "_status_by_section": {
            "service_priors":       "learned (Bayesian-smoothed)",
            "value_weights":        "bootstrap (no learning signal in engagement DB yet)",
            "calibration_curve":    "bootstrap (needs labeled TP/FP data + isotonic regression)",
            "source_weights":       "bootstrap (needs per-source success-rate telemetry)",
            "effectiveness_matrix": "bootstrap (needs payload-level attribution in findings)",
            "waf_bypass_priority":  "bootstrap (needs per-bypass success tracking)",
        },
        "service_priors":       learned_service_priors,
        "value_weights":        bootstrap.get("value_weights", {}),
        "calibration_curve":    bootstrap.get("calibration_curve", []),
        "source_weights":       bootstrap.get("source_weights", {}),
        "effectiveness_matrix": bootstrap.get("effectiveness_matrix", {}),
        "waf_bypass_priority":  bootstrap.get("waf_bypass_priority", {}),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(learned, indent=2), encoding="utf-8")

    return PriorsTrainingResult(
        engagement_count=len(engagement_paths),
        finding_count=total_findings,
        services_observed=len(findings_per_svc),
        service_priors_updated=updated_count,
        out_path=out_path,
        summary={
            "engagements_with_data": eng_with_data,
            "top_services_by_findings": sorted(
                findings_per_svc.items(), key=lambda x: -x[1]
            )[:5],
        },
    )


def discover_engagement_dbs(*dirs: Path) -> list[Path]:
    """Find all *.db files under the given directories (recursive)."""
    out: list[Path] = []
    for d in dirs:
        if not d.exists():
            continue
        out.extend(sorted(d.rglob("*.db")))
    return out
