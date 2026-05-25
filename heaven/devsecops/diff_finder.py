"""
HEAVEN — Differential scanning

Compute the delta between two scans of the same engagement. Returns four
buckets so the operator only spends attention on what changed:

  - new        — first_seen between baseline-complete and current-complete
  - resolved   — last_seen before current-start (no longer appearing)
  - regressed  — status was 'fixed'/'false_positive'/'accepted_risk', but
                 the finding has been re-observed in current (last_seen
                 >= current_scan.started_at). URGENT bucket.
  - unchanged  — present in both timeframes, status still open / verified

NOTE on the engagement model: HEAVEN dedupes findings globally on a
content-hash (target + vuln_type + param + endpoint). That means we
CANNOT diff by `scan_id` directly — the row's scan_id is just the
most-recent scan that observed the finding. Instead we anchor the diff
on the scans' `started_at` / `completed_at` timestamps and use
`first_seen_at` / `last_seen_at` on the finding rows.

This also means severity/confidence "promotion" between scans is not
meaningful at the engagement-DB layer (only the first-insertion values
are retained). Operators wanting per-scan severity history should query
the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class FindingDiffRow:
    """One row in a diff report. Shape matches what reporters expect."""
    id: str
    target: str
    vuln_type: str
    title: str
    severity: str
    confidence: float
    # Only set on `unchanged` when confidence shifted between scans:
    baseline_confidence: Optional[float] = None
    # Only set on `unchanged` when severity shifted between scans:
    baseline_severity: Optional[str] = None


@dataclass
class DiffReport:
    """Bucketed diff between two scans."""
    baseline_scan_id: str
    current_scan_id: str
    new: list[FindingDiffRow] = field(default_factory=list)
    resolved: list[FindingDiffRow] = field(default_factory=list)
    regressed: list[FindingDiffRow] = field(default_factory=list)
    unchanged: list[FindingDiffRow] = field(default_factory=list)

    @property
    def total_changed(self) -> int:
        return len(self.new) + len(self.resolved) + len(self.regressed)

    @property
    def critical_new(self) -> int:
        return sum(1 for r in self.new if r.severity == "critical")

    @property
    def regressed_critical_or_high(self) -> int:
        """Most-important number — fixes that came back."""
        return sum(1 for r in self.regressed if r.severity in ("critical", "high"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "summary": {
                "new": len(self.new),
                "resolved": len(self.resolved),
                "regressed": len(self.regressed),
                "unchanged": len(self.unchanged),
                "critical_new": self.critical_new,
                "regressed_critical_or_high": self.regressed_critical_or_high,
            },
            "new": [_row_dict(r) for r in self.new],
            "resolved": [_row_dict(r) for r in self.resolved],
            "regressed": [_row_dict(r) for r in self.regressed],
            # `unchanged` can be huge — caller asks for it explicitly via
            # include_unchanged=True if they want the full inventory
        }


def _row_dict(r: FindingDiffRow) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": r.id, "target": r.target, "vuln_type": r.vuln_type,
        "title": r.title, "severity": r.severity,
        "confidence": round(r.confidence, 3),
    }
    if r.baseline_confidence is not None:
        out["baseline_confidence"] = round(r.baseline_confidence, 3)
    if r.baseline_severity is not None:
        out["baseline_severity"] = r.baseline_severity
    return out


# ═══════════════════════════════════════════
# COMPUTE THE DIFF
# ═══════════════════════════════════════════


def _finding_to_row(f, *, baseline_conf: Optional[float] = None,
                    baseline_sev: Optional[str] = None) -> FindingDiffRow:
    return FindingDiffRow(
        id=f.id, target=f.target, vuln_type=f.vuln_type,
        title=f.title or f.vuln_type,
        severity=f.severity, confidence=float(f.confidence or 0),
        baseline_confidence=baseline_conf, baseline_severity=baseline_sev,
    )


def compute_diff(
    engagement_store,
    baseline_scan_id: str,
    current_scan_id: str,
) -> DiffReport:
    """Bucket the findings into new / resolved / regressed / unchanged based
    on the two scans' timestamps and the rows' first_seen / last_seen.

    Resolution rules (anchored on baseline.completed_at and current.started_at):
      - first_seen_at  > baseline.completed_at      → NEW
      - last_seen_at   < current.started_at         → RESOLVED
      - finding.status in {fixed, false_positive,
        accepted_risk} AND last_seen_at >= current.started_at → REGRESSED
      - otherwise                                    → UNCHANGED
    """
    base_scan = _scan_meta(engagement_store, baseline_scan_id)
    curr_scan = _scan_meta(engagement_store, current_scan_id)
    if not base_scan or not curr_scan:
        raise ValueError(
            f"Scan not found — baseline={base_scan is not None}, "
            f"current={curr_scan is not None}"
        )

    base_completed = base_scan.get("completed_at") or base_scan.get("started_at")
    curr_started = curr_scan.get("started_at") or curr_scan.get("completed_at")
    if not base_completed or not curr_started:
        raise ValueError("Scans missing started_at/completed_at — can't diff")

    all_findings = _all_findings(engagement_store)
    report = DiffReport(
        baseline_scan_id=baseline_scan_id, current_scan_id=current_scan_id,
    )

    for f in all_findings:
        first = f.first_seen_at or ""
        last = f.last_seen_at or first
        # NEW — first observed after the baseline scan completed
        if first > base_completed:
            report.new.append(_finding_to_row(f))
            continue
        # RESOLVED — not seen since before the current scan started
        if last < curr_started:
            report.resolved.append(_finding_to_row(f))
            continue
        # REGRESSED — dispositioned closed but observed again
        if f.status in ("fixed", "false_positive", "accepted_risk"):
            report.regressed.append(_finding_to_row(f))
            continue
        # UNCHANGED — still present, still open
        report.unchanged.append(_finding_to_row(f))

    return report


def _scan_meta(engagement_store, scan_id: str) -> Optional[dict]:
    """Return the scans row as a dict, or None."""
    with engagement_store._conn() as c:
        row = c.execute(
            "SELECT id, started_at, completed_at, status FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None


def _all_findings(engagement_store) -> list:
    """Pull every finding row in the engagement (no scan_id filter — global)."""
    with engagement_store._conn() as c:
        rows = c.execute("SELECT * FROM findings").fetchall()
        return [engagement_store._row_to_finding(r) for r in rows]


# ═══════════════════════════════════════════
# MARKDOWN REPORTER
# ═══════════════════════════════════════════


def render_diff_markdown(report: DiffReport,
                          *, include_unchanged: bool = False) -> str:
    """Render the diff as a markdown table set, suitable for PR comments."""
    lines: list[str] = []
    lines.append(f"# Scan diff — {report.current_scan_id[:8]} vs. {report.baseline_scan_id[:8]}\n")
    s = report.to_dict()["summary"]
    lines.append("## Summary\n")
    lines.append("| Bucket | Count |")
    lines.append("|---|---:|")
    lines.append(f"| 🆕 New | {s['new']} |")
    lines.append(f"| ✅ Resolved | {s['resolved']} |")
    lines.append(f"| ⚠️ Regressed | {s['regressed']} |")
    lines.append(f"| = Unchanged | {s['unchanged']} |\n")
    if s["regressed_critical_or_high"]:
        lines.append(f"> 🚨 **{s['regressed_critical_or_high']} previously-fixed "
                     f"critical/high finding(s) came back.**\n")

    def _section(title: str, rows: list[FindingDiffRow]) -> None:
        if not rows:
            return
        lines.append(f"## {title} ({len(rows)})\n")
        lines.append("| Severity | Type | Target | Conf | Title |")
        lines.append("|---|---|---|---:|---|")
        for r in rows[:50]:
            sev_em = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                      "low": "🔵", "info": "⚪"}.get(r.severity, "·")
            lines.append(f"| {sev_em} {r.severity} | `{r.vuln_type}` | "
                         f"{r.target[:60]} | {r.confidence:.2f} | "
                         f"{(r.title or '')[:60]} |")
        if len(rows) > 50:
            lines.append(f"\n*(+{len(rows) - 50} more — truncated)*\n")
        lines.append("")

    _section("🆕 New findings", report.new)
    _section("⚠️ Regressed (closed → reopened)", report.regressed)
    _section("✅ Resolved", report.resolved)
    if include_unchanged:
        _section("= Unchanged", report.unchanged)
    return "\n".join(lines) + "\n"
