"""
Head-to-head CSV exporter.

Produces two CSVs from a benchmark run:

  gt_coverage_<scanner>.csv  — one row per ground-truth entry, with detected
    yes/no for this scanner. Drop multiple scanners' CSVs into a spreadsheet
    and a diff column shows where they disagree.

  findings_<scanner>.csv     — one row per scanner finding, with whether it
    matched any GT entry. For false-positive analysis.

To compare HEAVEN vs Burp vs ZAP:
  1. Run each scanner against the same target.
  2. Adapt each scanner's output to list[Finding] (see metrics.Finding.from_*).
  3. Call render_comparison_csv() with each scanner's results.
  4. Open in a spreadsheet, pivot on the `detected` column.
"""

from __future__ import annotations

import csv
import io

from tests.benchmarks.metrics import BenchmarkResult, GroundTruth


def render_gt_coverage_csv(
    result: BenchmarkResult,
    gt: GroundTruth,
    scanner_name: str,
) -> str:
    """One row per GT entry; `detected` column says whether scanner found it."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "scanner", "gt_id", "endpoint", "method", "parameter", "category",
        "owasp", "cwe", "severity", "difficulty", "detection_required",
        "detected", "notes",
    ])
    for e in gt.vulnerabilities:
        detected = "yes" if e.id in result.detected_gt_ids else "no"
        w.writerow([
            scanner_name, e.id, e.endpoint, e.method, e.parameter or "",
            e.category, e.owasp, e.cwe, e.severity, e.difficulty,
            "yes" if e.detection_required else "no",
            detected, e.notes,
        ])
    return buf.getvalue()


def render_findings_csv(
    result: BenchmarkResult,
    scanner_name: str,
) -> str:
    """One row per scanner finding; flags whether it matched any GT."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "scanner", "url", "vuln_type", "category", "parameter",
        "confidence", "severity", "matched_gt",
    ])
    # We only have access to the unmatched-findings list on BenchmarkResult,
    # so this CSV is the FP candidate list. Callers wanting every finding
    # should retain the original list[Finding] before calling evaluate().
    for f in result.unmatched_findings:
        w.writerow([
            scanner_name, f.url, f.vuln_type, f.category, f.parameter,
            f"{f.confidence:.2f}", f.severity, "no",
        ])
    return buf.getvalue()


def render_comparison_csv(
    result: BenchmarkResult,
    gt: GroundTruth,
    scanner_name: str,
) -> tuple[str, str]:
    """Return (gt_coverage_csv, findings_csv) as strings."""
    return (
        render_gt_coverage_csv(result, gt, scanner_name),
        render_findings_csv(result, scanner_name),
    )
