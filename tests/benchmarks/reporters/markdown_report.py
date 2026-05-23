"""
Publication-style markdown report.

Renders a benchmark run (or aggregated multi-run) into a markdown document
suitable for inclusion in a README, a paper, or a release notes entry.
"""

from __future__ import annotations

from tests.benchmarks.metrics import (
    AggregatedResult,
    BenchmarkResult,
    GroundTruth,
)


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _pct_pm(mean: float, std: float) -> str:
    return f"{mean * 100:.1f}% ± {std * 100:.1f}%"


def render_markdown_report(
    result: BenchmarkResult,
    gt: GroundTruth,
    *,
    scanner_name: str = "HEAVEN",
    scanner_version: str = "",
) -> str:
    """Render a single benchmark run as markdown."""
    lines: list[str] = []
    title = f"{scanner_name}"
    if scanner_version:
        title += f" v{scanner_version}"
    lines.append(f"# Benchmark: {title} vs. {gt.target_app} v{gt.version}\n")
    lines.append(f"Target: `{gt.base_url}`  ·  "
                 f"Image: `{gt.docker_image or 'unspecified'}`  ·  "
                 f"Duration: {result.duration_seconds:.1f}s\n")

    # ── Headline ─────────────────────────────────────────────────────────
    lines.append("## Headline metrics\n")
    lines.append("| Metric                       | Value |")
    lines.append("|------------------------------|------:|")
    lines.append(f"| Precision (TP / TP+FP)       | {_pct(result.precision)} |")
    lines.append(f"| Recall (required GT only)    | {_pct(result.recall)} |")
    lines.append(f"| Recall (all GT)              | {_pct(result.recall_overall)} |")
    lines.append(f"| F1                           | {_pct(result.f1)} |")
    lines.append(f"| Required GT detected         | "
                 f"{len(result.detected_required_ids)} / {result.total_required} |")
    lines.append(f"| All GT detected              | "
                 f"{result.detected_count} / {result.total_gt} |")
    lines.append(f"| Findings matching ground truth | {result.matched_finding_count} |")
    lines.append(f"| Findings without GT match (potential FP) | {result.unmatched_finding_count} |\n")

    # ── Per-category breakdown ───────────────────────────────────────────
    lines.append("## Per-category recall\n")
    lines.append("| Category | GT total | Detected | Recall | Findings emitted | Of which matched |")
    lines.append("|----------|---------:|---------:|-------:|-----------------:|-----------------:|")
    cats = sorted(result.per_category.keys())
    for cat in cats:
        bucket = result.per_category[cat]
        gt_total = bucket.get("gt_total", 0)
        gt_detected = bucket.get("gt_detected", 0)
        recall = (gt_detected / gt_total) if gt_total else 0.0
        f_total = bucket.get("findings", 0)
        f_matched = bucket.get("matched", 0)
        lines.append(
            f"| {cat:14} | {gt_total:>8} | {gt_detected:>8} | "
            f"{_pct(recall):>6} | {f_total:>16} | {f_matched:>16} |"
        )
    lines.append("")

    # ── Missed required ──────────────────────────────────────────────────
    missed_required = [
        e for e in gt.vulnerabilities
        if e.detection_required and e.id not in result.detected_gt_ids
    ]
    if missed_required:
        lines.append("## Missed required vulnerabilities (benchmark failures)\n")
        for e in missed_required:
            lines.append(
                f"- **{e.id}** · `{e.method} {e.endpoint}` (param `{e.parameter}`) · "
                f"{e.category} / {e.severity} / {e.difficulty}"
            )
            if e.notes:
                lines.append(f"  - {e.notes}")
        lines.append("")
    else:
        lines.append("## Missed required vulnerabilities\n\n*None — all required GT detected.*\n")

    # ── Potential false positives ────────────────────────────────────────
    if result.unmatched_findings:
        lines.append("## Findings without ground-truth match\n")
        lines.append("These may be true positives (GT incomplete) or false positives. "
                     "Review and either add to the GT file or investigate.\n")
        lines.append("| URL | Vuln type | Param | Confidence |")
        lines.append("|-----|-----------|-------|-----------:|")
        for f in result.unmatched_findings[:50]:
            url = (f.url or "")[:80]
            vt = (f.vuln_type or "")[:30]
            param = (f.parameter or "")[:20]
            lines.append(f"| {url} | {vt} | {param} | {f.confidence:.2f} |")
        if len(result.unmatched_findings) > 50:
            lines.append(f"\n*({len(result.unmatched_findings) - 50} more findings omitted.)*")
        lines.append("")

    return "\n".join(lines) + "\n"


def render_aggregated_markdown_report(
    agg: AggregatedResult,
    *,
    scanner_name: str = "HEAVEN",
    scanner_version: str = "",
) -> str:
    """Render a multi-run aggregated result. Use this for publication tables."""
    lines: list[str] = []
    title = f"{scanner_name}"
    if scanner_version:
        title += f" v{scanner_version}"
    lines.append(f"# Benchmark (aggregated): {title} vs. {agg.target_app}\n")
    lines.append(f"Aggregated over **{agg.runs}** run(s). "
                 f"Mean scan duration: {agg.mean_duration_s:.1f}s ± {agg.std_duration_s:.1f}s.\n")

    lines.append("## Headline metrics (mean ± stddev)\n")
    lines.append("| Metric    | Value           |")
    lines.append("|-----------|-----------------|")
    lines.append(f"| Precision | {_pct_pm(agg.mean_precision, agg.std_precision)} |")
    lines.append(f"| Recall    | {_pct_pm(agg.mean_recall, agg.std_recall)} |")
    lines.append(f"| F1        | {_pct_pm(agg.mean_f1, agg.std_f1)} |")
    lines.append(f"| Required GT missed (min/max) | {agg.missed_required_min} / {agg.missed_required_max} |\n")

    lines.append("## Per-category recall (mean)\n")
    lines.append("| Category | Recall |")
    lines.append("|----------|-------:|")
    for cat in sorted(agg.per_category_recall.keys()):
        lines.append(f"| {cat:14} | {_pct(agg.per_category_recall[cat]):>6} |")
    lines.append("")

    return "\n".join(lines) + "\n"
