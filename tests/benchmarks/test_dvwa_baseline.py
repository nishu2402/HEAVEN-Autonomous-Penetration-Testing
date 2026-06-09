"""
HEAVEN vs. DVWA benchmark.

This test brings up DVWA in Docker, runs `heaven scan` against it, parses the
engagement DB, computes precision/recall/F1 vs. the labeled ground truth, and
writes a publication-style markdown report.

Run:
    HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py -v -s

Optional env vars:
    HEAVEN_BENCH_RUNS         : repeat the scan N times for mean±stddev (default 1)
    HEAVEN_BENCH_SCAN_TIMEOUT : per-scan timeout in seconds (default 600)
    HEAVEN_BENCH_REPORT_DIR   : where to save reports (default tests/benchmarks/reports/)

What this benchmark does NOT do (yet)
-------------------------------------
HEAVEN does not currently support authenticated scanning. DVWA's vulnerable
endpoints all live under /vulnerabilities/* which require login. So the scan
will only exercise the small public surface: /login.php, /setup.php, the
robots.txt, the index page. Expect low recall numbers until HEAVEN gains
cookie/session auth support.

The benchmark still runs in this state — it produces a real baseline number
("here's what HEAVEN finds with zero auth") that future improvements can
be measured against. The README documents the auth gap and how to close it.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from tests.benchmarks.metrics import (
    Finding,
    GroundTruth,
    aggregate,
    evaluate,
)
from tests.benchmarks.reporters.markdown_report import (
    render_aggregated_markdown_report,
    render_markdown_report,
)
from tests.benchmarks.reporters.comparison_csv import render_comparison_csv


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_REPORT_DIR = _PROJECT_ROOT / "tests" / "benchmarks" / "reports"


def _runs() -> int:
    return max(1, int(os.environ.get("HEAVEN_BENCH_RUNS", "1")))


def _scan_timeout() -> int:
    return int(os.environ.get("HEAVEN_BENCH_SCAN_TIMEOUT", "600"))


def _report_dir() -> Path:
    return Path(os.environ.get("HEAVEN_BENCH_REPORT_DIR", str(_DEFAULT_REPORT_DIR)))


def _find_heaven_cli() -> str:
    """Locate the heaven CLI in this venv. Prefer the venv-installed script."""
    venv_heaven = _PROJECT_ROOT / "venv" / "bin" / "heaven"
    if venv_heaven.exists():
        return str(venv_heaven)
    if shutil.which("heaven"):
        return "heaven"
    pytest.skip("heaven CLI not found — run `pip install -e .` first")
    return ""  # unreachable; keeps mypy happy


def _run_heaven_scan(base_url: str, engagement_db: Path) -> tuple[Path, float]:
    """Invoke `heaven scan` against the URL, persist findings in the given DB.

    Returns (engagement_db_path, duration_seconds).
    """
    heaven = _find_heaven_cli()
    engagement_name = engagement_db.stem  # heaven uses engagements/<name>.db
    engagement_dir = engagement_db.parent
    engagement_dir.mkdir(parents=True, exist_ok=True)

    # Heaven derives engagement DB path from the --engagement name relative to
    # CWD: engagements/<name>.db. Run from a tempdir so we control that.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Pre-create the engagement DB shell
        init_cmd = [heaven, "engage", "init", engagement_name, "--client", "benchmark"]
        subprocess.run(init_cmd, cwd=tmp_path, capture_output=True, text=True, timeout=60)

        # Add the target to scope so the auth gate accepts it
        scope_cmd = [
            heaven, "scope", "add", base_url,
            "--engagement", engagement_name, "--kind", "url",
        ]
        subprocess.run(scope_cmd, cwd=tmp_path, capture_output=True, text=True, timeout=60)

        scan_cmd = [
            heaven, "scan",
            "-u", base_url,
            "-m", "web",
            "--engagement", engagement_name,
            "--i-have-authorization",
            "--skip-dep-check",
        ]
        start = time.time()
        result = subprocess.run(
            scan_cmd, cwd=tmp_path, capture_output=True, text=True,
            timeout=_scan_timeout(),
        )
        duration = time.time() - start

        if result.returncode != 0:
            # Surface what HEAVEN said — useful when DVWA crawl genuinely fails.
            print("HEAVEN stdout:\n" + result.stdout[-2000:])
            print("HEAVEN stderr:\n" + result.stderr[-2000:])
            pytest.fail(f"heaven scan exited {result.returncode}")

        # Copy the DB out before the tempdir is cleaned up
        produced = tmp_path / "engagements" / f"{engagement_name}.db"
        if not produced.exists():
            pytest.fail(f"engagement DB not produced at {produced}")
        shutil.copy(produced, engagement_db)
        return engagement_db, duration


def _findings_from_db(db_path: Path) -> list[Finding]:
    """Read all findings rows out of a HEAVEN engagement SQLite DB."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows: list[dict] = []
    try:
        # `findings` is the canonical table — schema in heaven/engagement.py
        # The column is `evidence_json` in the engagement schema; alias it to
        # `evidence` so Finding.from_heaven (which reads the `evidence` key) works.
        cur = conn.execute(
            "SELECT id, target, vuln_type, title, severity, confidence, "
            "evidence_json AS evidence FROM findings"
        )
        for row in cur:
            rows.append(dict(row))
    except sqlite3.OperationalError as e:
        pytest.fail(f"could not read findings from {db_path}: {e}")
    finally:
        conn.close()

    findings = []
    for r in rows:
        evidence = r.get("evidence")
        if isinstance(evidence, str):
            try:
                r["evidence"] = json.loads(evidence)
            except json.JSONDecodeError:
                r["evidence"] = {}
        findings.append(Finding.from_heaven(r))
    return findings


def test_heaven_vs_dvwa_baseline(dvwa_target: GroundTruth) -> None:
    """Run heaven scan against DVWA, compute metrics, save report.

    Asserts are intentionally LOOSE on the first iteration: the scan must
    not crash and must produce *some* findings. Tighten thresholds once a
    calibrated baseline exists. See tests/benchmarks/README.md.
    """
    runs = _runs()
    report_dir = _report_dir()
    report_dir.mkdir(parents=True, exist_ok=True)

    run_results = []
    for i in range(runs):
        db = report_dir / f"dvwa_run{i + 1}.db"
        if db.exists():
            db.unlink()
        _, duration = _run_heaven_scan(dvwa_target.base_url, db)
        findings = _findings_from_db(db)
        result = evaluate(findings, dvwa_target, duration_seconds=duration)
        run_results.append(result)

        # Write per-run markdown report
        md = render_markdown_report(result, dvwa_target, scanner_name="HEAVEN")
        (report_dir / f"dvwa_run{i + 1}.md").write_text(md, encoding="utf-8")

        # Write comparison CSVs (one scanner; usable for diff vs. Burp/ZAP later)
        gt_csv, find_csv = render_comparison_csv(result, dvwa_target, "HEAVEN")
        (report_dir / f"dvwa_run{i + 1}_gt_coverage.csv").write_text(gt_csv, encoding="utf-8")
        (report_dir / f"dvwa_run{i + 1}_findings.csv").write_text(find_csv, encoding="utf-8")

    # Aggregate + write the headline report
    agg = aggregate(run_results)
    agg_md = render_aggregated_markdown_report(agg, scanner_name="HEAVEN")
    (report_dir / "dvwa_aggregated.md").write_text(agg_md, encoding="utf-8")

    # Print the headline numbers to test output for at-a-glance visibility
    print()
    print("=" * 70)
    print(f"HEAVEN vs. DVWA — {runs} run(s)")
    print("=" * 70)
    print(f"Precision: {agg.mean_precision * 100:.1f}% ± {agg.std_precision * 100:.1f}%")
    print(f"Recall:    {agg.mean_recall * 100:.1f}% ± {agg.std_recall * 100:.1f}%")
    print(f"F1:        {agg.mean_f1 * 100:.1f}% ± {agg.std_f1 * 100:.1f}%")
    print(f"Required GT missed: {agg.missed_required_min} (min) — {agg.missed_required_max} (max)")
    print(f"Mean scan duration: {agg.mean_duration_s:.1f}s")
    print(f"Reports written to: {report_dir}")
    print("=" * 70)

    # ── Loose floors. Tighten over time, see README. ─────────────────────
    # Smoke floor: scan completed, engagement DB was produced.
    assert all(r.total_gt > 0 for r in run_results), "ground truth empty?"
    # Don't assert recall/precision until HEAVEN has authenticated-scan
    # support — see module docstring.
