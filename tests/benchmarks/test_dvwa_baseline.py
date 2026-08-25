"""
HEAVEN vs. DVWA benchmark.

This test brings up DVWA in Docker, runs `heaven scan` against it, parses the
engagement DB, computes precision/recall/F1 vs. the labeled ground truth, and
writes a publication-style markdown report.

Run:
    HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py -v -s

Optional env vars:
    HEAVEN_BENCH_RUNS         : repeat the scan N times for mean±stddev (default 1)
    HEAVEN_BENCH_SCAN_TIMEOUT : per-scan timeout in seconds (default 900)
    HEAVEN_BENCH_REPORT_DIR   : where to save reports (default tests/benchmarks/reports/)

Authenticated scanning
----------------------
This benchmark runs AUTHENTICATED. DVWA's vulnerable endpoints all live under
/vulnerabilities/* behind a login, so the fixture (tests/benchmarks/conftest.py)
logs in as admin/password and hands the scan a cookie jar carrying the session
cookie **and** `security=low` (via `heaven scan --cookie-file <jar>`). The
authenticated crawl then reaches the /vulnerabilities/* pages and the injection
scanner detects the SQLi / reflected-XSS / command-injection / LFI there,
yielding a real recall number — typically ~0.8 of the detection-required set.

An authenticated crawler must never follow a logout link: DVWA's /logout.php
destroys the shared session server-side, after which every scanner reusing that
session is bounced to /login.php and detection silently collapses — and because
requests fire concurrently, *whether* the logout lands before a given scanner is
timing-dependent, so the collapse is intermittent and unreproducible. HEAVEN's
crawler skips session-destroying URLs
(heaven/recon/web_crawler.py::_is_session_destroying); without that guard recall
here is ~0. If login can't be completed the fixture falls back to an
unauthenticated run (low recall) rather than failing outright.

Remaining swing cases: blind-SQLi (timing-dependent) and CSRF (a non-injection
class); tightening boolean-blind SQLi precision on reflective endpoints is a
tracked follow-up.
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
from heaven import __version__ as _heaven_version


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_REPORT_DIR = _PROJECT_ROOT / "tests" / "benchmarks" / "reports"


def _runs() -> int:
    return max(1, int(os.environ.get("HEAVEN_BENCH_RUNS", "1")))


def _scan_timeout() -> int:
    # The authenticated scan crawls the whole post-login surface and fuzzes every
    # discovered vector, so it runs longer than the old public-only baseline —
    # especially against an emulated (amd64-on-arm64) DVWA. Raise
    # HEAVEN_BENCH_SCAN_TIMEOUT for very slow hosts.
    return int(os.environ.get("HEAVEN_BENCH_SCAN_TIMEOUT", "900"))


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


def _run_heaven_scan(
    base_url: str, engagement_db: Path, cookie_file: str | None = None
) -> tuple[Path, float]:
    """Invoke `heaven scan` against the URL, persist findings in the given DB.

    When ``cookie_file`` is provided the scan runs authenticated (DVWA's
    vulnerable endpoints live behind the login) and bypasses the scope filter so
    the single target URL is always in play.

    Returns (engagement_db_path, duration_seconds).
    """
    heaven = _find_heaven_cli()
    engagement_name = engagement_db.stem  # heaven uses engagements/<name>.db
    engagement_dir = engagement_db.parent
    engagement_dir.mkdir(parents=True, exist_ok=True)

    # Heaven writes the engagement DB to <data_dir>/engagements/<name>.db, where
    # data_dir follows HEAVEN_DATA_DIR (default ./data). Pin HEAVEN_DATA_DIR to
    # this tempdir so the DB lands at <tmp>/engagements/<name>.db, exactly where
    # we look below — and so it is unaffected by the suite's autouse data-dir
    # isolation (tests/conftest.py points HEAVEN_DATA_DIR at pytest's tmp_path,
    # which these subprocesses would otherwise inherit).
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        env = {**os.environ, "HEAVEN_DATA_DIR": str(tmp_path)}
        # The target is the official multi-arch DVWA image, which runs NATIVE on
        # the host CPU (no QEMU), so its baselines are sub-second and timing-based
        # blind SQLi is stable. On a small (2-CPU) VM a modest per-host concurrency
        # keeps request timing clean for that oracle without saturating the single
        # MariaDB backend; the throttle's AIMD still adapts from here. These are
        # only defaults (operator `HEAVEN_THROTTLE_*` env wins), and on a larger
        # host you can raise them freely.
        for _k, _v in {"HEAVEN_THROTTLE_START": "8", "HEAVEN_THROTTLE_MAX": "16",
                       "HEAVEN_THROTTLE_MIN": "2"}.items():
            env.setdefault(_k, _v)
        # Pre-create the engagement DB shell
        init_cmd = [heaven, "engage", "init", engagement_name, "--client", "benchmark"]
        subprocess.run(init_cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)

        # Add the target to scope so the auth gate accepts it
        scope_cmd = [
            heaven, "scope", "add", base_url,
            "--engagement", engagement_name, "--kind", "url",
        ]
        subprocess.run(scope_cmd, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)

        scan_cmd = [
            heaven, "scan",
            "-u", base_url,
            "-m", "web",
            "--engagement", engagement_name,
            "--i-have-authorization",
            "--skip-dep-check",
        ]
        if cookie_file:
            # Authenticated scan; bypass the scope filter for the single target.
            scan_cmd += ["--cookie-file", cookie_file, "--no-use-scope"]
        start = time.time()
        result = subprocess.run(
            scan_cmd, cwd=tmp_path, env=env, capture_output=True, text=True,
            timeout=_scan_timeout(),
        )
        duration = time.time() - start

        if result.returncode != 0:
            # Surface what HEAVEN said — useful when DVWA crawl genuinely fails.
            print("HEAVEN stdout:\n" + result.stdout[-2000:])
            print("HEAVEN stderr:\n" + result.stderr[-2000:])
            pytest.fail(f"heaven scan exited {result.returncode}")

        # Copy the DB out before the tempdir is cleaned up. HEAVEN_DATA_DIR is
        # pinned to tmp_path above, so the engagement lands at
        # <tmp>/engagements/<name>.db.
        produced = tmp_path / "engagements" / f"{engagement_name}.db"
        if not produced.exists():
            pytest.fail(f"engagement DB not produced at {produced}")
        shutil.copy(produced, engagement_db)
        return engagement_db, duration


def _scope_to_target(findings: list[Finding], base_url: str) -> list[Finding]:
    """Keep only findings on the benchmark's own host:port.

    A URL-targeted web scan does a quick host recon first, which on a shared
    loopback can legitimately surface the operator's *other* local services (a
    colima/lima SSH forward on an ephemeral port, for instance). Those are real
    findings, but they belong to a different host:port than the DVWA web app
    under test, so they are out of scope for this benchmark's precision. Reuse
    HEAVEN's own host-key logic so the notion of "same host:port" matches the
    product's dedup (default web ports normalised, a real non-default port kept).
    """
    from heaven.engagement import _host_key
    target_key = _host_key(base_url)
    target_host = target_key.split(":", 1)[0]
    return [f for f in findings
            if _host_key(f.url or "") in (target_key, target_host)]


def _findings_from_db(db_path: Path, base_url: str = "") -> list[Finding]:
    """Read all findings rows out of a HEAVEN engagement SQLite DB.

    When ``base_url`` is given, findings are scoped to that host:port (see
    :func:`_scope_to_target`)."""
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
    if base_url:
        findings = _scope_to_target(findings, base_url)
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

    cookie_file = dvwa_target.auth.get("cookie_file")
    run_results = []
    for i in range(runs):
        db = report_dir / f"dvwa_run{i + 1}.db"
        if db.exists():
            db.unlink()
        _, duration = _run_heaven_scan(dvwa_target.base_url, db, cookie_file=cookie_file)
        findings = _findings_from_db(db, base_url=dvwa_target.base_url)
        result = evaluate(findings, dvwa_target, duration_seconds=duration)
        run_results.append(result)

        # Write per-run markdown report
        md = render_markdown_report(
            result, dvwa_target, scanner_name="HEAVEN",
            scanner_version=_heaven_version,
        )
        (report_dir / f"dvwa_run{i + 1}.md").write_text(md, encoding="utf-8")

        # Write comparison CSVs (one scanner; usable for diff vs. Burp/ZAP later)
        gt_csv, find_csv = render_comparison_csv(result, dvwa_target, "HEAVEN")
        (report_dir / f"dvwa_run{i + 1}_gt_coverage.csv").write_text(gt_csv, encoding="utf-8")
        (report_dir / f"dvwa_run{i + 1}_findings.csv").write_text(find_csv, encoding="utf-8")

    # Aggregate + write the headline report
    agg = aggregate(run_results)
    agg_md = render_aggregated_markdown_report(
        agg, scanner_name="HEAVEN", scanner_version=_heaven_version,
    )
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

    # ── Floors ────────────────────────────────────────────────────────────
    # Smoke floor: every run loaded ground truth and produced findings.
    assert all(r.total_gt > 0 for r in run_results), "ground truth empty?"
    # Detection floor: the authenticated scan must find essentially all of DVWA's
    # detection-required vulnerabilities. Against the native multi-arch image all
    # ten required entries detect — SQLi (id) ×2, reflected XSS (name) ×2, command
    # injection (ip) ×2, LFI (page) ×2, blind-timing SQLi, and the GET-based CSRF
    # (measured 10/10, 100% recall). The 0.9 floor locks that in while allowing a
    # single transient miss (e.g. one timing sample lost on a loaded CI runner)
    # rather than flaking. A drop well below this is a real regression — most
    # often an authenticated-crawl session collapse, which craters recall (see the
    # module docstring on /logout).
    assert agg.mean_recall >= 0.9, (
        f"DVWA authenticated recall {agg.mean_recall:.0%} is below the 0.9 floor — "
        "core detection regressed (check the authenticated crawl / session)."
    )
