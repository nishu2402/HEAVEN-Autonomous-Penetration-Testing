"""Scored, Docker-free functional benchmark for HEAVEN's web scanner.

Unlike the Docker DVWA benchmark (which needs QEMU on arm64 and is gated behind
HEAVEN_RUN_BENCHMARKS), this runs the REAL crawler + injection scanner against
the in-process native target and scores the run with the SAME metrics layer the
DVWA benchmark uses (precision / recall / F1 vs. a labelled ground truth). It is
fast (~1 s), deterministic, and always-on in CI, so the headline numbers are
reproducible by anyone with `pip install -e .[dev]` and no Docker at all.

The run itself lives in `tests/benchmarks/native/runner.py` (`run_native_benchmark`)
so the CLI (`heaven benchmark`) and the web Benchmark page score the target by
exactly the same code path this test enforces the floor on.

This is a *controlled functional benchmark*: the target is a faithful
reproduction of DVWA's injection endpoints (including MySQL comment semantics),
so the score measures HEAVEN's end-to-end detection + attribution on a known
surface. It is NOT a claim of performance against any live third-party app.
"""

from __future__ import annotations

import pytest


def test_benchmark_cli_registered_and_help() -> None:
    """`heaven benchmark` is wired into the CLI and documents itself.

    The full scored run is exercised by test_native_benchmark_scores below (same
    `run_native_benchmark` path the CLI drives), so this just locks in the command
    registration + option parsing cheaply.
    """
    from click.testing import CliRunner

    from heaven.main import cli

    r = CliRunner().invoke(cli, ["benchmark", "--help"])
    assert r.exit_code == 0, r.output
    assert "precision" in r.output.lower()
    assert "--json" in r.output and "--no-report" in r.output


def test_native_benchmark_scores() -> None:
    pytest.importorskip("flask")
    pytest.importorskip("bs4")
    pytest.importorskip("aiohttp")
    pytest.importorskip("yaml")

    from tests.benchmarks.native.runner import run_native_benchmark

    run = run_native_benchmark()  # writes reports/native_benchmark.md
    result = run.result

    print()
    print("=" * 64)
    print(f"HEAVEN vs. {run.gt.target_app} (native, Docker-free)")
    print("=" * 64)
    print(f"Precision: {result.precision * 100:5.1f}%  "
          f"({result.matched_finding_count}/"
          f"{result.matched_finding_count + result.unmatched_finding_count} findings real)")
    print(f"Recall:    {result.recall * 100:5.1f}%  "
          f"({len(result.detected_required_ids)}/{result.total_required} required)")
    print(f"F1:        {result.f1 * 100:5.1f}%")
    print(f"Duration:  {result.duration_seconds:.2f}s")
    if result.unmatched_findings:
        print("Unmatched (potential FPs):")
        for f in result.unmatched_findings:
            print(f"  - {f.category:6} {f.parameter:8} {f.url}")
    print("=" * 64)

    # ── Floors. Every required vuln must be found (this is what the comment-
    #    style fix restored), and precision must stay high — the target is a
    #    known surface, so unmatched findings are genuine false positives. ────
    assert result.recall == 1.0, (
        f"missed required GT: detected {sorted(result.detected_required_ids)} "
        f"of {result.total_required}"
    )
    assert result.precision >= 0.90, (
        f"precision {result.precision:.2f} — unexpected false positives: "
        f"{[(f.category, f.parameter, f.url) for f in result.unmatched_findings]}"
    )
    assert result.f1 >= 0.95, f"F1 {result.f1:.2f} below floor"
