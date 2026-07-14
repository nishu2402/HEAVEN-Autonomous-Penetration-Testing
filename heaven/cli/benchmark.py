"""HEAVEN — `heaven benchmark` (score the scanner against a labelled target).

Runs the Docker-free *native* benchmark: the real crawler + injection / misconfig
/ out-of-band scanners against a faithful, in-process reproduction of DVWA's
vulnerable endpoints, scored with precision / recall / F1 against a labelled
ground truth. No Docker, no network, ~1 s.

This is the same run the always-on regression test enforces a floor on and the
web Benchmark page renders — one code path
(`tests/benchmarks/native/runner.py::run_native_benchmark`), so the CLI number,
the UI number and CI never drift.

It is a *controlled functional benchmark* on a known surface — NOT a claim of
performance against any live third-party app. For that, run the live Docker DVWA
benchmark (`HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py`).
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from heaven.cli._helpers import _print, emit_json, json_output

# Repo root holds the (non-packaged) `tests/` tree the benchmark lives in. The
# API server resolves the same root the same way to read the report files.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_runner():
    """Import the native benchmark runner, making `tests/` importable first.

    `tests/` ships with the source checkout but isn't part of the installed
    `heaven` package, so add the repo root to `sys.path` before importing.
    Returns None when the source tree isn't present (e.g. a bare wheel install).
    """
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    try:
        from tests.benchmarks.native.runner import run_native_benchmark
        return run_native_benchmark
    except Exception:
        return None


@click.command(name="benchmark")
@click.option("--json", "as_json", is_flag=True,
              help="Emit machine-readable JSON instead of a table.")
@click.option("--no-report", is_flag=True,
              help="Don't write reports/native_benchmark.md (just print).")
def benchmark(as_json: bool, no_report: bool) -> None:
    """Score HEAVEN's scanner against the built-in labelled target.

    Runs the real detectors against a faithful, in-process reproduction of DVWA's
    vulnerable endpoints and reports precision / recall / F1 vs. ground truth —
    the same numbers the web Benchmark page shows. Docker-free, ~1 s.
    """
    run_native_benchmark = _load_runner()
    if run_native_benchmark is None:
        msg = ("Benchmark harness not found. It ships in the source checkout under "
               "tests/benchmarks/ — run `heaven benchmark` from a git clone, or "
               "reproduce with:\n"
               "  pip install -e \".[dev]\"\n"
               "  pytest tests/benchmarks/test_native_benchmark.py -s")
        if as_json or json_output():
            emit_json({"available": False, "error": "harness_not_found", "note": msg})
        else:
            _print(f"[red]{msg}[/red]")
        sys.exit(2)

    # Optional deps (flask / bs4 / aiohttp / pyyaml) back the in-process target.
    missing = [m for m in ("flask", "bs4", "aiohttp", "yaml")
               if not _has_module(m)]
    if missing:
        pretty = {"bs4": "beautifulsoup4", "yaml": "pyyaml"}
        pkgs = " ".join(pretty.get(m, m) for m in missing)
        msg = (f"Benchmark needs the [dev] extras (missing: {', '.join(missing)}). "
               f"Install: pip install {pkgs}   — or: pip install -e \".[dev]\"")
        if as_json or json_output():
            emit_json({"available": False, "error": "missing_deps",
                       "missing": missing, "note": msg})
        else:
            _print(f"[yellow]{msg}[/yellow]")
        sys.exit(2)

    if not (as_json or json_output()):
        _print("[dim]Running native benchmark (real scanners vs. labelled target)…[/dim]")

    run = run_native_benchmark(write_report=not no_report)
    result = run.result

    # Per-category recall, derived the same way the markdown report does it.
    per_cat = {}
    for cat, bucket in result.per_category.items():
        total = bucket.get("gt_total", 0)
        detected = bucket.get("gt_detected", 0)
        per_cat[cat] = {
            "gt_total": total,
            "detected": detected,
            "recall": (detected / total) if total else 0.0,
        }

    payload = {
        "available": True,
        "source": "native-controlled",
        "target": run.gt.target_app,
        "target_version": run.gt.version,
        "duration_seconds": round(run.duration_seconds, 2),
        "metrics": {
            "precision": round(result.precision, 4),
            "recall": round(result.recall, 4),
            "recall_overall": round(result.recall_overall, 4),
            "f1": round(result.f1, 4),
        },
        "required_detected": len(result.detected_required_ids),
        "required_total": result.total_required,
        "findings_matched": result.matched_finding_count,
        "findings_unmatched": result.unmatched_finding_count,
        "per_category": per_cat,
        "report": str(run.report_path) if run.report_path else None,
    }

    if as_json or json_output():
        emit_json(payload)
        return

    _print(f"\n[bold cyan]HEAVEN vs. {run.gt.target_app} v{run.gt.version}[/bold cyan]"
           f"  [dim](native, Docker-free · {run.duration_seconds:.1f}s)[/dim]")
    _print(f"  Precision : [bold]{result.precision * 100:5.1f}%[/bold]"
           f"   [dim]{result.matched_finding_count}/"
           f"{result.matched_finding_count + result.unmatched_finding_count} findings real[/dim]")
    _print(f"  Recall    : [bold]{result.recall * 100:5.1f}%[/bold]"
           f"   [dim]{len(result.detected_required_ids)}/{result.total_required} required GT[/dim]")
    _print(f"  F1        : [bold]{result.f1 * 100:5.1f}%[/bold]")

    _print("\n[bold]Per-category recall[/bold]")
    for cat in sorted(per_cat):
        c = per_cat[cat]
        _print(f"  {cat:18} {c['recall'] * 100:5.1f}%"
               f"   [dim]{c['detected']}/{c['gt_total']}[/dim]")

    if result.unmatched_findings:
        _print("\n[yellow]Findings without a ground-truth match (potential FPs):[/yellow]")
        for f in result.unmatched_findings[:20]:
            _print(f"  - {f.category:8} {f.parameter or '-':10} {f.url}")

    if run.report_path:
        _print(f"\n[dim]Report written to {run.report_path}[/dim]")
    _print("[dim]Controlled functional benchmark on a known surface — not a claim "
           "against any live third-party app.[/dim]")


def _has_module(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None


def register(cli: click.Group) -> None:
    cli.add_command(benchmark)
