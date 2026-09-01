"""HEAVEN — `heaven benchmark` (score the scanner against a labelled target).

Runs a Docker-free *native* benchmark: the real scanners against a faithful,
in-process reproduction of a vulnerable target, scored with precision / recall /
F1 against a labelled ground truth. No Docker, no network, ~1 s.

Two always-on tiers share this one command (pick with ``--tier``):

* ``web`` (default) — the crawler + injection / misconfig / out-of-band scanners
  vs. a reproduction of DVWA's vulnerable endpoints.
* ``api`` — the OWASP-API-Top-10 scanner (``scan_api_targets``) vs. a reproduction
  of a BOLA / mass-assignment / secret-leak / GraphQL-vulnerable API.

Each tier is the same run its always-on regression test enforces a floor on and
the web Benchmark page renders — one code path per tier
(``tests/benchmarks/native/runner.py`` and ``.../api_runner.py``), so the CLI
number, the UI number and CI never drift.

These are *controlled functional benchmarks* on known surfaces — NOT a claim of
performance against any live third-party app. For that, run the live Docker DVWA
benchmark (``HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py``)
or the live Metasploitable-2 network benchmark (``... test_msf2_baseline.py``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from heaven.cli._helpers import _print, emit_json, json_output

# Repo root holds the (non-packaged) `tests/` tree the benchmark lives in. The
# API server resolves the same root the same way to read the report files.
_REPO_ROOT = Path(__file__).resolve().parents[2]

# tier → (loader import path attr, human label, target-kind slug).
_TIERS = {
    "web": ("run_native_benchmark", "web (DVWA-class)", "native-controlled"),
    "api": ("run_api_benchmark", "api (OWASP API Top 10)", "native-controlled-api"),
}


def _load_runner(tier: str):
    """Import a native benchmark runner, making `tests/` importable first.

    `tests/` ships with the source checkout but isn't part of the installed
    `heaven` package, so add the repo root to `sys.path` before importing.
    Returns None when the source tree isn't present (e.g. a bare wheel install).
    """
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    try:
        if tier == "api":
            from tests.benchmarks.native.api_runner import run_api_benchmark
            return run_api_benchmark
        from tests.benchmarks.native.runner import run_native_benchmark
        return run_native_benchmark
    except Exception:
        return None


def _build_payload(run, source: str) -> dict:
    """Shape one benchmark run into the JSON payload the CLI + web share."""
    result = run.result
    per_cat = {}
    for cat, bucket in result.per_category.items():
        total = bucket.get("gt_total", 0)
        detected = bucket.get("gt_detected", 0)
        per_cat[cat] = {
            "gt_total": total,
            "detected": detected,
            "recall": (detected / total) if total else 0.0,
        }
    return {
        "available": True,
        "source": source,
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


def _print_payload(run, payload: dict) -> None:
    """Render one run's headline + per-category table to the terminal."""
    result = run.result
    _print(f"\n[bold cyan]HEAVEN vs. {run.gt.target_app} v{run.gt.version}[/bold cyan]"
           f"  [dim](native, Docker-free · {run.duration_seconds:.1f}s)[/dim]")
    _print(f"  Precision : [bold]{result.precision * 100:5.1f}%[/bold]"
           f"   [dim]{result.matched_finding_count}/"
           f"{result.matched_finding_count + result.unmatched_finding_count} findings real[/dim]")
    _print(f"  Recall    : [bold]{result.recall * 100:5.1f}%[/bold]"
           f"   [dim]{len(result.detected_required_ids)}/{result.total_required} required GT[/dim]")
    _print(f"  F1        : [bold]{result.f1 * 100:5.1f}%[/bold]")

    _print("\n[bold]Per-category recall[/bold]")
    for cat in sorted(payload["per_category"]):
        c = payload["per_category"][cat]
        _print(f"  {cat:22} {c['recall'] * 100:5.1f}%"
               f"   [dim]{c['detected']}/{c['gt_total']}[/dim]")

    if result.unmatched_findings:
        _print("\n[yellow]Findings without a ground-truth match (potential FPs):[/yellow]")
        for f in result.unmatched_findings[:20]:
            _print(f"  - {f.category:8} {f.parameter or '-':10} {f.endpoint or f.url}")

    if run.report_path:
        _print(f"[dim]Report written to {run.report_path}[/dim]")


@click.command(name="benchmark")
@click.option("--tier", type=click.Choice(["web", "api", "all"]), default="web",
              show_default=True,
              help="Which native benchmark to score: the web (DVWA-class) tier, "
                   "the api (OWASP API Top 10) tier, or all of them.")
@click.option("--json", "as_json", is_flag=True,
              help="Emit machine-readable JSON instead of a table.")
@click.option("--no-report", is_flag=True,
              help="Don't write reports/*.md (just print).")
@click.option("--scorecard", type=click.Path(), default=None,
              help="Also write the headline metrics as a machine-readable JSON "
                   "scorecard to this path (for CI badges / a committed artifact).")
def benchmark(tier: str, as_json: bool, no_report: bool, scorecard: str | None) -> None:
    """Score HEAVEN's scanners against the built-in labelled targets.

    Runs the real detectors against faithful, in-process reproductions of
    vulnerable targets and reports precision / recall / F1 vs. ground truth — the
    same numbers the web Benchmark page shows. Docker-free, ~1 s per tier.
    """
    want = ["web", "api"] if tier == "all" else [tier]

    # Optional deps (flask / bs4 / aiohttp / pyyaml) back the in-process targets.
    # The API tier does not need bs4 (no HTML crawl), but requiring the full [dev]
    # extras keeps the message simple and the two tiers reproducible together.
    missing = [m for m in ("flask", "aiohttp", "yaml") if not _has_module(m)]
    if "web" in want and not _has_module("bs4"):
        missing.append("bs4")
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
        _print("[dim]Running native benchmark(s) (real scanners vs. labelled target)…[/dim]")

    runs: dict[str, tuple] = {}  # tier -> (run, payload)
    for t in want:
        runner = _load_runner(t)
        if runner is None:
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
        run = runner(write_report=not no_report)
        runs[t] = (run, _build_payload(run, _TIERS[t][2]))

    # Optional committed artifact: a compact, machine-readable scorecard so the
    # README / CI / web can all cite one canonical headline number. For a single
    # tier it keeps the original flat shape; for --tier all it is keyed by tier.
    if scorecard:
        _write_scorecard(scorecard, runs, as_json)

    if as_json or json_output():
        if tier == "all":
            emit_json({"available": True, "tiers": {t: p for t, (_, p) in runs.items()}})
        else:
            emit_json(runs[want[0]][1])
        return

    for t in want:
        run, payload = runs[t]
        _print(f"\n[bold]▶ {_TIERS[t][1]} tier[/bold]")
        _print_payload(run, payload)

    _print("\n[dim]Controlled functional benchmark on known surfaces — not a claim "
           "against any live third-party app.[/dim]")


def _write_scorecard(scorecard: str, runs: dict, as_json: bool) -> None:
    import datetime as _dt
    import json as _json

    def _card(payload: dict) -> dict:
        return {
            "tool": "HEAVEN", "kind": "native-controlled-functional-benchmark",
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "target": payload["target"], "target_version": payload["target_version"],
            "metrics": payload["metrics"],
            "required_detected": payload["required_detected"],
            "required_total": payload["required_total"],
            "categories": sorted(payload["per_category"]),
            "duration_seconds": payload["duration_seconds"],
            "note": ("Controlled functional benchmark on a known, labelled surface — "
                     "measures end-to-end detection + attribution, not a claim against "
                     "any live third-party app."),
        }

    if len(runs) == 1:
        card = _card(next(iter(runs.values()))[1])
    else:
        card = {t: _card(p) for t, (_, p) in runs.items()}
    _sc = Path(scorecard)
    _sc.parent.mkdir(parents=True, exist_ok=True)
    _sc.write_text(_json.dumps(card, indent=2) + "\n")
    if not (as_json or json_output()):
        _print(f"[dim]Scorecard written to {scorecard}[/dim]")


def _has_module(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None


def register(cli: click.Group) -> None:
    cli.add_command(benchmark)
