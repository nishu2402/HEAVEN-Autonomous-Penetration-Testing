"""Single source of truth for HEAVEN's Docker-free native **API** benchmark.

The API analogue of ``native/runner.py``: it drives the REAL API scanner
(``heaven/vulnscan/api_scanner.py`` — ``scan_api_targets``) against a faithful,
in-process reproduction of an OWASP-API-Top-10-vulnerable service
(``native/api_app.py``) and scores the run with the SAME precision / recall / F1
metrics layer the web and network benchmarks use. It needs no Docker, no network
egress, and ~1 s — so the API tier gets an always-on, reproducible number too.

Both the always-on regression test (``test_api_benchmark.py``) and the
``heaven benchmark --tier api`` command call :func:`run_api_benchmark`, so the CLI
number, the web Benchmark page, and the floor CI enforces are one code path.

This is a *controlled functional benchmark*: the target is a known, labelled
surface, so it measures HEAVEN's end-to-end API detection + attribution. It is NOT
a claim of performance against any live third-party API.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path

from tests.benchmarks.metrics import (
    BenchmarkResult,
    Finding,
    GroundTruth,
    evaluate,
)

_BENCH_DIR = Path(__file__).resolve().parents[1]
GT_PATH = _BENCH_DIR / "ground_truth" / "api.yaml"
REPORTS_DIR = _BENCH_DIR / "reports"
REPORT_NAME = "api_benchmark.md"


@dataclass
class APIBenchmarkRun:
    """Everything one native API benchmark run produced."""

    result: BenchmarkResult
    gt: GroundTruth
    markdown: str
    duration_seconds: float
    report_path: Path | None = None


async def _drive(base_url: str) -> tuple[list[dict], float]:
    """Run the real HEAVEN API scanner against ``base_url`` and collect findings."""
    from heaven.vulnscan.api_scanner import scan_api_targets

    start = time.time()
    out = await scan_api_targets(urls=[base_url])
    return out.get("findings", []), time.time() - start


def run_api_benchmark(*, write_report: bool = True) -> APIBenchmarkRun:
    """Run the native API benchmark end-to-end and score it.

    Requires the optional ``[dev]`` extras (flask / aiohttp / pyyaml). When
    ``write_report`` is set (the default) a publication-style markdown report is
    written to ``tests/benchmarks/reports/api_benchmark.md`` — the same file the
    web Benchmark page renders for the API tier.
    """
    from tests.benchmarks.native.api_app import serve
    from tests.benchmarks.reporters.markdown_report import render_markdown_report

    gt = GroundTruth.load(GT_PATH)

    with serve() as base_url:
        gt.base_url = base_url  # report header only; matching is by route + category
        raw_findings, duration = asyncio.run(_drive(base_url))

    findings = [Finding.from_heaven(f) for f in raw_findings]
    result = evaluate(findings, gt, duration_seconds=duration)

    from heaven import __version__ as _heaven_version
    markdown = render_markdown_report(
        result, gt, scanner_name="HEAVEN", scanner_version=_heaven_version
    )

    report_path: Path | None = None
    if write_report:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORTS_DIR / REPORT_NAME
        report_path.write_text(markdown, encoding="utf-8")

    return APIBenchmarkRun(
        result=result,
        gt=gt,
        markdown=markdown,
        duration_seconds=duration,
        report_path=report_path,
    )
