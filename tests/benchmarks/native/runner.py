"""Single source of truth for HEAVEN's Docker-free native benchmark.

The native benchmark drives the REAL crawler + injection / misconfig / out-of-band
scanners against a faithful, in-process reproduction of DVWA's injection endpoints
and scores the run with the same precision / recall / F1 metrics layer the Docker
DVWA benchmark uses. It needs no Docker, no network, and ~1 s to run — so anyone
with ``pip install -e ".[dev]"`` can reproduce the headline numbers.

Both the always-on regression test (``test_native_benchmark.py``) and the
``heaven benchmark`` CLI command call :func:`run_native_benchmark`, so the number
the CLI prints, the report the web UI renders, and the floor CI enforces are all
produced by exactly one code path.

This is a *controlled functional benchmark*: the target is a known surface, so the
score measures HEAVEN's end-to-end detection + attribution on it. It is NOT a claim
of performance against any live third-party app.
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
GT_PATH = _BENCH_DIR / "ground_truth" / "native.yaml"
REPORTS_DIR = _BENCH_DIR / "reports"
REPORT_NAME = "native_benchmark.md"


@dataclass
class NativeBenchmarkRun:
    """Everything one native benchmark run produced."""

    result: BenchmarkResult
    gt: GroundTruth
    markdown: str
    duration_seconds: float
    report_path: Path | None = None


async def _drive(base_url: str) -> tuple[list[dict], float]:
    """Run the real HEAVEN scanners against ``base_url`` and collect findings."""
    from heaven.recon.web_crawler import crawl_targets
    from heaven.vulnscan.injection_scanner import (
        build_injection_targets,
        scan_for_injections,
    )
    from heaven.vulnscan.misconfig_scanner import scan_misconfig
    from heaven.vulnscan.oast import OASTListener
    from heaven.vulnscan.oob_scanner import scan_oob

    start = time.time()
    crawl = await crawl_targets([base_url], stealth_level="aggressive")
    endpoints = crawl.get("endpoints", [])

    # Injection scanner — the classic surface (SQLi/XSS/LFI/cmdi).
    urls, forms_by_url = build_injection_targets(endpoints, seed_urls=[base_url])
    inj = await scan_for_injections(urls, forms_by_url=forms_by_url,
                                    stealth_level="aggressive")

    # The v1.0 misconfig + out-of-band scanners run over the SAME discovered
    # surface — param-less routes (/api/data, /login, /xxe/) that the injection
    # target builder drops are exactly where CORS/JWT/cookie/XXE live, so feed
    # every crawled URL plus the seed. One shared, loopback-bound collaborator
    # observes the SSRF/XXE callbacks; the app reaches it over 127.0.0.1.
    discovered = list({ep.get("url", "") for ep in endpoints if ep.get("url")} | {base_url})
    mis = await scan_misconfig(discovered)
    with OASTListener() as oast:
        oob = await scan_oob(discovered, oast=oast)

    findings = (inj.get("findings", []) + mis.get("findings", [])
                + oob.get("findings", []))
    return findings, time.time() - start


def run_native_benchmark(*, write_report: bool = True) -> NativeBenchmarkRun:
    """Run the native benchmark end-to-end and score it.

    Requires the optional ``[dev]`` extras (flask / bs4 / aiohttp / pyyaml). When
    ``write_report`` is set (the default) a publication-style markdown report is
    written to ``tests/benchmarks/reports/native_benchmark.md`` — the same file the
    web Benchmark page renders.
    """
    from tests.benchmarks.native.vuln_app import serve
    from tests.benchmarks.reporters.markdown_report import render_markdown_report

    gt = GroundTruth.load(GT_PATH)

    with serve() as base_url:
        gt.base_url = base_url  # report header only; matching is by path
        raw_findings, duration = asyncio.run(_drive(base_url))

    findings = [Finding.from_heaven(f) for f in raw_findings]
    result = evaluate(findings, gt, duration_seconds=duration)
    markdown = render_markdown_report(result, gt, scanner_name="HEAVEN")

    report_path: Path | None = None
    if write_report:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORTS_DIR / REPORT_NAME
        report_path.write_text(markdown, encoding="utf-8")

    return NativeBenchmarkRun(
        result=result,
        gt=gt,
        markdown=markdown,
        duration_seconds=duration,
        report_path=report_path,
    )
