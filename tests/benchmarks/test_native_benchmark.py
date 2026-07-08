"""Scored, Docker-free functional benchmark for HEAVEN's web scanner.

Unlike the Docker DVWA benchmark (which needs QEMU on arm64 and is gated behind
HEAVEN_RUN_BENCHMARKS), this runs the REAL crawler + injection scanner against
the in-process native target and scores the run with the SAME metrics layer the
DVWA benchmark uses (precision / recall / F1 vs. a labelled ground truth). It is
fast (~1 s), deterministic, and always-on in CI, so the headline numbers are
reproducible by anyone with `pip install -e .[dev]` and no Docker at all.

This is a *controlled functional benchmark*: the target is a faithful
reproduction of DVWA's injection endpoints (including MySQL comment semantics),
so the score measures HEAVEN's end-to-end detection + attribution on a known
surface. It is NOT a claim of performance against any live third-party app.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.benchmarks.metrics import Finding, GroundTruth, evaluate

_GT_PATH = Path(__file__).resolve().parent / "ground_truth" / "native.yaml"


def _reports_dir() -> Path:
    d = Path(__file__).resolve().parent / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_native_benchmark_scores() -> None:
    pytest.importorskip("flask")
    pytest.importorskip("bs4")
    pytest.importorskip("aiohttp")
    pytest.importorskip("yaml")

    import time

    from heaven.recon.web_crawler import crawl_targets
    from heaven.vulnscan.injection_scanner import (
        build_injection_targets,
        scan_for_injections,
    )
    from heaven.vulnscan.misconfig_scanner import scan_misconfig
    from heaven.vulnscan.oast import OASTListener
    from heaven.vulnscan.oob_scanner import scan_oob

    from tests.benchmarks.native.vuln_app import serve

    gt = GroundTruth.load(_GT_PATH)

    async def _drive(base_url: str) -> tuple[list[dict], float]:
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

    with serve() as base_url:
        gt.base_url = base_url  # for the report header; matching is by path
        raw_findings, duration = asyncio.run(_drive(base_url))

    findings = [Finding.from_heaven(f) for f in raw_findings]
    result = evaluate(findings, gt, duration_seconds=duration)

    # Write a publication-style report (reports/ is gitignored).
    from tests.benchmarks.reporters.markdown_report import render_markdown_report
    report = render_markdown_report(result, gt, scanner_name="HEAVEN")
    (_reports_dir() / "native_benchmark.md").write_text(report, encoding="utf-8")

    print()
    print("=" * 64)
    print(f"HEAVEN vs. {gt.target_app} (native, Docker-free)")
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
