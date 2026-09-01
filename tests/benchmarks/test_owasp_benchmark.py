"""Live OWASP Benchmark (Java) SAST benchmark.

Scores HEAVEN's real, shipped SAST engine (builtin rule pack, including the Java
rules) against the full OWASP Benchmark v1.2 corpus (2 740 Java test cases) and
asserts the measured scorecard clears an honest floor.

Gating mirrors the domain labs: it runs only when ``HEAVEN_RUN_BENCHMARKS=1`` is
set. The corpus is not vendored (GPLv2 vs HEAVEN's MIT); it is taken from
``HEAVEN_OWASP_BENCHMARK_DIR`` when set, otherwise shallow-cloned from the pinned
upstream. Without an env checkout and without git/network, the test skips with a
clear reason rather than failing.

The floors below sit well under the numbers this engine actually produces
(pooled Youden ~0.51, recall ~0.96 at the time of writing) so the test guards
against a regression in the rules or the scorer without pinning an aspirational
target. Run it, and print the live scorecard, with:

    HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_owasp_benchmark.py -s
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from tests.benchmarks import owasp_benchmark as ob
from tests.benchmarks.labs.harness import benchmarks_enabled
from heaven.vulnscan.sast_runner import has_semgrep


def _obtain_corpus() -> tuple[ob.BenchmarkCorpus, Path | None]:
    """Return (corpus, tmp_to_cleanup). Skips the test if it cannot be obtained."""
    corpus = ob.locate_corpus()
    if corpus is not None:
        return corpus, None
    if shutil.which("git") is None:
        pytest.skip(
            "No OWASP Benchmark checkout: set HEAVEN_OWASP_BENCHMARK_DIR to a "
            "BenchmarkJava clone, or install git so the corpus can be fetched."
        )
    tmp = Path(tempfile.mkdtemp(prefix="heaven_owasp_bench_"))
    try:
        corpus = ob.clone_pinned(tmp)
    except Exception as e:  # network/git failure — skip, don't fail
        shutil.rmtree(tmp, ignore_errors=True)
        pytest.skip(f"could not fetch the OWASP Benchmark corpus: {e}")
    return corpus, tmp


@pytest.mark.skipif(not benchmarks_enabled(),
                    reason="Live benchmark gated by HEAVEN_RUN_BENCHMARKS=1")
@pytest.mark.skipif(not has_semgrep(), reason="semgrep not installed")
def test_heaven_sast_scores_owasp_benchmark():
    corpus, tmp = _obtain_corpus()
    try:
        card = asyncio.run(ob.run(corpus, timeout_s=1800))
        print("\n" + card.render())

        # The real v1.2 corpus is 2 740 cases; tolerate a future corpus refresh.
        assert card.total_cases >= 2000, card.render()
        assert card.corpus_version.startswith("1."), card.corpus_version
        assert card.findings_count >= 2000, card.render()

        # Honest floors, set below the live-measured numbers (Youden ~0.51,
        # recall ~0.96) to catch a regression, not to assert an aspiration.
        assert card.youden >= 0.42, card.render()
        assert card.recall >= 0.88, card.render()
        assert card.precision >= 0.55, card.render()

        # Every one of the eleven detectors fires live on the corpus.
        for cat, cs in card.per_category.items():
            assert cs.tp >= 1, f"category {cat} produced no true positives\n{card.render()}"

        # The clean API-pattern classes are near-perfect (no taint ambiguity).
        for cat in ("weakrand", "crypto", "securecookie"):
            assert card.per_category[cat].youden >= 0.90, card.render()
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
