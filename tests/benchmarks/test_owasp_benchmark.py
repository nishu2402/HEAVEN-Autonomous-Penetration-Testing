"""Live OWASP Benchmark (Java) SAST benchmark.

Scores HEAVEN's real, shipped SAST engine (builtin rule pack, including the Java
rules) against the full OWASP Benchmark v1.2 corpus (2 740 Java test cases) and
asserts the measured scorecard clears an honest floor.

Gating mirrors the domain labs: it runs only when ``HEAVEN_RUN_BENCHMARKS=1`` is
set. The corpus is not vendored (GPLv2 vs HEAVEN's MIT); it is taken from
``HEAVEN_OWASP_BENCHMARK_DIR`` when set, otherwise fetched once from the pinned
upstream into a per-user cache (``$XDG_CACHE_HOME/heaven/owasp-benchmark``) and
reused across runs. Without an env checkout and without git/network, the test
skips with a clear reason rather than failing.

The floors below sit well under the numbers this engine actually produces
(pooled Youden ~0.52, recall ~0.97, precision ~0.70 at the time of writing) so
the test guards against a regression in the rules or the scorer without pinning
an aspirational target. Run it, and print the live scorecard, with:

    HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_owasp_benchmark.py -s
"""

from __future__ import annotations

import asyncio

import pytest

from tests.benchmarks import owasp_benchmark as ob
from tests.benchmarks.labs.harness import benchmarks_enabled
from heaven.vulnscan.sast_runner import has_semgrep


def _obtain_corpus() -> ob.BenchmarkCorpus:
    """Return a ready corpus (env checkout or a persistent cached clone).

    The corpus is fetched once into a per-user cache and reused across runs, so
    a repeated benchmark run never re-pulls the ~300 MB tree. Skips the test if
    it cannot be obtained (no git, no network)."""
    try:
        return ob.get_or_fetch_corpus()
    except Exception as e:  # git missing / network failure — skip, don't fail
        pytest.skip(
            "No OWASP Benchmark corpus: set HEAVEN_OWASP_BENCHMARK_DIR to a "
            f"BenchmarkJava clone, or allow git to fetch it ({e})."
        )


@pytest.mark.skipif(not benchmarks_enabled(),
                    reason="Live benchmark gated by HEAVEN_RUN_BENCHMARKS=1")
@pytest.mark.skipif(not has_semgrep(), reason="semgrep not installed")
def test_heaven_sast_scores_owasp_benchmark():
    corpus = _obtain_corpus()
    card = asyncio.run(ob.run(corpus, timeout_s=1800))
    print("\n" + card.render())

    # The real v1.2 corpus is 2 740 cases; tolerate a future corpus refresh.
    assert card.total_cases >= 2000, card.render()
    assert card.corpus_version.startswith("1."), card.corpus_version
    assert card.findings_count >= 2000, card.render()

    # Honest floors, set below the live-measured numbers (Youden ~0.52,
    # recall ~0.97, precision ~0.70) to catch a regression, not to assert an
    # aspiration. The residual gap is structural, not a rules deficiency: the
    # FPs are the Benchmark's synthetic dead-code obfuscations (arithmetic
    # always-true ternaries, switch-on-constant, key-insensitive collection
    # overwrites) that a rule engine cannot fold, and the FNs are the
    # config-driven hash cases (weak algorithm named in a .properties file).
    assert card.youden >= 0.48, card.render()
    assert card.recall >= 0.93, card.render()
    assert card.precision >= 0.62, card.render()

    # Every one of the eleven detectors fires live on the corpus.
    for cat, cs in card.per_category.items():
        assert cs.tp >= 1, f"category {cat} produced no true positives\n{card.render()}"

    # The clean API-pattern classes are near-perfect (no taint ambiguity).
    for cat in ("weakrand", "crypto", "securecookie"):
        assert card.per_category[cat].youden >= 0.90, card.render()

    # The taint classes reach every real vulnerability: the only recall gap
    # the engine cannot close honestly is the config-driven hash cases, so
    # every injection category should detect all of its real vulns.
    for cat in ("cmdi", "sqli", "xss", "pathtraver", "ldapi", "xpathi",
                "trustbound"):
        assert card.per_category[cat].tpr >= 0.95, card.render()
