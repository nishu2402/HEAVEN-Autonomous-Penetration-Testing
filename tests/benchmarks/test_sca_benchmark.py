"""Live SCA benchmark: prove HEAVEN's dependency audit against OSV.dev.

Gated by ``HEAVEN_RUN_BENCHMARKS=1`` (see conftest ``collect_ignore``): the
default ``pytest`` run never touches the network. When enabled, this audits the
inert vulnerable-dependency corpus in ``labs/sca-corpus/`` live against OSV and
asserts:

  * recall over the curated must-find CVEs is 100% (the advisories are permanent,
    so this is stable), and
  * the precision control holds — the patched half of the corpus reports NONE of
    the must-find CVEs (a fixed dependency is never flagged for the vuln it
    resolved).

If OSV cannot be reached, the test skips (offline-safe) rather than failing.
"""

from __future__ import annotations

import os

import pytest

from tests.benchmarks import sca_benchmark as sca


def _benchmarks_enabled() -> bool:
    return os.environ.get("HEAVEN_RUN_BENCHMARKS", "").lower() in ("1", "true", "yes")


def test_sca_benchmark_recall_and_precision_control():
    if not _benchmarks_enabled():
        pytest.skip("SCA benchmark gated by HEAVEN_RUN_BENCHMARKS=1")
    try:
        score = sca.run()
    except sca.OSVUnavailable as e:
        pytest.skip(f"OSV.dev unreachable — skipping live SCA benchmark: {e}")

    # Persist the real numbers for the Benchmark page / docs to cite.
    sca.write_report(score)

    assert score.recall == 1.0, (
        f"SCA recall {score.recall*100:.1f}% < 100%; missed {score.missed}")
    assert score.precision_control_passed, (
        f"patched pins wrongly flagged for fixed CVEs: {score.leaked_on_patched}")
    # Sanity: the vulnerable corpus really did produce a rich set of real
    # advisories (every one a true positive), far more than the curated floor.
    assert score.vulnerable_total_findings >= len(score.must_find_all)
