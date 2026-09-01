"""Scored, Docker-free functional benchmark for HEAVEN's API scanner.

This is the API-tier analogue of ``test_native_benchmark.py``. It drives the REAL
API scanner (``heaven/vulnscan/api_scanner.py`` — ``scan_api_targets``) against an
in-process, OWASP-API-Top-10-vulnerable target and scores the run with the SAME
metrics layer the web and network benchmarks use (precision / recall / F1 vs. a
labelled ground truth). It is fast (~1 s), deterministic, always-on in CI, and
needs no Docker and no network egress — so the API tier's headline number is
reproducible by anyone with ``pip install -e .[dev]``.

The run lives in ``tests/benchmarks/native/api_runner.py`` (``run_api_benchmark``)
so the CLI (``heaven benchmark --tier api``) and the web Benchmark page score the
API target by exactly the same code path this test enforces the floor on.

Controlled functional benchmark on a known, labelled surface — NOT a claim of
performance against any live third-party API.
"""

from __future__ import annotations

import pytest


def test_api_benchmark_scores() -> None:
    pytest.importorskip("flask")
    pytest.importorskip("aiohttp")
    pytest.importorskip("yaml")

    from tests.benchmarks.native.api_runner import run_api_benchmark

    run = run_api_benchmark()  # writes reports/api_benchmark.md
    result = run.result

    print()
    print("=" * 64)
    print(f"HEAVEN vs. {run.gt.target_app} (native API, Docker-free)")
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
            print(f"  - {f.category:20} {f.vuln_type:22} {f.endpoint or f.url}")
    print("=" * 64)

    # ── Floors. The native API target is a controlled surface with a COMPLETE
    #    ground truth (every finding the real scanner emits against it is labelled),
    #    so the honest bar is a perfect score: every required OWASP-API class found
    #    AND zero unmatched findings. Any unmatched finding is a genuine regression
    #    — either a real false positive to fix or a real finding to add to the
    #    ground truth — and must fail the benchmark. ──
    assert result.recall == 1.0, (
        f"missed required GT: detected {sorted(result.detected_required_ids)} "
        f"of {result.total_required}"
    )
    assert result.precision == 1.0, (
        f"precision {result.precision:.3f} — unmatched findings (each is either a "
        f"false positive to fix or a real finding to label in api.yaml): "
        f"{[(f.vuln_type, f.endpoint or f.url) for f in result.unmatched_findings]}"
    )
    assert result.f1 == 1.0, f"F1 {result.f1:.3f} — expected a perfect score on the native API surface"


def test_api_ground_truth_parses_and_is_api_tier() -> None:
    """The API ground truth loads, is api-tier, and every category is canonical."""
    pytest.importorskip("yaml")

    from pathlib import Path

    from tests.benchmarks.metrics import CANONICAL_CATEGORIES, GroundTruth

    gt_path = Path(__file__).resolve().parent / "ground_truth" / "api.yaml"
    gt = GroundTruth.load(gt_path)

    assert gt.vulnerabilities, "api.yaml has no entries"
    assert all(e.tier == "api" for e in gt.vulnerabilities), "every entry must be api-tier"
    assert all(e.category in CANONICAL_CATEGORIES for e in gt.vulnerabilities)
    # The eight must-find OWASP-API classes (the deep-query heuristic is supporting).
    assert gt.required_count == 8, f"expected 8 required entries, got {gt.required_count}"


class TestAPIMatcher:
    """Unit-level guards on the api-tier matcher, independent of a live scan."""

    def _gt(self, endpoint: str, category: str):
        from tests.benchmarks.metrics import GroundTruthEntry
        return GroundTruthEntry(
            id="t", endpoint=endpoint, method="GET", parameter=None,
            category=category, subtypes_ok=[], owasp="", cwe="", severity="high",
            difficulty="low", detection_required=True, tier="api",
        )

    def _finding(self, vuln_type: str, endpoint: str = "", url: str = "http://h"):
        from tests.benchmarks.metrics import Finding
        return Finding(url=url, vuln_type=vuln_type, endpoint=endpoint)

    def test_route_and_category_match(self):
        from tests.benchmarks.metrics import matches
        f = self._finding("bola", endpoint="/api/users/{id}")
        assert matches(f, self._gt("/api/users/", "bola"))

    def test_wrong_category_does_not_match(self):
        from tests.benchmarks.metrics import matches
        f = self._finding("api_broken_auth", endpoint="/api/users")
        assert not matches(f, self._gt("/api/users/", "bola"))

    def test_wrong_route_does_not_match(self):
        from tests.benchmarks.metrics import matches
        f = self._finding("bola", endpoint="/api/orders/{id}")
        assert not matches(f, self._gt("/api/users/", "bola"))

    def test_route_can_live_in_url_when_endpoint_blank(self):
        from tests.benchmarks.metrics import matches
        f = self._finding("api_docs_exposed", endpoint="", url="http://h/openapi.json")
        assert matches(f, self._gt("/openapi.json", "api_docs_exposed"))

    def test_bola_and_broken_auth_do_not_cross_match(self):
        """/api/users (collection, API2) and /api/users/{id} (object, API1) stay distinct."""
        from tests.benchmarks.metrics import matches
        obj = self._finding("bola", endpoint="/api/users/{id}")
        coll = self._finding("api_broken_auth", endpoint="/api/users")
        assert matches(obj, self._gt("/api/users/", "bola"))
        assert not matches(coll, self._gt("/api/users/", "bola"))
        assert matches(coll, self._gt("/api/users", "api_broken_auth"))
