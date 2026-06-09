"""
Metrics-layer unit tests. Run in normal CI — no Docker required.

These tests validate the matching predicate, the TP/FP/FN math, and the
multi-run aggregation. If they pass, the benchmark numbers can be trusted;
if they fail, every publication claim derived from this suite is suspect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.benchmarks.metrics import (
    Finding,
    GroundTruth,
    GroundTruthEntry,
    aggregate,
    evaluate,
    matches,
    normalize_category,
)


# ═══════════════════════════════════════════
# CATEGORY NORMALISATION
# ═══════════════════════════════════════════


class TestNormalizeCategory:
    @pytest.mark.parametrize("raw,expected", [
        ("sqli", "sqli"),
        ("sqli_boolean", "sqli"),
        ("sqli_time", "sqli"),
        ("SQL Injection", "sqli"),
        ("xss_reflected", "xss"),
        ("Cross-Site Scripting", "xss"),
        ("command_injection", "cmdi"),
        ("os_command_injection", "cmdi"),
        ("rce", "cmdi"),
        ("path_traversal", "lfi"),
        ("local_file_inclusion", "lfi"),
        ("ssrf", "ssrf"),
        ("ssti", "ssti"),
        ("csrf", "csrf"),
        ("open_redirect", "open_redirect"),
        ("unvalidated_redirect", "open_redirect"),
    ])
    def test_known_types_normalise(self, raw: str, expected: str) -> None:
        assert normalize_category(raw) == expected

    def test_unknown_type_returns_lowercase(self) -> None:
        # Unknown but harmless — return lower-cased input
        assert normalize_category("CustomThing") == "customthing"

    def test_empty_string_returns_empty(self) -> None:
        assert normalize_category("") == ""

    def test_split_on_underscore_fallback(self) -> None:
        # Unknown compound name — first token wins if it's known
        assert normalize_category("sqli_someweirdvariant") == "sqli"


# ═══════════════════════════════════════════
# FINDING ADAPTER
# ═══════════════════════════════════════════


class TestFindingFromHeaven:
    def test_full_finding_dict(self) -> None:
        d = {
            "target": "http://x/sqli/?id=1",
            "vuln_type": "sqli_boolean",
            "confidence": 0.93,
            "severity": "critical",
            "evidence": {"parameter": "id", "payload": "1 AND 1=1"},
        }
        f = Finding.from_heaven(d)
        assert f.url == "http://x/sqli/?id=1"
        assert f.vuln_type == "sqli_boolean"
        assert f.parameter == "id"
        assert f.confidence == pytest.approx(0.93)
        assert f.severity == "critical"
        assert f.category == "sqli"

    def test_evidence_as_json_string(self) -> None:
        d = {
            "target": "http://x/xss?q=foo",
            "vuln_type": "xss_reflected",
            "evidence": '{"parameter": "q"}',
        }
        f = Finding.from_heaven(d)
        assert f.parameter == "q"
        assert f.category == "xss"

    def test_missing_fields_default_to_empty(self) -> None:
        f = Finding.from_heaven({})
        assert f.url == ""
        assert f.vuln_type == ""
        assert f.parameter == ""
        assert f.confidence == 0.0

    def test_url_falls_back_to_url_key(self) -> None:
        f = Finding.from_heaven({"url": "http://x/y", "vuln_type": "sqli"})
        assert f.url == "http://x/y"


# ═══════════════════════════════════════════
# MATCHER
# ═══════════════════════════════════════════


def _gt(**kw) -> GroundTruthEntry:
    """GT entry factory with sensible defaults for tests."""
    defaults: dict = dict(
        id="gt-test",
        endpoint="/vuln/",
        method="GET",
        parameter="id",
        category="sqli",
        subtypes_ok=[],
        owasp="A03_2021",
        cwe="CWE-89",
        severity="critical",
        difficulty="low",
        detection_required=True,
        notes="",
    )
    defaults.update(kw)
    return GroundTruthEntry(**defaults)


class TestMatches:
    def test_full_match_returns_true(self) -> None:
        f = Finding(url="http://x/vuln/?id=1", vuln_type="sqli_boolean", parameter="id")
        assert matches(f, _gt()) is True

    def test_url_mismatch_returns_false(self) -> None:
        f = Finding(url="http://x/other/", vuln_type="sqli", parameter="id")
        assert matches(f, _gt()) is False

    def test_category_mismatch_returns_false(self) -> None:
        f = Finding(url="http://x/vuln/?id=1", vuln_type="xss", parameter="id")
        assert matches(f, _gt(category="sqli")) is False

    def test_parameter_mismatch_returns_false(self) -> None:
        f = Finding(url="http://x/vuln/?name=x", vuln_type="sqli", parameter="name")
        assert matches(f, _gt(parameter="id")) is False

    def test_parameter_case_insensitive(self) -> None:
        f = Finding(url="http://x/vuln/", vuln_type="sqli", parameter="ID")
        assert matches(f, _gt(parameter="id")) is True

    def test_missing_finding_parameter_is_tolerated(self) -> None:
        # Some scanners don't attribute findings to a specific param — we
        # match anyway to avoid penalising them.
        f = Finding(url="http://x/vuln/?id=1", vuln_type="sqli", parameter="")
        assert matches(f, _gt(parameter="id")) is True

    def test_gt_without_parameter_matches_any(self) -> None:
        f = Finding(url="http://x/vuln/?anything=1", vuln_type="sqli", parameter="whatever")
        assert matches(f, _gt(parameter=None)) is True

    def test_canonical_normalisation_at_match_time(self) -> None:
        # "sqli_time" → category "sqli", matches GT with category "sqli"
        f = Finding(url="http://x/vuln/?id=1", vuln_type="sqli_time", parameter="id")
        assert matches(f, _gt(category="sqli")) is True


# ═══════════════════════════════════════════
# EVALUATE — synthetic findings vs. synthetic GT
# ═══════════════════════════════════════════


def _gt_doc() -> GroundTruth:
    """Small synthetic GT for evaluate() tests: 3 required + 1 optional."""
    return GroundTruth(
        target_app="synthetic",
        version="0",
        base_url="http://x",
        vulnerabilities=[
            _gt(id="req-sqli",  endpoint="/sqli/",  category="sqli",
                detection_required=True),
            _gt(id="req-xss",   endpoint="/xss/",   parameter="q",
                category="xss", detection_required=True),
            _gt(id="req-cmdi",  endpoint="/exec/",  parameter="ip",
                category="cmdi", detection_required=True),
            _gt(id="opt-csrf",  endpoint="/csrf/",  parameter="tok",
                category="csrf", detection_required=False),
        ],
    )


class TestEvaluate:
    def test_perfect_detection(self) -> None:
        gt = _gt_doc()
        findings = [
            Finding(url="http://x/sqli/?id=1",  vuln_type="sqli_boolean", parameter="id"),
            Finding(url="http://x/xss/?q=z",    vuln_type="xss_reflected", parameter="q"),
            Finding(url="http://x/exec/",       vuln_type="rce", parameter="ip"),
            Finding(url="http://x/csrf/",       vuln_type="csrf", parameter="tok"),
        ]
        result = evaluate(findings, gt)
        assert result.detected_count == 4
        assert len(result.detected_required_ids) == 3
        assert result.matched_finding_count == 4
        assert result.unmatched_finding_count == 0
        assert result.precision == pytest.approx(1.0)
        assert result.recall == pytest.approx(1.0)  # required-only recall
        assert result.recall_overall == pytest.approx(1.0)
        assert result.f1 == pytest.approx(1.0)
        assert result.missed_required_count == 0

    def test_missed_required_drops_recall(self) -> None:
        gt = _gt_doc()
        findings = [
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
            Finding(url="http://x/xss/?q=z",   vuln_type="xss",  parameter="q"),
            # missed: /exec/, /csrf/
        ]
        result = evaluate(findings, gt)
        assert result.recall == pytest.approx(2/3)        # 2 of 3 required
        assert result.recall_overall == pytest.approx(0.5)  # 2 of 4 total
        assert result.missed_required_count == 1
        assert result.precision == pytest.approx(1.0)     # no FPs

    def test_false_positives_drop_precision(self) -> None:
        gt = _gt_doc()
        findings = [
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
            Finding(url="http://x/elsewhere",  vuln_type="sqli", parameter="z"),  # FP
            Finding(url="http://x/another",    vuln_type="xss",  parameter="q"),  # FP
        ]
        result = evaluate(findings, gt)
        assert result.matched_finding_count == 1
        assert result.unmatched_finding_count == 2
        assert result.precision == pytest.approx(1/3)

    def test_per_category_breakdown(self) -> None:
        gt = _gt_doc()
        findings = [
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
            Finding(url="http://x/sqli/?id=2", vuln_type="sqli", parameter="id"),  # duplicate cat
        ]
        result = evaluate(findings, gt)
        sqli_bucket = result.per_category["sqli"]
        assert sqli_bucket["findings"] == 2
        assert sqli_bucket["matched"] == 2  # both match the same GT
        assert sqli_bucket["gt_total"] == 1
        assert sqli_bucket["gt_detected"] == 1
        # XSS and cmdi entries should appear with 0/1 detection
        xss_bucket = result.per_category.get("xss", {})
        assert xss_bucket.get("gt_total", 0) == 1
        assert xss_bucket.get("gt_detected", 0) == 0

    def test_empty_findings_yields_zero_metrics(self) -> None:
        gt = _gt_doc()
        result = evaluate([], gt)
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1 == 0.0
        assert result.missed_required_count == 3

    def test_one_finding_matches_multiple_gt(self) -> None:
        # Two GT entries (low + medium difficulty) on the same endpoint.
        # A single finding should count both as detected.
        gt = GroundTruth(
            target_app="x", version="0", base_url="http://x",
            vulnerabilities=[
                _gt(id="low",    endpoint="/sqli/", difficulty="low"),
                _gt(id="medium", endpoint="/sqli/", difficulty="medium"),
            ],
        )
        findings = [Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id")]
        result = evaluate(findings, gt)
        assert result.detected_count == 2
        assert result.matched_finding_count == 1


# ═══════════════════════════════════════════
# AGGREGATE — multi-run statistics
# ═══════════════════════════════════════════


class TestAggregate:
    def test_single_run_yields_zero_stddev(self) -> None:
        gt = _gt_doc()
        findings = [Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id")]
        result = evaluate(findings, gt)
        agg = aggregate([result])
        assert agg.runs == 1
        assert agg.std_precision == 0.0
        assert agg.std_recall == 0.0
        assert agg.mean_precision == pytest.approx(result.precision)
        assert agg.mean_recall == pytest.approx(result.recall)

    def test_two_runs_compute_mean_and_stddev(self) -> None:
        gt = _gt_doc()
        # Run A: detects all 3 required → recall=1.0
        # Run B: detects 2 of 3 required → recall=0.667
        a = evaluate([
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
            Finding(url="http://x/xss/?q=z",   vuln_type="xss", parameter="q"),
            Finding(url="http://x/exec/",      vuln_type="rce", parameter="ip"),
        ], gt)
        b = evaluate([
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
            Finding(url="http://x/xss/?q=z",   vuln_type="xss", parameter="q"),
        ], gt)
        agg = aggregate([a, b])
        assert agg.runs == 2
        assert agg.mean_recall == pytest.approx((1.0 + 2/3) / 2)
        assert agg.std_recall > 0.0
        assert agg.missed_required_min == 0
        assert agg.missed_required_max == 1

    def test_per_category_recall_aggregates(self) -> None:
        gt = _gt_doc()
        a = evaluate([
            Finding(url="http://x/sqli/?id=1", vuln_type="sqli", parameter="id"),
        ], gt)
        b = evaluate([], gt)  # nothing detected
        agg = aggregate([a, b])
        # sqli detected 1 of 1 in run a, 0 of 1 in run b → mean recall 0.5
        assert agg.per_category_recall["sqli"] == pytest.approx(0.5)
        # xss detected 0 of 1 in both runs → mean 0.0
        assert agg.per_category_recall.get("xss", 0.0) == pytest.approx(0.0)

    def test_empty_runs_raises(self) -> None:
        with pytest.raises(ValueError):
            aggregate([])


# ═══════════════════════════════════════════
# GROUND-TRUTH YAML LOADER
# ═══════════════════════════════════════════


class TestGroundTruthLoader:
    def test_loads_dvwa_yaml_without_error(self) -> None:
        # The shipped DVWA file must always parse and pass schema validation.
        path = Path(__file__).parent / "ground_truth" / "dvwa.yaml"
        gt = GroundTruth.load(path)
        assert gt.target_app == "dvwa"
        assert gt.base_url
        assert len(gt.vulnerabilities) >= 8  # sanity floor
        assert gt.required_count >= 5
        # Every entry uses a canonical category
        from tests.benchmarks.metrics import CANONICAL_CATEGORIES
        for e in gt.vulnerabilities:
            assert e.category in CANONICAL_CATEGORIES

    def test_unknown_category_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "target_app: t\nversion: '1'\nbase_url: http://x\n"
            "vulnerabilities:\n"
            "  - id: x\n"
            "    endpoint: /\n"
            "    method: GET\n"
            "    parameter: id\n"
            "    category: nonsense_not_canonical\n"
            "    subtypes_ok: []\n"
            "    owasp: A01_2021\n"
            "    cwe: CWE-0\n"
            "    severity: low\n"
            "    difficulty: low\n"
            "    detection_required: false\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="unknown category"):
            GroundTruth.load(bad)


# ═══════════════════════════════════════════
# END-TO-END SCORING OF THE 1.0.0 INJECTION CLASSES
# ═══════════════════════════════════════════


class TestNewClassesScoreAgainstDvwaGroundTruth:
    """Regression guard for the SQLi/LFI/CmdI probes shipped in 1.0.0.

    The scanner emits findings with ``vuln_type`` of ``"sqli"``, ``"lfi"`` and
    ``"cmdi"``. Those strings must (a) normalise to the canonical categories the
    DVWA ground-truth uses and (b) match the corresponding GT endpoints so they
    are scored as true positives. A future rename of any vuln_type would
    silently zero-out these benchmark numbers — this test fails loudly first.
    """

    _DVWA_GT = Path(__file__).parent / "ground_truth" / "dvwa.yaml"

    def _gt(self) -> GroundTruth:
        return GroundTruth.load(self._DVWA_GT)

    def test_injection_findings_match_their_gt_entries(self) -> None:
        gt = self._gt()
        base = gt.base_url.rstrip("/")
        findings = [
            Finding(url=f"{base}/vulnerabilities/sqli/?id=1",
                    vuln_type="sqli", parameter="id", severity="critical"),
            Finding(url=f"{base}/vulnerabilities/fi/?page=../../etc/passwd",
                    vuln_type="lfi", parameter="page", severity="high"),
            Finding(url=f"{base}/vulnerabilities/exec/",
                    vuln_type="cmdi", parameter="ip", severity="critical"),
        ]

        result = evaluate(findings, gt)

        # Every finding corresponds to at least one labeled vuln → perfect precision.
        assert result.matched_finding_count == 3
        assert result.unmatched_finding_count == 0
        assert result.precision == 1.0

        # The low-difficulty required entries for each new class are credited.
        for gt_id in ("dvwa-sqli-low-id", "dvwa-lfi-low-page", "dvwa-cmdi-low-ip"):
            assert gt_id in result.detected_gt_ids, f"{gt_id} not scored as a TP"
            assert gt_id in result.detected_required_ids

    def test_vuln_types_normalise_to_gt_categories(self) -> None:
        # The exact strings the injection scanner emits must land on the
        # canonical categories present in the DVWA ground-truth.
        assert normalize_category("lfi") == "lfi"
        assert normalize_category("rfi") == "rfi"
        assert normalize_category("cmdi") == "cmdi"
        gt_categories = {e.category for e in self._gt().vulnerabilities}
        assert {"sqli", "lfi", "cmdi"} <= gt_categories
