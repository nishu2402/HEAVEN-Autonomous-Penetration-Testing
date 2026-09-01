"""Hermetic tests for the OWASP Benchmark SAST scorer.

The pure-Python scoring math runs everywhere. The end-to-end slice runs HEAVEN's
real Semgrep engine over a small set of HEAVEN-authored Java fixtures (MIT, not
the GPL corpus) and is skipped when semgrep is not installed. It proves the Java
rules distinguish a genuine vulnerability from a safe look-alike — including the
two behaviours that make or break an OWASP Benchmark score: a taint flow that
only reaches the sink through a collection propagator (Case03), and a real
sanitizer that must clear the taint (Case07).

The live, full-corpus benchmark lives in tests/benchmarks/test_owasp_benchmark.py
and is gated behind HEAVEN_RUN_BENCHMARKS=1.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from tests.benchmarks import owasp_benchmark as ob

_FIXTURES = Path(__file__).parent / "benchmarks" / "fixtures" / "owasp_mini"


def _has_semgrep() -> bool:
    from heaven.vulnscan.sast_runner import has_semgrep
    return has_semgrep()


# ═══════════════════════════════════════════════════════════════════════════
# Pure scoring math (no semgrep needed)
# ═══════════════════════════════════════════════════════════════════════════


def test_cwe_map_covers_all_eleven_categories():
    assert len(ob.CWE_TO_CATEGORY) == 11
    assert set(ob.BENCHMARK_CATEGORIES) == {
        "cmdi", "crypto", "hash", "ldapi", "pathtraver", "securecookie",
        "sqli", "trustbound", "weakrand", "xpathi", "xss",
    }


def test_load_expected_parses_mini_csv():
    expected = ob.load_expected(_FIXTURES / "expectedresults-mini.csv")
    assert len(expected) == 12
    assert expected["Case01"].category == "cmdi"
    assert expected["Case01"].is_real is True
    assert expected["Case02"].is_real is False           # the safe look-alike
    assert expected["Case10"].cwe == "328"


def test_score_confusion_matrix_math():
    # Two real + two safe cmdi cases; the tool flags one real (tp) and one safe (fp),
    # missing one real (fn) and correctly clearing one safe (tn).
    expected = {
        "a": ob.ExpectedCase("a", "cmdi", True, "78"),
        "b": ob.ExpectedCase("b", "cmdi", True, "78"),
        "c": ob.ExpectedCase("c", "cmdi", False, "78"),
        "d": ob.ExpectedCase("d", "cmdi", False, "78"),
    }
    flagged = {"a": {"cmdi"}, "c": {"cmdi"}}
    cat = ob.score(expected, flagged)["cmdi"]
    assert (cat.tp, cat.fn, cat.fp, cat.tn) == (1, 1, 1, 1)
    assert cat.tpr == 0.5
    assert cat.fpr == 0.5
    assert cat.youden == 0.0


def test_score_wrong_category_is_not_credited():
    # A finding in the wrong category must not satisfy a real case (OWASP keys on CWE).
    expected = {"a": ob.ExpectedCase("a", "sqli", True, "89")}
    flagged = {"a": {"xss"}}                              # mis-categorised noise
    cat = ob.score(expected, flagged)["sqli"]
    assert (cat.tp, cat.fn) == (0, 1)


def test_flagged_categories_keys_by_file_stem_and_cwe():
    class _F:
        def __init__(self, path, cwe):
            self.file_path, self.cwe = path, cwe
    findings = [
        _F("/x/BenchmarkTest01234.java", "CWE-78"),
        _F("/x/BenchmarkTest01234.java", "89"),
        _F("/x/Other.java", "CWE-330"),
        _F("/x/Nope.java", "CWE-9999"),                   # unknown CWE -> ignored
    ]
    flagged = ob.flagged_categories(findings)
    assert flagged["BenchmarkTest01234"] == {"cmdi", "sqli"}
    assert flagged["Other"] == {"weakrand"}
    assert "Nope" not in flagged


def test_scorecard_pooled_and_render():
    per_cat = {
        "cmdi": ob.CategoryScore("cmdi", tp=2, fn=0, fp=0, tn=1),
        "sqli": ob.CategoryScore("sqli", tp=1, fn=1, fp=1, tn=1),
    }
    card = ob.Scorecard("HEAVEN", "1.2", total_cases=7, per_category=per_cat)
    assert card.tp == 3 and card.fn == 1 and card.fp == 1 and card.tn == 2
    assert card.recall == pytest.approx(3 / 4)
    assert card.fpr == pytest.approx(1 / 3)
    assert card.youden == pytest.approx(3 / 4 - 1 / 3)
    text = card.render()
    assert "YOUDEN" in text and "POOLED" in text and "cmdi" in text


# ═══════════════════════════════════════════════════════════════════════════
# End-to-end over HEAVEN-authored fixtures (real semgrep)
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not _has_semgrep(), reason="semgrep not installed")
def test_java_rules_separate_vuln_from_safe(tmp_path):
    # Semgrep's default ignore skips paths with a `tests`/`fixtures` component, so
    # copy the fixtures to a neutral temp dir before scanning (this also mirrors
    # how the real scorer scans an external checkout).
    testcode = tmp_path / "testcode"
    shutil.copytree(_FIXTURES / "testcode", testcode)
    corpus = ob.BenchmarkCorpus(
        root=tmp_path, testcode_dir=testcode,
        expected_csv=_FIXTURES / "expectedresults-mini.csv",
    )
    card = asyncio.run(ob.run(corpus, timeout_s=120))

    # Every genuine vulnerability is detected, and no safe look-alike is flagged:
    # on this hand-built set the rules are exact.
    assert card.recall == 1.0, card.render()
    assert card.fp == 0, card.render()
    assert card.youden == 1.0, card.render()

    # And specifically: the propagator carried taint through the List (Case03),
    # while the ESAPI encoder cleared it (Case07 stays a true negative).
    expected = ob.load_expected(corpus.expected_csv)
    res = asyncio.run(ob.scan_corpus(testcode, timeout_s=120))
    flagged = ob.flagged_categories(res.findings)
    assert "cmdi" in flagged.get("Case03", set())        # collection propagator
    assert flagged.get("Case07") in (None, set())        # sanitizer clears taint
    assert flagged.get("Case05") in (None, set())        # parameterized query
    # All eleven categories are known to the scorer even if this mini set omits some.
    assert set(card.per_category) >= set(expected[c].category for c in expected)
