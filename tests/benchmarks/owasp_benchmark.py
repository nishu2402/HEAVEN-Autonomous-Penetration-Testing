"""OWASP Benchmark (Java) SAST scorer for HEAVEN.

This runs HEAVEN's own Semgrep-based SAST engine — the *shipped* builtin rule
pack in ``heaven/vulnscan/sast_rules/`` (which now includes a real Java pack) —
against the OWASP Benchmark v1.2 Java corpus, and computes the standard OWASP
Benchmark scorecard:

  * per-category and pooled TP / FN / FP / TN,
  * the true-positive rate (recall) and false-positive rate,
  * the Youden index ``J = TPR - FPR`` — the Benchmark's headline score, which
    is 0.0 for a tool that flags everything and 1.0 for a perfect tool.

The corpus is deliberately **not vendored**. The OWASP Benchmark is licensed
GPLv2 and HEAVEN is MIT, so copying its 2 740 Java files into this tree would be
a licence conflict. Instead the operator (or CI) supplies a checkout and the
ground truth (``expectedresults-1.2.csv``) is read straight from it — never
copied here. See :func:`locate_corpus` and :func:`clone_pinned`.

Nothing in this module is Benchmark-aware in the detection path: HEAVEN's Java
rules are generic security rules tagged with the same CWE ids the Benchmark
uses, and the mapping below is purely the standard CWE ↔ category correspondence
the OWASP scorecard itself relies on.
"""

from __future__ import annotations

import asyncio
import csv
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── the eleven OWASP Benchmark categories, by their CWE (the scorecard key) ──
CWE_TO_CATEGORY: dict[str, str] = {
    "78": "cmdi",
    "89": "sqli",
    "22": "pathtraver",
    "90": "ldapi",
    "643": "xpathi",
    "79": "xss",
    "501": "trustbound",
    "330": "weakrand",
    "328": "hash",
    "327": "crypto",
    "614": "securecookie",
}
BENCHMARK_CATEGORIES = sorted(set(CWE_TO_CATEGORY.values()))

# The corpus layout inside a BenchmarkJava checkout.
_TESTCODE_REL = Path("src/main/java/org/owasp/benchmark/testcode")
_EXPECTED_GLOB = "expectedresults-*.csv"

# A reproducible pin. The v1.2 corpus has been frozen since 2016; this is the
# commit the scorer was validated against. clone_pinned() checks this out when
# it can, and otherwise falls back to the default-branch HEAD (still v1.2).
PINNED_REPO = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
PINNED_COMMIT = "51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661"
EXPECTED_VERSION = "1.2"


# ═══════════════════════════════════════════════════════════════════════════
# CORPUS LOCATION
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class BenchmarkCorpus:
    """A located OWASP Benchmark checkout ready to score."""
    root: Path
    testcode_dir: Path
    expected_csv: Path

    @property
    def version(self) -> str:
        """The Benchmark version stamped in the ground-truth CSV header."""
        try:
            first = self.expected_csv.read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            return ""
        m = re.search(r"Benchmark version:\s*([0-9.]+)", first)
        return m.group(1) if m else ""


def _validate_root(root: Path) -> Optional[BenchmarkCorpus]:
    """Return a BenchmarkCorpus if ``root`` is a real Benchmark checkout."""
    if not root or not root.is_dir():
        return None
    testcode = root / _TESTCODE_REL
    csvs = sorted(root.glob(_EXPECTED_GLOB))
    if not testcode.is_dir() or not csvs:
        return None
    return BenchmarkCorpus(root=root, testcode_dir=testcode, expected_csv=csvs[0])


def locate_corpus(explicit: Optional[Path] = None) -> Optional[BenchmarkCorpus]:
    """Find a Benchmark checkout without cloning.

    Order: an ``explicit`` path argument, then the ``HEAVEN_OWASP_BENCHMARK_DIR``
    environment variable. Returns None if neither points at a valid checkout, so
    the caller can decide to clone or skip.
    """
    import os

    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("HEAVEN_OWASP_BENCHMARK_DIR", "").strip()
    if env:
        candidates.append(Path(env))
    for c in candidates:
        corpus = _validate_root(c.expanduser().resolve())
        if corpus:
            return corpus
    return None


def clone_pinned(dest: Path) -> BenchmarkCorpus:
    """Shallow-clone the pinned Benchmark corpus into ``dest`` and return it.

    Pins to :data:`PINNED_COMMIT` when the host git/GitHub can fetch a bare SHA;
    otherwise it keeps the shallow default-branch HEAD (still the frozen v1.2
    corpus). Raises if git is unavailable or the clone does not yield a valid
    checkout.
    """
    if shutil.which("git") is None:
        raise RuntimeError("git not on PATH — cannot fetch the OWASP Benchmark corpus")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        ["git", "clone", "--depth", "1", PINNED_REPO, str(dest)],
        check=True, capture_output=True, text=True, timeout=600,
    )
    # Best-effort pin to the exact validated commit; fall back to HEAD.
    try:
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", PINNED_COMMIT],
            check=True, capture_output=True, text=True, timeout=300,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--quiet", PINNED_COMMIT],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass  # HEAD of the default branch is the same frozen v1.2 corpus.

    corpus = _validate_root(dest.resolve())
    if corpus is None:
        raise RuntimeError(f"clone did not yield a valid Benchmark checkout at {dest}")
    return corpus


# ═══════════════════════════════════════════════════════════════════════════
# GROUND TRUTH
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ExpectedCase:
    name: str
    category: str
    is_real: bool          # True == a genuine vulnerability; False == a safe lookalike
    cwe: str


def load_expected(csv_path: Path) -> dict[str, ExpectedCase]:
    """Parse ``expectedresults-1.2.csv`` into {testcase name -> ExpectedCase}."""
    out: dict[str, ExpectedCase] = {}
    with Path(csv_path).open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            # Skip the comment header (starts with '#'), blanks, and short rows.
            if not row or row[0].lstrip().startswith("#") or len(row) < 3:
                continue
            name, category, real, cwe = row[0].strip(), row[1], row[2], (row[3] if len(row) > 3 else "")
            if not name:
                continue
            out[name] = ExpectedCase(
                name=name,
                category=category.strip(),
                is_real=real.strip().lower() == "true",
                cwe=cwe.strip(),
            )
    return out


# ═══════════════════════════════════════════════════════════════════════════
# SCAN  (HEAVEN's real SAST engine)
# ═══════════════════════════════════════════════════════════════════════════


async def scan_corpus(testcode_dir: Path, timeout_s: int = 1800):
    """Run HEAVEN's builtin SAST engine over the corpus, return the SastRunResult."""
    from heaven.vulnscan.sast_runner import run_sast

    return await run_sast(str(testcode_dir), use_builtin_rules=True, timeout_s=timeout_s)


def flagged_categories(findings) -> dict[str, set[str]]:
    """Map each test case to the set of categories HEAVEN flagged on it.

    A finding is attributed to a test case by its source file's stem (which is
    the test-case name: ``BenchmarkTest00001.java`` -> ``BenchmarkTest00001``,
    the exact key used in ``expectedresults.csv``), and to a category by its CWE
    (the OWASP scorecard's matching key).
    """
    flagged: dict[str, set[str]] = {}
    for f in findings:
        path = f.file_path or ""
        if not path:
            continue
        name = Path(path).stem
        cwe = str(getattr(f, "cwe", "") or "").upper().replace("CWE-", "").strip()
        category = CWE_TO_CATEGORY.get(cwe)
        if not category:
            continue
        flagged.setdefault(name, set()).add(category)
    return flagged


# ═══════════════════════════════════════════════════════════════════════════
# SCORE
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class CategoryScore:
    category: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fn + self.fp + self.tn

    @property
    def tpr(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def youden(self) -> float:
        return self.tpr - self.fpr


@dataclass
class Scorecard:
    tool: str
    corpus_version: str
    total_cases: int
    per_category: dict[str, CategoryScore] = field(default_factory=dict)
    findings_count: int = 0
    files_scanned: int = 0
    duration_s: float = 0.0

    # ── pooled counts ────────────────────────────────────────────────────
    @property
    def tp(self) -> int:
        return sum(c.tp for c in self.per_category.values())

    @property
    def fn(self) -> int:
        return sum(c.fn for c in self.per_category.values())

    @property
    def fp(self) -> int:
        return sum(c.fp for c in self.per_category.values())

    @property
    def tn(self) -> int:
        return sum(c.tn for c in self.per_category.values())

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def youden(self) -> float:
        """Pooled Youden index — the Benchmark's headline score."""
        return self.recall - self.fpr

    @property
    def mean_category_youden(self) -> float:
        if not self.per_category:
            return 0.0
        return sum(c.youden for c in self.per_category.values()) / len(self.per_category)

    # ── rendering ────────────────────────────────────────────────────────
    def render(self) -> str:
        lines = [
            f"OWASP Benchmark v{self.corpus_version} — {self.tool}",
            f"  {self.total_cases} test cases, {self.findings_count} findings, "
            f"{self.files_scanned} files scanned in {self.duration_s:.1f}s",
            "",
            f"  {'CATEGORY':<13}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}"
            f"{'TPR':>8}{'FPR':>8}{'YOUDEN':>8}",
        ]
        for cat in sorted(self.per_category):
            c = self.per_category[cat]
            lines.append(
                f"  {cat:<13}{c.tp:>5}{c.fn:>5}{c.fp:>5}{c.tn:>5}"
                f"{c.tpr:>8.3f}{c.fpr:>8.3f}{c.youden:>8.3f}"
            )
        lines += [
            f"  {'-' * 58}",
            f"  {'POOLED':<13}{self.tp:>5}{self.fn:>5}{self.fp:>5}{self.tn:>5}"
            f"{self.recall:>8.3f}{self.fpr:>8.3f}{self.youden:>8.3f}",
            "",
            f"  Youden index (TPR - FPR): {self.youden:.3f}   "
            f"recall {self.recall:.3f}   precision {self.precision:.3f}",
            f"  Mean per-category Youden: {self.mean_category_youden:.3f}",
        ]
        return "\n".join(lines)


def score(expected: dict[str, ExpectedCase],
          flagged: dict[str, set[str]]) -> dict[str, CategoryScore]:
    """Compute per-category TP/FN/FP/TN under the OWASP Benchmark scoring model.

    For every test case with category C:
      * real vuln + HEAVEN flagged C  -> TP
      * real vuln + not flagged       -> FN
      * safe case + HEAVEN flagged C  -> FP
      * safe case + not flagged       -> TN
    A finding in the *wrong* category never satisfies a case (matches the OWASP
    scorecard, which keys on CWE), so mis-categorised noise is not free credit.
    """
    scores: dict[str, CategoryScore] = {
        cat: CategoryScore(category=cat) for cat in BENCHMARK_CATEGORIES
    }
    for name, case in expected.items():
        bucket = scores.setdefault(case.category, CategoryScore(category=case.category))
        hit = case.category in flagged.get(name, set())
        if case.is_real and hit:
            bucket.tp += 1
        elif case.is_real and not hit:
            bucket.fn += 1
        elif not case.is_real and hit:
            bucket.fp += 1
        else:
            bucket.tn += 1
    return scores


async def run(corpus: BenchmarkCorpus, timeout_s: int = 1800) -> Scorecard:
    """Scan the corpus with HEAVEN's SAST engine and return a full Scorecard."""
    expected = load_expected(corpus.expected_csv)
    result = await scan_corpus(corpus.testcode_dir, timeout_s=timeout_s)
    if not result.success:
        raise RuntimeError(f"HEAVEN SAST run failed: {result.error}")
    flagged = flagged_categories(result.findings)
    per_category = score(expected, flagged)
    return Scorecard(
        tool="HEAVEN SAST (builtin Java rules)",
        corpus_version=corpus.version or EXPECTED_VERSION,
        total_cases=len(expected),
        per_category=per_category,
        findings_count=len(result.findings),
        files_scanned=result.files_scanned,
        duration_s=result.duration_s,
    )


def _main() -> int:
    """Standalone runner: locate or clone the corpus, score, print the card."""
    import argparse
    import tempfile

    ap = argparse.ArgumentParser(description="Score HEAVEN SAST against the OWASP Benchmark")
    ap.add_argument("--dir", type=Path, default=None,
                    help="Path to a BenchmarkJava checkout (else $HEAVEN_OWASP_BENCHMARK_DIR, "
                         "else a shallow clone of the pinned corpus).")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    corpus = locate_corpus(args.dir)
    tmp: Optional[Path] = None
    if corpus is None:
        tmp = Path(tempfile.mkdtemp(prefix="heaven_owasp_bench_"))
        print(f"No corpus found; shallow-cloning the pinned corpus into {tmp} ...")
        corpus = clone_pinned(tmp)
    try:
        card = asyncio.run(run(corpus, timeout_s=args.timeout))
        print(card.render())
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
