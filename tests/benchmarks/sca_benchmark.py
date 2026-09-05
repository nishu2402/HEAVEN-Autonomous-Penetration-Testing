"""HEAVEN — Software Composition Analysis (SCA) benchmark scorer.

This is the SCA analogue of ``owasp_benchmark.py`` (which scores SAST against the
OWASP Benchmark). It audits a small, multi-ecosystem corpus of KNOWN-vulnerable
dependency manifests live against OSV.dev and scores the result against a curated
ground truth (``ground_truth/sca.yaml``):

* **recall** — of the curated must-find CVEs (permanent historical advisories
  whose affected range provably covers each pinned version), how many HEAVEN's
  ``sca_scanner.scan_path`` detects. Because the advisories are immutable, this
  number is stable across runs.
* **precision control** — the ``patched/`` half of the corpus pins the versions
  that fixed each CVE. HEAVEN must report NONE of the must-find CVEs against
  them, proving it honours OSV's fixed ranges (a patched dependency is never
  flagged for a vulnerability it already resolved). A patched pin may still carry
  newer, unrelated advisories — that is correct and deliberately not asserted.

Nothing is installed or executed: the corpus is inert manifest text, and the
audit is a set of read-only OSV lookups. The scorer raises :class:`OSVUnavailable`
when OSV cannot be reached so callers can skip rather than fail offline.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
CORPUS_DIR = _HERE / "labs" / "sca-corpus"
GROUND_TRUTH = _HERE / "ground_truth" / "sca.yaml"
REPORT = _HERE / "reports" / "sca_benchmark.md"

# The corpus manifests are stored on disk with this suffix (e.g.
# ``requirements.txt.fixture``) so GitHub's dependency graph never mistakes these
# intentionally-vulnerable pins for real project dependencies and files Dependabot
# alerts against the repo. The benchmark reads each fixture and parses it under its
# logical manifest name, so the audit is byte-for-byte identical to scanning the
# real file — only the on-disk filename differs.
_FIXTURE_SUFFIX = ".fixture"


class OSVUnavailable(RuntimeError):
    """OSV.dev could not be reached, so the live SCA benchmark cannot run."""


@dataclass
class PackageGT:
    package: str
    ecosystem: str
    vulnerable_version: str
    patched_version: str
    must_find: list[str]


@dataclass
class SCAScore:
    packages: list[PackageGT]
    detected: dict[str, bool]          # CVE -> found in the vulnerable audit
    leaked_on_patched: list[str]       # must-find CVEs wrongly seen on patched
    vulnerable_total_findings: int
    patched_total_findings: int
    per_package: dict[str, dict] = field(default_factory=dict)

    @property
    def must_find_all(self) -> list[str]:
        out: list[str] = []
        for p in self.packages:
            out.extend(p.must_find)
        return out

    @property
    def recall(self) -> float:
        want = self.must_find_all
        if not want:
            return 1.0
        return sum(1 for c in want if self.detected.get(c)) / len(want)

    @property
    def missed(self) -> list[str]:
        return [c for c in self.must_find_all if not self.detected.get(c)]

    @property
    def precision_control_passed(self) -> bool:
        return not self.leaked_on_patched


def load_ground_truth(path: Path = GROUND_TRUTH) -> list[PackageGT]:
    import yaml  # PyYAML is a dev dependency (also used by the other benchmarks)

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out: list[PackageGT] = []
    for entry in data.get("packages", []):
        out.append(PackageGT(
            package=str(entry["package"]),
            ecosystem=str(entry.get("ecosystem", "")),
            vulnerable_version=str(entry.get("vulnerable_version", "")),
            patched_version=str(entry.get("patched_version", "")),
            must_find=[str(c) for c in entry.get("must_find", [])],
        ))
    return out


def _cves_of(findings: list[dict[str, Any]]) -> set[str]:
    """All CVE identifiers across a set of SCA findings (cve_id + OSV aliases)."""
    cves: set[str] = set()
    for f in findings:
        if f.get("cve_id"):
            cves.add(f["cve_id"])
        for a in (f.get("evidence", {}) or {}).get("aliases", []) or []:
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                cves.add(a)
    return cves


async def _audit(path: Path) -> list[dict[str, Any]]:
    from heaven.vulnscan.sca_scanner import scan_manifest_text

    # Manifests live under `<name>.fixture` (see `_FIXTURE_SUFFIX`); read each and
    # parse it under its logical name so the real scanner audits it unchanged.
    fixtures = sorted(path.glob(f"*{_FIXTURE_SUFFIX}"))
    if not fixtures:
        raise OSVUnavailable(
            f"no manifest fixtures (*{_FIXTURE_SUFFIX}) found under {path}")
    findings: list[dict[str, Any]] = []
    for fx in fixtures:
        logical_name = fx.name[: -len(_FIXTURE_SUFFIX)]  # requirements.txt / package.json
        text = fx.read_text(encoding="utf-8", errors="ignore")
        findings.extend(await scan_manifest_text(logical_name, text))
    return findings


def run(corpus_dir: Path = CORPUS_DIR) -> SCAScore:
    """Run the live SCA benchmark and return a scored result."""
    packages = load_ground_truth()

    async def _both() -> tuple[list[dict], list[dict]]:
        vuln = await _audit(corpus_dir / "vulnerable")
        patched = await _audit(corpus_dir / "patched")
        return vuln, patched

    try:
        vuln_findings, patched_findings = asyncio.run(_both())
    except OSVUnavailable:
        raise
    except Exception as e:  # network / DNS / timeout → treat as unavailable
        raise OSVUnavailable(f"OSV audit failed: {type(e).__name__}: {e}") from e

    if not vuln_findings:
        raise OSVUnavailable(
            "OSV returned zero findings for a known-vulnerable corpus — "
            "almost certainly a connectivity problem, not a real result.")

    vuln_cves = _cves_of(vuln_findings)
    patched_cves = _cves_of(patched_findings)

    detected = {c: (c in vuln_cves) for c in
                (cv for p in packages for cv in p.must_find)}
    leaked = [c for p in packages for c in p.must_find if c in patched_cves]

    per_package: dict[str, dict] = {}
    for p in packages:
        per_package[p.package] = {
            "ecosystem": p.ecosystem,
            "vulnerable_version": p.vulnerable_version,
            "patched_version": p.patched_version,
            "must_find": p.must_find,
            "found": [c for c in p.must_find if c in vuln_cves],
            "missed": [c for c in p.must_find if c not in vuln_cves],
        }

    return SCAScore(
        packages=packages,
        detected=detected,
        leaked_on_patched=leaked,
        vulnerable_total_findings=len(vuln_findings),
        patched_total_findings=len(patched_findings),
        per_package=per_package,
    )


def render_report(score: SCAScore) -> str:
    lines = [
        "# Benchmark: HEAVEN SCA vs. a multi-ecosystem vulnerable-dependency corpus",
        "",
        "Live audit of `tests/benchmarks/labs/sca-corpus/` against **OSV.dev**. "
        "Recall is measured over a curated set of permanent CVE advisories; the "
        "`patched/` half is the precision control (the same packages at their "
        "fixed versions must not be flagged for the CVE they resolved).",
        "",
        "## Headline metrics",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| Recall (curated must-find CVEs) | {score.recall * 100:.1f}% "
        f"({len(score.must_find_all) - len(score.missed)} / "
        f"{len(score.must_find_all)}) |",
        f"| Precision control (no fixed CVE on patched pins) | "
        f"{'PASS' if score.precision_control_passed else 'FAIL'} |",
        f"| Advisories on the vulnerable corpus (all true positives) | "
        f"{score.vulnerable_total_findings} |",
        f"| Advisories on the patched corpus | {score.patched_total_findings} |",
        "",
        "## Per-package recall",
        "",
        "| Package | Ecosystem | Vulnerable | Patched | Must-find | Detected |",
        "|---------|-----------|-----------|---------|-----------|---------:|",
    ]
    for p in score.packages:
        d = score.per_package[p.package]
        lines.append(
            f"| {p.package} | {p.ecosystem} | {p.vulnerable_version} | "
            f"{p.patched_version} | {', '.join(p.must_find)} | "
            f"{len(d['found'])}/{len(p.must_find)} |")
    if score.missed:
        lines += ["", "## Missed must-find CVEs", "",
                  ", ".join(score.missed)]
    if score.leaked_on_patched:
        lines += ["", "## Precision-control FAILURES (fixed CVE seen on patched pin)",
                  "", ", ".join(score.leaked_on_patched)]
    lines.append("")
    return "\n".join(lines)


def write_report(score: SCAScore, path: Path = REPORT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(score), encoding="utf-8")
    return path


if __name__ == "__main__":  # pragma: no cover - manual/CLI use
    s = run()
    print(render_report(s))
    write_report(s)
