"""
HEAVEN — Self-Test / Accuracy Measurement Mode.

Runs HEAVEN against a known-vulnerable target (DVWA, Juice Shop, vulnerable
web apps published as Docker images) and computes detection rate / false-
positive rate. This is how you *measure* a scanner's accuracy instead of
claiming a number.

This module does NOT require the target to be running — it provides three
modes:

    1. report           : prints calibration data from a previous run
    2. measure-against  : runs against a user-supplied target with a known
                          ground truth and outputs precision/recall
    3. list-fixtures    : shows known-good test images you can spin up

Usage from CLI:
    python -m heaven.testing.selftest measure-against \\
        --target http://localhost:3000 \\
        --ground-truth tests/fixtures/juice_shop_truth.json \\
        --i-have-authorization

Authorization rules still apply.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ── Known test images (these run locally; you spin them up yourself) ──
KNOWN_FIXTURES = {
    "juice-shop": {
        "image": "bkimminich/juice-shop:latest",
        "default_port": 3000,
        "url": "http://localhost:3000",
        "ground_truth_file": "tests/fixtures/juice_shop_truth.json",
        "categories": ["sqli", "xss", "broken_auth", "sensitive_data", "xxe",
                       "broken_access_control", "ssrf", "deserialization"],
        "vendor_url": "https://owasp.org/www-project-juice-shop/",
        "license": "MIT",
        "notes": "OWASP Juice Shop — primary integration test target",
    },
    "dvwa": {
        "image": "vulnerables/web-dvwa:latest",
        "default_port": 80,
        "url": "http://localhost",
        "ground_truth_file": "tests/fixtures/dvwa_truth.json",
        "categories": ["sqli", "xss", "csrf", "command_injection", "file_upload"],
        "vendor_url": "https://github.com/digininja/DVWA",
        "license": "GPL-3.0",
        "notes": "DVWA — classic vulnerable web app",
    },
    "vulnerable-rest-api": {
        "image": "erev0s/vampi:latest",
        "default_port": 5000,
        "url": "http://localhost:5000",
        "ground_truth_file": "tests/fixtures/vampi_truth.json",
        "categories": ["broken_auth", "excessive_data", "rate_limit", "bola"],
        "vendor_url": "https://github.com/erev0s/VAmPI",
        "license": "MIT",
        "notes": "VAmPI — vulnerable API for testing OWASP API Top 10",
    },
    "webgoat": {
        "image": "webgoat/webgoat:latest",
        "default_port": 8080,
        "url": "http://localhost:8080/WebGoat",
        "ground_truth_file": "tests/fixtures/webgoat_truth.json",
        "categories": ["sqli", "xss", "auth_bypass", "csrf", "deserialization"],
        "vendor_url": "https://owasp.org/www-project-webgoat/",
        "license": "GPL-2.0",
        "notes": "WebGoat — OWASP guided vulnerable training app",
    },
}


@dataclass
class TestVerdict:
    """Verdict for a single ground-truth check vs HEAVEN's findings."""
    category: str
    expected_present: bool
    detected: bool
    confidence: float = 0.0
    notes: str = ""


@dataclass
class AccuracyReport:
    """Aggregate accuracy report."""
    target: str
    fixture: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    verdicts: list[TestVerdict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "fixture": self.fixture,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1_score, 3),
            "verdicts": [
                {
                    "category": v.category,
                    "expected": v.expected_present,
                    "detected": v.detected,
                    "confidence": v.confidence,
                    "notes": v.notes,
                }
                for v in self.verdicts
            ],
        }

    def print_summary(self) -> None:
        """Print a human-readable summary."""
        print("\n=== HEAVEN Accuracy Report ===")
        print(f"Target:    {self.target}")
        print(f"Fixture:   {self.fixture}")
        print("\nConfusion matrix:")
        print(f"  True Positives:  {self.true_positives}")
        print(f"  False Positives: {self.false_positives}")
        print(f"  True Negatives:  {self.true_negatives}")
        print(f"  False Negatives: {self.false_negatives}")
        print(f"\nPrecision: {self.precision:.1%}  (lower bound on accuracy)")
        print(f"Recall:    {self.recall:.1%}  (coverage of known issues)")
        print(f"F1 Score:  {self.f1_score:.3f}")
        print("\nNote: numbers are calibrated to this fixture only. They do")
        print("not generalize to all targets. A real engagement requires")
        print("manual validation regardless of automated scores.\n")


def evaluate_against_truth(scan_findings: list[dict], truth: dict) -> AccuracyReport:
    """
    Compare HEAVEN scan findings to a ground-truth file.

    Ground-truth format:
        {
          "target": "http://localhost:3000",
          "fixture": "juice-shop",
          "expected_findings": [
            {"category": "sqli", "endpoint": "/rest/user/login", "present": true},
            {"category": "xss", "endpoint": "/#/search", "present": true},
            {"category": "ssrf", "present": false},
            ...
          ]
        }
    """
    report = AccuracyReport(
        target=truth.get("target", "unknown"),
        fixture=truth.get("fixture", "unknown"),
    )

    # Build a category → detected map from scan findings
    detected_categories: dict[str, float] = {}
    for f in scan_findings:
        cat = (f.get("vuln_type") or f.get("type")
               or f.get("category") or "").lower()
        if not cat:
            continue
        # Keep the highest-confidence detection per category
        detected_categories[cat] = max(
            detected_categories.get(cat, 0.0),
            float(f.get("confidence", 0.0)),
        )

    # Compare against expected
    seen_categories = set()
    for expected in truth.get("expected_findings", []):
        cat = expected["category"].lower()
        seen_categories.add(cat)
        was_detected = cat in detected_categories
        confidence = detected_categories.get(cat, 0.0)
        notes = ""

        if expected["present"] and was_detected:
            report.true_positives += 1
            notes = "correctly detected"
        elif expected["present"] and not was_detected:
            report.false_negatives += 1
            notes = "missed — vulnerability present but not flagged"
        elif not expected["present"] and was_detected:
            report.false_positives += 1
            notes = "false alarm — flagged but vuln not present"
        else:
            report.true_negatives += 1
            notes = "correctly ignored"

        report.verdicts.append(TestVerdict(
            category=cat,
            expected_present=expected["present"],
            detected=was_detected,
            confidence=confidence,
            notes=notes,
        ))

    # Categories detected but not in ground-truth = either missing GT or FP
    for cat, conf in detected_categories.items():
        if cat not in seen_categories:
            report.false_positives += 1
            report.verdicts.append(TestVerdict(
                category=cat,
                expected_present=False,
                detected=True,
                confidence=conf,
                notes="detected but not in ground-truth — likely false positive",
            ))

    return report


def list_fixtures() -> None:
    """Print known test fixtures."""
    print("\nKnown vulnerable test fixtures:\n")
    for name, info in KNOWN_FIXTURES.items():
        print(f"  {name:25} {info['image']}")
        print(f"    Categories: {', '.join(info['categories'])}")
        print(f"    Vendor:     {info['vendor_url']}")
        print(f"    Spin up:    docker run --rm -p {info['default_port']}:{info['default_port']} {info['image']}")
        print()


def cli_main() -> int:
    """Minimal CLI for self-test. Use `python -m heaven.testing.selftest`."""
    import argparse
    parser = argparse.ArgumentParser(description="HEAVEN self-test / accuracy measurement")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list-fixtures", help="Print known vulnerable test images")

    measure = sub.add_parser("measure-against", help="Compare scan output to a ground-truth file")
    measure.add_argument("--findings-file", required=True,
                          help="Path to a JSON file containing HEAVEN scan output (the report_*.json from a scan)")
    measure.add_argument("--ground-truth", required=True,
                          help="Path to a ground-truth JSON file")
    measure.add_argument("--output", help="Write report to JSON file instead of just printing")

    args = parser.parse_args()

    if args.cmd == "list-fixtures":
        list_fixtures()
        return 0

    if args.cmd == "measure-against":
        findings_path = Path(args.findings_file)
        truth_path = Path(args.ground_truth)
        if not findings_path.exists():
            print(f"Findings file not found: {findings_path}", file=sys.stderr)
            return 2
        if not truth_path.exists():
            print(f"Ground-truth file not found: {truth_path}", file=sys.stderr)
            return 2

        scan = json.loads(findings_path.read_text())
        truth = json.loads(truth_path.read_text())
        findings = scan.get("vulnerabilities", []) + scan.get("findings", [])
        report = evaluate_against_truth(findings, truth)
        report.print_summary()

        if args.output:
            Path(args.output).write_text(json.dumps(report.to_dict(), indent=2))
            print(f"Report written to: {args.output}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(cli_main())
