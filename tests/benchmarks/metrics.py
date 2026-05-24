"""
HEAVEN benchmark — metrics layer
Scanner-agnostic: matches findings against ground truth and computes
precision / recall / F1, both overall and per category.

The two data types live here because the metrics module is the canonical
contract — every reporter consumes BenchmarkResult, every adapter
(HEAVEN, Burp, ZAP, ...) produces a list[Finding].
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ═══════════════════════════════════════════
# CATEGORY NORMALISATION
# Every scanner names its findings differently. We map raw vuln_type
# strings to a small set of canonical categories so HEAVEN's
# "sqli_boolean" and Burp's "SQL injection" both land in "sqli".
# ═══════════════════════════════════════════

CANONICAL_CATEGORIES = {
    "sqli", "xss", "cmdi", "lfi", "rfi", "ssrf", "ssti", "xxe",
    "csrf", "open_redirect", "weak_auth", "file_upload", "idor",
    "info_disclosure", "auth_bypass", "deserialization",
    "broken_access_control", "security_misconfig",
}

_TYPE_TO_CATEGORY: dict[str, str] = {
    # SQLi family
    "sqli": "sqli", "sql_injection": "sqli", "sqli_blind": "sqli",
    "sqli_error": "sqli", "sqli_union": "sqli", "sqli_boolean": "sqli",
    "sqli_time": "sqli", "blind_sqli": "sqli", "sql injection": "sqli",
    "boolean-based blind sql injection": "sqli",
    "time-based blind sql injection": "sqli",
    # XSS family
    "xss": "xss", "xss_reflected": "xss", "xss_stored": "xss",
    "xss_dom": "xss", "reflected_xss": "xss", "stored_xss": "xss",
    "cross-site scripting": "xss", "cross-site scripting (reflected)": "xss",
    "cross-site scripting (stored)": "xss",
    # Command injection / RCE
    "cmdi": "cmdi", "command_injection": "cmdi", "rce": "cmdi",
    "os_command_injection": "cmdi", "remote_code_execution": "cmdi",
    "os command injection": "cmdi",
    # Path traversal / LFI
    "lfi": "lfi", "local_file_inclusion": "lfi", "path_traversal": "lfi",
    "directory_traversal": "lfi", "file path traversal": "lfi",
    "path traversal": "lfi",
    # Remote file inclusion
    "rfi": "rfi", "remote_file_inclusion": "rfi",
    # SSRF
    "ssrf": "ssrf", "server_side_request_forgery": "ssrf",
    "server-side request forgery": "ssrf",
    # SSTI
    "ssti": "ssti", "server_side_template_injection": "ssti",
    "server-side template injection": "ssti",
    # XXE
    "xxe": "xxe", "xml_external_entity": "xxe",
    "xml external entity injection": "xxe",
    # CSRF
    "csrf": "csrf", "cross_site_request_forgery": "csrf",
    "cross-site request forgery": "csrf",
    # Open redirect
    "open_redirect": "open_redirect", "unvalidated_redirect": "open_redirect",
    "open redirection": "open_redirect", "external service interaction (http)": "open_redirect",
    # Authentication weaknesses
    "weak_auth": "weak_auth", "weak_credentials": "weak_auth",
    "default_credentials": "weak_auth", "no_rate_limit": "weak_auth",
    "brute_force": "weak_auth",
    # File upload
    "file_upload": "file_upload", "unrestricted_file_upload": "file_upload",
    # IDOR
    "idor": "idor", "insecure_direct_object_reference": "idor",
    # Misc
    "info_disclosure": "info_disclosure", "information_disclosure": "info_disclosure",
    "auth_bypass": "auth_bypass", "authentication_bypass": "auth_bypass",
    "deserialization": "deserialization", "insecure_deserialization": "deserialization",
    "broken_access_control": "broken_access_control",
    "security_misconfig": "security_misconfig",
}


def normalize_category(vuln_type: str) -> str:
    """Map a raw scanner vuln_type string to a canonical category."""
    if not vuln_type:
        return ""
    key = vuln_type.strip().lower()
    if key in _TYPE_TO_CATEGORY:
        return _TYPE_TO_CATEGORY[key]
    # Best-effort: split on underscores and try the first token
    head = key.split("_")[0]
    return _TYPE_TO_CATEGORY.get(head, key)


# ═══════════════════════════════════════════
# FINDING / GROUND-TRUTH TYPES
# ═══════════════════════════════════════════


@dataclass
class Finding:
    """One finding produced by a scanner. Tool-agnostic shape."""
    url: str
    vuln_type: str
    parameter: str = ""
    confidence: float = 0.0
    severity: str = ""

    @property
    def category(self) -> str:
        return normalize_category(self.vuln_type)

    @classmethod
    def from_heaven(cls, d: dict[str, Any]) -> "Finding":
        """Adapt a HEAVEN finding dict (engagement DB row or summary entry)."""
        evidence = d.get("evidence") or {}
        if not isinstance(evidence, dict):
            try:
                evidence = json.loads(evidence) if isinstance(evidence, str) else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                evidence = {}
        return cls(
            url=d.get("target", "") or d.get("url", ""),
            vuln_type=d.get("vuln_type", "") or d.get("type", ""),
            parameter=evidence.get("parameter", "") or evidence.get("param", ""),
            confidence=float(d.get("confidence", 0) or 0),
            severity=d.get("severity", ""),
        )


@dataclass
class GroundTruthEntry:
    """A single labeled vulnerability in a benchmark target."""
    id: str
    endpoint: str
    method: str
    parameter: Optional[str]
    category: str
    subtypes_ok: list[str]
    owasp: str
    cwe: str
    severity: str
    difficulty: str
    detection_required: bool
    notes: str = ""


@dataclass
class GroundTruth:
    """A full ground-truth file describing one benchmark target."""
    target_app: str
    version: str
    base_url: str
    vulnerabilities: list[GroundTruthEntry]
    docker_image: str = ""
    auth: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "GroundTruth":
        try:
            import yaml  # PyYAML — added to dev deps; not required at runtime
        except ImportError as e:
            raise RuntimeError(
                "PyYAML required to load benchmark ground truth. Install: pip install pyyaml"
            ) from e
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = [
            GroundTruthEntry(
                id=v["id"],
                endpoint=v["endpoint"],
                method=v.get("method", "GET").upper(),
                parameter=v.get("parameter"),
                category=v["category"],
                subtypes_ok=list(v.get("subtypes_ok") or []),
                owasp=v.get("owasp", ""),
                cwe=v.get("cwe", ""),
                severity=v.get("severity", "medium"),
                difficulty=v.get("difficulty", "low"),
                detection_required=bool(v.get("detection_required", True)),
                notes=v.get("notes", ""),
            )
            for v in data.get("vulnerabilities") or []
        ]
        for e in entries:
            if e.category not in CANONICAL_CATEGORIES:
                raise ValueError(
                    f"Ground-truth entry '{e.id}' has unknown category "
                    f"'{e.category}'. Add it to CANONICAL_CATEGORIES in "
                    f"tests/benchmarks/metrics.py or fix the YAML."
                )
        return cls(
            target_app=data["target_app"],
            version=str(data.get("version", "")),
            base_url=data["base_url"],
            vulnerabilities=entries,
            docker_image=data.get("docker_image", ""),
            auth=data.get("auth") or {},
        )

    @property
    def required_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.detection_required)


# ═══════════════════════════════════════════
# MATCHER
# ═══════════════════════════════════════════


def matches(finding: Finding, gt: GroundTruthEntry) -> bool:
    """True if `finding` plausibly corresponds to ground-truth entry `gt`.

    Rules (all must hold):
      1. The finding URL contains the GT endpoint path.
      2. The finding's canonical category equals GT's category.
      3. If GT specifies a parameter AND the finding reports one, they match.
         (We tolerate missing parameter info on the finding side because not
         every scanner attributes findings to a specific input.)
    """
    if not gt.endpoint or gt.endpoint not in (finding.url or ""):
        return False
    if finding.category != gt.category:
        return False
    if gt.parameter and finding.parameter:
        if finding.parameter.lower() != gt.parameter.lower():
            return False
    return True


# ═══════════════════════════════════════════
# RESULT TYPE
# ═══════════════════════════════════════════


@dataclass
class BenchmarkResult:
    """Outcome of one benchmark run."""
    target_app: str
    total_gt: int
    total_required: int
    detected_gt_ids: set[str] = field(default_factory=set)
    detected_required_ids: set[str] = field(default_factory=set)
    matched_finding_count: int = 0
    unmatched_finding_count: int = 0
    # Per-category counters: cat → {tp_gt, fn_gt, fp_findings, total_findings}
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    unmatched_findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0

    # ── derived metrics ──────────────────────────────────────────────────

    @property
    def detected_count(self) -> int:
        return len(self.detected_gt_ids)

    @property
    def missed_required_count(self) -> int:
        # required_count - detected_required_count
        return self.total_required - len(self.detected_required_ids)

    @property
    def precision(self) -> float:
        """TP / (TP + FP) — fraction of findings that were real."""
        tp = self.matched_finding_count
        fp = self.unmatched_finding_count
        denom = tp + fp
        return tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN) — fraction of REQUIRED GT entries we detected.

        We compute recall against detection_required entries only, so
        opportunistic findings (e.g., stored XSS, file upload) don't drag
        the headline number down for scanners that don't probe for them.
        """
        if self.total_required == 0:
            return 0.0
        return len(self.detected_required_ids) / self.total_required

    @property
    def recall_overall(self) -> float:
        """Recall across ALL GT entries (including nice-to-haves)."""
        if self.total_gt == 0:
            return 0.0
        return self.detected_count / self.total_gt

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)


# ═══════════════════════════════════════════
# EVALUATE
# ═══════════════════════════════════════════


def evaluate(findings: list[Finding], gt: GroundTruth,
             duration_seconds: float = 0.0) -> BenchmarkResult:
    """Run all findings against all GT entries, return a BenchmarkResult."""
    detected_gt_ids: set[str] = set()
    detected_required_ids: set[str] = set()
    matched_count = 0
    unmatched: list[Finding] = []
    per_cat: dict[str, dict[str, int]] = {}

    # Findings → GT matching
    for f in findings:
        matched_any = False
        for entry in gt.vulnerabilities:
            if matches(f, entry):
                detected_gt_ids.add(entry.id)
                if entry.detection_required:
                    detected_required_ids.add(entry.id)
                matched_any = True
                # Don't break — one finding may correspond to multiple GT
                # entries (e.g., same endpoint at different difficulty levels)
        if matched_any:
            matched_count += 1
        else:
            unmatched.append(f)

        cat = f.category
        cat_bucket = per_cat.setdefault(
            cat, {"findings": 0, "matched": 0, "unmatched": 0}
        )
        cat_bucket["findings"] += 1
        if matched_any:
            cat_bucket["matched"] += 1
        else:
            cat_bucket["unmatched"] += 1

    # Attribute missed GT entries to their category for the FN side
    for entry in gt.vulnerabilities:
        cat_bucket = per_cat.setdefault(
            entry.category,
            {"findings": 0, "matched": 0, "unmatched": 0},
        )
        cat_bucket.setdefault("gt_total", 0)
        cat_bucket.setdefault("gt_detected", 0)
        cat_bucket["gt_total"] += 1
        if entry.id in detected_gt_ids:
            cat_bucket["gt_detected"] += 1

    return BenchmarkResult(
        target_app=gt.target_app,
        total_gt=len(gt.vulnerabilities),
        total_required=gt.required_count,
        detected_gt_ids=detected_gt_ids,
        detected_required_ids=detected_required_ids,
        matched_finding_count=matched_count,
        unmatched_finding_count=len(unmatched),
        per_category=per_cat,
        unmatched_findings=unmatched,
        duration_seconds=duration_seconds,
    )


# ═══════════════════════════════════════════
# MULTI-RUN AGGREGATION
# Publication requires "X% ± Y%" — single-run numbers are unreliable
# for tools that have randomness (multi-armed bandit explore step,
# timing-based detection noise).
# ═══════════════════════════════════════════


@dataclass
class AggregatedResult:
    target_app: str
    runs: int
    mean_precision: float
    std_precision: float
    mean_recall: float
    std_recall: float
    mean_f1: float
    std_f1: float
    mean_duration_s: float
    std_duration_s: float
    # Per-category recall mean (the most useful publication number)
    per_category_recall: dict[str, float]
    # The min/max number of required GT entries missed across runs
    missed_required_min: int
    missed_required_max: int


def _stdev(xs: list[float]) -> float:
    if len(xs) < 2:
        return 0.0
    return statistics.stdev(xs)


def aggregate(runs: list[BenchmarkResult]) -> AggregatedResult:
    """Combine N runs into mean ± stddev for publication."""
    if not runs:
        raise ValueError("aggregate() requires at least one run")
    target = runs[0].target_app

    precisions = [r.precision for r in runs]
    recalls = [r.recall for r in runs]
    f1s = [r.f1 for r in runs]
    durations = [r.duration_seconds for r in runs]
    missed = [r.missed_required_count for r in runs]

    # Per-category recall: for each category present in any run, average
    # gt_detected / gt_total
    cats: set[str] = set()
    for r in runs:
        cats.update(r.per_category.keys())
    per_cat_recall: dict[str, float] = {}
    for cat in sorted(cats):
        ratios = []
        for r in runs:
            bucket = r.per_category.get(cat, {})
            total = bucket.get("gt_total", 0)
            detected = bucket.get("gt_detected", 0)
            if total:
                ratios.append(detected / total)
        if ratios:
            per_cat_recall[cat] = sum(ratios) / len(ratios)

    return AggregatedResult(
        target_app=target,
        runs=len(runs),
        mean_precision=sum(precisions) / len(precisions),
        std_precision=_stdev(precisions),
        mean_recall=sum(recalls) / len(recalls),
        std_recall=_stdev(recalls),
        mean_f1=sum(f1s) / len(f1s),
        std_f1=_stdev(f1s),
        mean_duration_s=sum(durations) / len(durations) if durations else 0.0,
        std_duration_s=_stdev(durations),
        per_category_recall=per_cat_recall,
        missed_required_min=min(missed),
        missed_required_max=max(missed),
    )
