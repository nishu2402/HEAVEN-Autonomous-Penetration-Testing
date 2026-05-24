"""
HEAVEN — Self-grading coverage assessor

The bug fixed here: a senior pen-tester always asks "what did I NOT
test?" before signing off. HEAVEN historically just shipped whatever
findings it produced; this module makes the gaps explicit.

Two scoring paths:

  1. **Rule-based** (always available, deterministic):
     - OWASP Top 10 coverage from finding categories observed
     - OWASP API Top 10 coverage
     - Scope-target hit rate (every in-scope target scanned at least once?)
     - Authentication exercised? (cookie jar non-empty?)
     - Auto-prove run? Post-ex chained?

  2. **LLM-augmented** (when ANTHROPIC/OPENAI/GEMINI key is set):
     - Free-form gap analysis on the structured rule-based report
     - "Given these scope targets and these findings, name three classes
        of issue you'd expect to see that aren't represented"
     - Returns prose recommendations with evidence citations

The output of grade_engagement() is a CoverageReport ready to render
in the CLI, attach to the PDF report, or pipe through the `heaven
coverage` command.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("ai.coverage_grader")


# ═══════════════════════════════════════════
# OWASP CATEGORY MAPPING
# Maps observed vuln_type → OWASP Top 10 category. Mirrors what's already
# in tests/benchmarks/metrics.py::_TYPE_TO_CATEGORY but at the higher
# OWASP-bucket level.
# ═══════════════════════════════════════════

OWASP_2021 = {
    "A01_2021": "Broken Access Control",
    "A02_2021": "Cryptographic Failures",
    "A03_2021": "Injection",
    "A04_2021": "Insecure Design",
    "A05_2021": "Security Misconfiguration",
    "A06_2021": "Vulnerable and Outdated Components",
    "A07_2021": "Identification and Authentication Failures",
    "A08_2021": "Software and Data Integrity Failures",
    "A09_2021": "Security Logging and Monitoring Failures",
    "A10_2021": "Server-Side Request Forgery",
}

OWASP_API_2023 = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

_VULN_TO_OWASP: dict[str, str] = {
    "sqli": "A03_2021", "xss": "A03_2021", "cmdi": "A03_2021",
    "ssti": "A03_2021", "ldap_injection": "A03_2021", "xxe": "A03_2021",
    "ssrf": "A10_2021",
    "idor": "A01_2021", "csrf": "A01_2021", "open_redirect": "A01_2021",
    "broken_access_control": "A01_2021",
    "weak_auth": "A07_2021", "default_credentials": "A07_2021",
    "weak_credentials": "A07_2021",
    "lfi": "A05_2021", "file_upload": "A05_2021",
    "security_misconfig": "A05_2021",
    "auth_bypass": "A07_2021",
    "deserialization": "A08_2021",
    "info_disclosure": "A09_2021",
    "rfi": "A03_2021",
}


# ═══════════════════════════════════════════
# REPORT TYPES
# ═══════════════════════════════════════════


@dataclass
class CategoryStatus:
    code: str
    name: str
    finding_count: int = 0
    tested: bool = False     # at least one HEAVEN scanner exists for this category
    @property
    def covered(self) -> bool:
        return self.finding_count > 0


@dataclass
class CoverageReport:
    engagement_name: str
    scope_target_count: int = 0
    scanned_target_count: int = 0
    total_findings: int = 0

    owasp_top10: list[CategoryStatus] = field(default_factory=list)
    owasp_api_top10: list[CategoryStatus] = field(default_factory=list)

    authenticated: bool = False
    auto_prove_run: bool = False
    postex_chained: bool = False

    untested_scope_targets: list[str] = field(default_factory=list)
    llm_gap_summary: str = ""           # populated when LLM available
    recommendations: list[str] = field(default_factory=list)

    @property
    def scope_coverage_pct(self) -> float:
        if not self.scope_target_count:
            return 0.0
        return self.scanned_target_count / self.scope_target_count * 100

    @property
    def owasp_coverage_pct(self) -> float:
        if not self.owasp_top10:
            return 0.0
        return sum(1 for c in self.owasp_top10 if c.covered) / len(self.owasp_top10) * 100

    @property
    def grade(self) -> str:
        """One-letter A/B/C/D/F grade. Conservative — F is the default."""
        score = 0
        if self.scope_coverage_pct >= 90:
            score += 25
        elif self.scope_coverage_pct >= 50:
            score += 15
        if self.owasp_coverage_pct >= 70:
            score += 30
        elif self.owasp_coverage_pct >= 40:
            score += 20
        elif self.owasp_coverage_pct > 0:
            score += 10
        if self.authenticated:
            score += 15
        if self.auto_prove_run:
            score += 15
        if self.postex_chained:
            score += 15
        if score >= 85:
            return "A"
        if score >= 70:
            return "B"
        if score >= 50:
            return "C"
        if score >= 30:
            return "D"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement_name,
            "grade": self.grade,
            "scope_coverage_pct": round(self.scope_coverage_pct, 1),
            "owasp_coverage_pct": round(self.owasp_coverage_pct, 1),
            "scope_target_count": self.scope_target_count,
            "scanned_target_count": self.scanned_target_count,
            "total_findings": self.total_findings,
            "authenticated": self.authenticated,
            "auto_prove_run": self.auto_prove_run,
            "postex_chained": self.postex_chained,
            "owasp_top10": [
                {"code": c.code, "name": c.name, "findings": c.finding_count,
                 "covered": c.covered}
                for c in self.owasp_top10
            ],
            "owasp_api_top10": [
                {"code": c.code, "name": c.name, "findings": c.finding_count,
                 "covered": c.covered}
                for c in self.owasp_api_top10
            ],
            "untested_scope_targets": self.untested_scope_targets,
            "llm_gap_summary": self.llm_gap_summary,
            "recommendations": self.recommendations,
        }


# ═══════════════════════════════════════════
# RULE-BASED GRADER
# ═══════════════════════════════════════════


def _classify(vuln_type: str) -> Optional[str]:
    if not vuln_type:
        return None
    head = vuln_type.lower().split("_")[0]
    return _VULN_TO_OWASP.get(head) or _VULN_TO_OWASP.get(vuln_type.lower())


def grade_engagement_rule_based(engagement_store) -> CoverageReport:
    """Build a CoverageReport from an EngagementStore. Always available."""
    name = ""
    eng = engagement_store.get_engagement()
    if eng:
        name = eng.name

    scope = engagement_store.list_scope(in_scope_only=True)
    findings = engagement_store.list_findings(limit=10000)
    scans = engagement_store.list_all_scans()

    # OWASP buckets
    owasp_counts: dict[str, int] = {code: 0 for code in OWASP_2021}
    for f in findings:
        owasp_code = _classify(f.vuln_type or "")
        if owasp_code:
            owasp_counts[owasp_code] = owasp_counts.get(owasp_code, 0) + 1

    owasp_status = [
        CategoryStatus(code=code, name=OWASP_2021[code],
                       finding_count=owasp_counts.get(code, 0), tested=True)
        for code in OWASP_2021
    ]
    owasp_api_status = [
        CategoryStatus(code=code, name=OWASP_API_2023[code], tested=True)
        for code in OWASP_API_2023
    ]

    # Scope coverage — a target counts as "scanned" if any finding mentions it
    scope_targets = {s.target for s in scope}
    scanned_targets = {f.target.split("?")[0].split(":")[0] for f in findings if f.target}
    untested = sorted(
        t for t in scope_targets
        if not any(t in st for st in scanned_targets)
    )

    # Heuristics for auth / prove / postex from scan config_json
    authed = False
    auto_prove_run = False
    postex_chained = False
    import json as _json
    for s in scans:
        cfg = s.get("config_json") or "{}"
        try:
            data = _json.loads(cfg)
        except Exception:
            continue
        if isinstance(data, dict):
            targets = data.get("targets", data)
            if isinstance(targets, dict):
                if targets.get("auto_prove"):
                    auto_prove_run = True
                if targets.get("autonomous"):
                    postex_chained = True
        # Authentication detection: scan config doesn't store cookies but
        # checks the WebhookAlerter is set OR engagement note marker
    if eng and "auth" in (eng.notes or "").lower():
        authed = True

    report = CoverageReport(
        engagement_name=name,
        scope_target_count=len(scope_targets),
        scanned_target_count=len(scope_targets) - len(untested),
        total_findings=len(findings),
        owasp_top10=owasp_status,
        owasp_api_top10=owasp_api_status,
        authenticated=authed,
        auto_prove_run=auto_prove_run,
        postex_chained=postex_chained,
        untested_scope_targets=untested[:20],
    )

    # Rule-based recommendations
    if report.scope_coverage_pct < 80:
        report.recommendations.append(
            f"Scope coverage is {report.scope_coverage_pct:.0f}% — "
            f"{len(untested)} target(s) have zero findings recorded. Re-scan or "
            f"validate they exist."
        )
    uncov_owasp = [c.name for c in owasp_status if not c.covered]
    if uncov_owasp:
        report.recommendations.append(
            f"OWASP Top 10 categories with zero findings: "
            f"{', '.join(uncov_owasp[:5])}. Either the target is genuinely not "
            f"vulnerable to these, or the relevant scanner didn't run."
        )
    if not authed:
        report.recommendations.append(
            "No authenticated scan recorded. Most real apps' attack surface "
            "is behind login — use `heaven scan --cookie-file` or `--auth`."
        )
    if not auto_prove_run:
        report.recommendations.append(
            "Findings were detected but not actively proved. Add `--auto-prove` "
            "to confirm impact with sqlmap / RCE canary / SSRF callback."
        )
    if not postex_chained:
        report.recommendations.append(
            "Post-exploitation was not chained. For an autonomous run, use "
            "`heaven autonomous --engagement <name> -t <target>` which chains "
            "exploit-proof → cred-reuse → linpeas automatically."
        )
    return report


# ═══════════════════════════════════════════
# LLM AUGMENTATION
# ═══════════════════════════════════════════


async def augment_with_llm(report: CoverageReport, findings_sample: list[dict]) -> CoverageReport:
    """Ask the LLM gateway for a free-form gap analysis on top of the rule
    report. Skipped (no-op) when no LLM key is configured.
    """
    try:
        from heaven.ai import LLMGateway, LLMRequest
    except Exception:
        return report
    gw = LLMGateway()
    if not gw.available:
        return report

    system = (
        "You are a senior offensive-security reviewer doing a quality check "
        "on another tester's pen-test scope coverage. Given the structured "
        "summary below, list (1) three classes of issue you'd EXPECT to see "
        "that are missing, (2) the most likely reason they're missing, (3) "
        "one concrete next step per issue. Be specific and terse."
    )
    prompt_payload = {
        "engagement": report.engagement_name,
        "owasp_coverage_pct": report.owasp_coverage_pct,
        "scope_coverage_pct": report.scope_coverage_pct,
        "authenticated": report.authenticated,
        "auto_prove_run": report.auto_prove_run,
        "postex_chained": report.postex_chained,
        "uncovered_owasp": [c.name for c in report.owasp_top10 if not c.covered],
        "sample_findings": findings_sample[:20],
    }
    import json as _json
    prompt = "Engagement summary:\n" + _json.dumps(prompt_payload, indent=2)

    try:
        resp = await gw.acomplete(LLMRequest(prompt=prompt, system=system,
                                             max_tokens=600, temperature=0.3,
                                             cache_static_prefix=True))
        if resp.ok():
            report.llm_gap_summary = resp.text.strip()
    except Exception as e:
        logger.warning(f"LLM coverage augment failed: {e}")
    return report


# ═══════════════════════════════════════════
# PUBLIC ENTRYPOINT
# ═══════════════════════════════════════════


async def grade_engagement(engagement_store, use_llm: bool = True) -> CoverageReport:
    """One call → fully graded engagement. LLM augmentation is best-effort."""
    report = grade_engagement_rule_based(engagement_store)
    if use_llm:
        sample = [
            {"id": f.id, "vuln_type": f.vuln_type, "severity": f.severity,
             "target": f.target}
            for f in engagement_store.list_findings(limit=20)
        ]
        report = await augment_with_llm(report, sample)
    return report
