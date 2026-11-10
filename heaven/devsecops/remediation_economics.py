"""
HEAVEN — Remediation economics (risk x effort, and quick wins).

Severity alone does not tell a client what to fix first. A senior tester's
report says "these three are quick wins, do them this week; this one is
expensive, plan it for next quarter." This module adds that economic dimension
to every finding:

* **effort** — how much work the fix is (``low`` / ``medium`` / ``high``),
  derived from the weakness class, because remediation effort really does cluster
  by class: a missing security header is a config flip (low), a dependency CVE is
  a version bump (medium), and an injection flaw is a code change plus review
  (high). A curated ``effort`` override in the vuln knowledge base wins when
  present.
* **priority_score** — risk divided by effort, so the roadmap can lead with the
  highest return-on-effort items. Risk is the severity weight lifted by concrete
  exploit signals (CISA KEV, a public exploit, a high EPSS probability).
* **quick_win** — a high-impact finding whose fix is low effort: the items a
  client should knock out immediately.

Everything here is deterministic and offline. :func:`annotate` stamps the three
values onto each finding so the API, UI and reports share one source of truth.
"""

from __future__ import annotations

from typing import Any, Iterable

# ── effort tiers ────────────────────────────────────────────────────────────
# Relative cost used to turn risk into return-on-effort. Low effort = best ROI
# for the same risk.
_EFFORT_COST = {"low": 1.0, "medium": 2.5, "high": 5.0}
_EFFORT_RANK = {"low": 0, "medium": 1, "high": 2}

# Severity → base risk weight (aligned with the report's severity ordering).
_SEV_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 1.0}

# Classifier rules, evaluated HIGH → MEDIUM → LOW so a specific high-effort class
# (``sql_injection``) is never captured by a generic lower rule. Each tier lists
# vuln_type / CWE substrings. Matching is on the normalised key and the CWE id.
_HIGH_EFFORT = (
    # injection & code-execution classes — a code change plus review
    "sql_injection", "sqli", "xss", "cross_site_scripting", "command_injection",
    "cmdi", "os_command", "rce", "code_injection", "remote_code", "ssti",
    "template_injection", "xxe", "xml_external", "ldap_injection", "nosql",
    "deserialization", "insecure_deserialization", "expression_language",
    "ognl", "el_injection", "prototype_pollution", "crlf_injection",
    # access-control & logic classes — design/code change
    "idor", "bola", "bfla", "broken_access", "access_control",
    "insecure_direct_object", "privilege_escalation", "mass_assignment",
    "business_logic", "workflow", "numeric_tampering", "auth_bypass",
    "authentication_bypass", "broken_auth", "forced_browsing", "race_condition",
    # server-side request, upload, token classes
    "ssrf", "server_side_request", "file_upload", "unrestricted_upload",
    "path_traversal", "directory_traversal", "jwt", "insecure_jwt",
)
_HIGH_EFFORT_CWE = {
    "CWE-89", "CWE-79", "CWE-78", "CWE-77", "CWE-94", "CWE-90", "CWE-91",
    "CWE-611", "CWE-502", "CWE-918", "CWE-434", "CWE-639", "CWE-862", "CWE-863",
    "CWE-284", "CWE-287", "CWE-840", "CWE-22", "CWE-362", "CWE-915", "CWE-1321",
}
_MEDIUM_EFFORT = (
    "outdated", "eol", "end_of_life", "unsupported", "vulnerable_service",
    "potential_vulnerable_service", "known_vulnerability", "cve",
    "sca", "dependency", "outdated_component", "component_with_known",
    "weak_credential", "default_credential", "weak_password", "credential",
    "rate_limit", "missing_rate_limit", "brute_force", "cors",
    "subdomain_takeover", "missing_patch", "open_redirect", "csrf",
)
_MEDIUM_EFFORT_CWE = {
    "CWE-1104", "CWE-1035", "CWE-937", "CWE-521", "CWE-798", "CWE-307",
    "CWE-352", "CWE-601", "CWE-1395",
}
_LOW_EFFORT = (
    "header", "security_header", "missing_header", "hsts", "x_frame",
    "clickjack", "csp", "content_security_policy", "x_content_type",
    "referrer_policy", "permissions_policy", "cookie", "secure_flag",
    "httponly", "samesite", "tls", "ssl", "cipher", "certificate", "cert",
    "forward_secrecy", "sweet32", "poodle", "beast", "heartbleed", "protocol",
    "directory_listing", "autoindex", "verbose_error", "stack_trace",
    "information_disclosure", "info_disclosure", "info_leak", "banner",
    "server_header", "version_disclosure", "default_page", "debug",
    "spf", "dkim", "dmarc", "dnssec", "caa", "open_port", "exposed",
    "perimeter", "firewall",
)


def _norm(vuln_type: str) -> str:
    """Normalise a vuln_type the same way the knowledge base does."""
    import re
    return re.sub(r"[^a-z0-9]+", "_", str(vuln_type or "").lower()).strip("_")


def _kb_effort(vuln_type: str) -> str:
    """A curated ``effort`` override from the knowledge base, or ''."""
    try:
        from heaven.devsecops.vuln_kb import lookup
        val = str(lookup(vuln_type).get("effort") or "").strip().lower()
        return val if val in _EFFORT_COST else ""
    except Exception:  # noqa: BLE001 — KB is optional
        return ""


def remediation_effort(finding: dict[str, Any]) -> str:
    """Classify the fix effort for a finding: ``low`` / ``medium`` / ``high``.

    A curated knowledge-base override wins; otherwise the weakness class decides
    (its vuln_type and CWE). Unknown classes default to ``medium`` — neither a
    quick win nor assumed to be a rewrite.
    """
    vt = _norm(finding.get("vuln_type") or finding.get("type") or "")
    override = _kb_effort(vt)
    if override:
        return override
    cwe = str(finding.get("cwe") or finding.get("cwe_id") or "").upper().strip()

    if cwe in _HIGH_EFFORT_CWE or any(k in vt for k in _HIGH_EFFORT):
        return "high"
    if cwe in _MEDIUM_EFFORT_CWE or any(k in vt for k in _MEDIUM_EFFORT):
        return "medium"
    if any(k in vt for k in _LOW_EFFORT):
        return "low"
    return "medium"


def _exploit_multiplier(finding: dict[str, Any]) -> float:
    """Lift risk for concrete exploit signals (bounded to [1.0, 1.6])."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    mult = 1.0
    if finding.get("in_kev") or finding.get("kev") or finding.get("cisa_kev") \
            or ev.get("in_kev") or ev.get("kev"):
        mult = max(mult, 1.5)
    if finding.get("exploit_available") or ev.get("exploit_available"):
        mult = max(mult, 1.3)
    try:
        epss = float(finding.get("epss") or finding.get("epss_score")
                     or ev.get("epss") or ev.get("epss_score") or 0.0)
    except (TypeError, ValueError):
        epss = 0.0
    if epss >= 0.5:
        mult = max(mult, 1.2)
    # KEV + public exploit compound a little, but never past 1.6.
    return min(mult, 1.6)


def _severity(finding: dict[str, Any]) -> str:
    s = str(finding.get("severity") or "info").strip().lower()
    return s if s in _SEV_WEIGHT else "info"


def risk_weight(finding: dict[str, Any]) -> float:
    """Severity weight lifted by exploit signals — the numerator of the ROI."""
    return _SEV_WEIGHT[_severity(finding)] * _exploit_multiplier(finding)


def priority_score(finding: dict[str, Any]) -> float:
    """Return-on-effort score: risk / effort cost. Higher = fix sooner.

    A rounded, stable float so two findings with the same risk and effort tie
    deterministically and the roadmap order is reproducible.
    """
    effort = finding.get("remediation_effort") or remediation_effort(finding)
    cost = _EFFORT_COST.get(str(effort), 2.5)
    return round(risk_weight(finding) / cost, 3)


def is_quick_win(finding: dict[str, Any]) -> bool:
    """A quick win: high-impact AND low-effort.

    High-impact means a critical/high severity, or a medium that exploit signals
    have lifted (KEV / public exploit / high EPSS). Low-effort means a config/
    header/flag fix. These are the items a client should fix immediately.
    """
    effort = finding.get("remediation_effort") or remediation_effort(finding)
    if effort != "low":
        return False
    sev = _severity(finding)
    if sev in ("critical", "high"):
        return True
    # A lifted medium (real exploit pressure) also qualifies.
    return sev == "medium" and _exploit_multiplier(finding) > 1.0


def annotate(findings: Iterable[dict[str, Any]]) -> int:
    """Stamp ``remediation_effort``, ``priority_score`` and ``quick_win`` onto
    each finding, in place. Returns the count annotated. Idempotent and never
    raises — economics are additive metadata.
    """
    n = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            effort = remediation_effort(f)
            f["remediation_effort"] = effort
            f["priority_score"] = priority_score(f)
            f["quick_win"] = is_quick_win(f)
            n += 1
        except Exception:  # noqa: BLE001 — never block on one finding
            continue
    return n


def prioritise(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return findings ordered by return-on-effort (priority_score desc).

    Ties break by severity then by lower effort, so the order is deterministic.
    Does not mutate the input list.
    """
    items = [f for f in findings if isinstance(f, dict)]
    return sorted(
        items,
        key=lambda f: (
            -priority_score(f),
            _SEV_WEIGHT[_severity(f)] * -1,
            _EFFORT_RANK.get(f.get("remediation_effort") or remediation_effort(f), 1),
        ),
    )


def quick_wins(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The quick-win findings, ordered by return-on-effort."""
    return [f for f in prioritise(findings) if is_quick_win(f)]


def effort_summary(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count findings per effort tier, for a report header line."""
    out = {"low": 0, "medium": 0, "high": 0}
    for f in findings:
        if not isinstance(f, dict):
            continue
        out[remediation_effort(f)] = out.get(remediation_effort(f), 0) + 1
    return out


def render_quick_wins_markdown(findings: Iterable[dict[str, Any]]) -> str:
    """Render a "Quick wins" Markdown section, or '' when there are none."""
    wins = quick_wins(findings)
    if not wins:
        return ""
    out = [
        "## Quick wins (high impact, low effort)",
        "",
        "_Fix these first: each is a configuration, header or flag change that "
        "removes a high-impact issue with minimal work._",
        "",
        "| # | Finding | Severity | Target |",
        "|---|---|---|---|",
    ]
    for i, f in enumerate(wins, 1):
        title = str(f.get("title") or f.get("vuln_type") or "Finding").replace("|", "/")[:70]
        sev = _severity(f).title()
        target = str(f.get("target") or f.get("url") or f.get("host") or "").replace("|", "/")[:60]
        out.append(f"| {i} | {title} | {sev} | {target} |")
    out.append("")
    return "\n".join(out)
