"""
HEAVEN — CI / DevSecOps export (SARIF 2.1.0 + JUnit XML)

Machine-readable exports so HEAVEN findings flow into the pipelines security teams
already run:

  • **SARIF 2.1.0** — GitHub / GitLab / Azure DevOps "code scanning" ingest.
    Emits per-finding results with real ``artifactLocation`` URIs (the target),
    ``partialFingerprints`` (so the platform tracks a finding across runs instead
    of re-alerting), and a numeric ``security-severity`` property (what GitHub
    reads to bucket Critical/High/…). Each distinct rule carries CWE/OWASP tags
    and the confirmation status (Confirmed vs Potential).

  • **JUnit XML** — the lingua-franca every CI runner renders. One ``<testcase>``
    per finding; findings at/above the ``fail_on`` severity become ``<failure>``
    elements so a pipeline step goes red, while lower-severity findings pass as
    informational. Lets a build gate on "no new High/Critical".

Both are pure functions returning a string — no side effects, no file writes —
so a caller decides where the bytes go. Nothing here fabricates data; every field
is read straight off the finding.
"""

from __future__ import annotations

import json
from typing import Any
# saxutils.escape/quoteattr only *escape* our own strings for XML OUTPUT; we never
# parse untrusted XML here, so the B406 XML-attack blacklist does not apply.
from xml.sax.saxutils import escape, quoteattr  # nosec B406

from heaven.utils.cvss import (
    is_confirmed_finding,
    objective_base_score,
    severity_from_score,
)

_TOOL_VERSION = "3.0.0"
_INFO_URI = "https://github.com/heaven-security/heaven"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev(finding: dict[str, Any]) -> str:
    return str(finding.get("severity") or "info").strip().lower()


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(severity, "note")


def _cve(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(finding.get("cve") or finding.get("cve_id") or ev.get("cve") or "").strip()


def _target(finding: dict[str, Any]) -> str:
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(finding.get("target") or finding.get("url") or finding.get("host")
               or ev.get("url") or "").strip() or "unspecified-asset"


def _rule_id(finding: dict[str, Any]) -> str:
    """Stable rule id: the CVE when present, else the vuln_type/type token."""
    cve = _cve(finding)
    if cve:
        return cve
    return str(finding.get("vuln_type") or finding.get("type") or "finding").strip() or "finding"


def _fingerprint(finding: dict[str, Any]) -> str:
    """A stable per-finding id so the platform tracks it across runs."""
    fid = str(finding.get("id") or "").strip()
    if fid:
        return fid
    # Fall back to a deterministic identity when no stored id is present.
    parts = [_rule_id(finding), _target(finding),
             str(finding.get("port") or ""), str(finding.get("param") or "")]
    return "heaven:" + "|".join(parts)


def findings_to_sarif(findings: list[dict[str, Any]], *,
                      engagement_name: str = "",
                      tool_version: str = _TOOL_VERSION) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (as a dict) from HEAVEN findings."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rid = _rule_id(f)
        severity = _sev(f)
        base = objective_base_score(f) or 0.0
        confirmation = "Confirmed" if is_confirmed_finding(f) else "Potential"

        if rid not in rules:
            tags = ["security"]
            for k in ("cwe", "owasp"):
                v = f.get(k) or (f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}).get(k)
                if v:
                    tags.append(str(v))
            help_uri = (f"https://nvd.nist.gov/vuln/detail/{rid}"
                        if rid.upper().startswith("CVE-") else _INFO_URI)
            rules[rid] = {
                "id": rid,
                "name": str(f.get("title") or rid)[:120],
                "shortDescription": {"text": str(f.get("title") or rid)[:240]},
                "fullDescription": {
                    "text": str((f.get("evidence", {}) if isinstance(f.get("evidence"), dict)
                                 else {}).get("description") or f.get("description")
                                or f.get("title") or rid)[:2000]
                },
                "helpUri": help_uri,
                "defaultConfiguration": {"level": _sarif_level(severity)},
                "properties": {
                    "tags": tags,
                    # GitHub code-scanning reads security-severity (0.0-10.0) to
                    # bucket the alert's severity — must be a string.
                    "security-severity": f"{base:.1f}",
                },
            }

        results.append({
            "ruleId": rid,
            "level": _sarif_level(severity),
            "message": {"text": str(f.get("title") or f.get("description") or rid)[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _target(f)},
                }
            }],
            # Stable identity so the platform dedupes/tracks across runs.
            "partialFingerprints": {"heavenFindingId/v1": _fingerprint(f)},
            "properties": {
                "severity": severity,
                "security-severity": f"{base:.1f}",
                "confirmation": confirmation,
                "confidence": float(f.get("confidence") or 0.0),
                "cve": _cve(f),
                "port": f.get("port") or 0,
            },
        })

    driver_name = "HEAVEN" + (f" — {engagement_name}" if engagement_name else "")
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": driver_name,
                    "version": tool_version,
                    "informationUri": _INFO_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def findings_to_sarif_str(findings: list[dict[str, Any]], **kw: Any) -> str:
    """SARIF log serialized to an indented JSON string."""
    return json.dumps(findings_to_sarif(findings, **kw), indent=2, default=str)


def findings_to_junit(findings: list[dict[str, Any]], *,
                      engagement_name: str = "",
                      fail_on: str = "medium") -> str:
    """Render findings as a JUnit XML suite.

    A finding whose severity is at or above ``fail_on`` becomes a ``<failure>``
    (a red test) so a CI step can gate the build; lower-severity findings pass as
    informational testcases. ``fail_on`` accepts a severity name or ``"none"`` to
    never fail (every finding passes — useful for a purely informational report).
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    # A finding fails when its severity rank <= fail_rank (lower rank = worse).
    # "none" (and any unknown value) → rank -1, so nothing ever fails.
    fail_rank = _SEV_RANK.get(str(fail_on).strip().lower(), -1)
    failures = 0
    cases: list[str] = []

    for f in findings:
        severity = _sev(f)
        target = _target(f)
        vt = str(f.get("vuln_type") or f.get("type") or "finding")
        title = str(f.get("title") or vt)
        name = f"{title} @ {target}"
        classname = f"heaven.{vt}"
        is_fail = _SEV_RANK.get(severity, 4) <= fail_rank
        if is_fail:
            failures += 1
            base = objective_base_score(f) or 0.0
            confirmation = "Confirmed" if is_confirmed_finding(f) else "Potential"
            detail = (f"Severity: {severity} (CVSS {base:.1f}) | {confirmation}\n"
                      f"Target: {target}\n"
                      f"CVE: {_cve(f) or '—'}")
            cases.append(
                f'  <testcase classname={quoteattr(classname)} name={quoteattr(name)}>\n'
                f'    <failure message={quoteattr(f"{severity.upper()}: {title}")} '
                f'type={quoteattr(severity)}>{escape(detail)}</failure>\n'
                f'  </testcase>'
            )
        else:
            cases.append(
                f'  <testcase classname={quoteattr(classname)} name={quoteattr(name)}/>'
            )

    suite_name = "HEAVEN" + (f" — {engagement_name}" if engagement_name else "")
    header = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              f'<testsuites tests="{len(findings)}" failures="{failures}">\n'
              f'  <testsuite name={quoteattr(suite_name)} tests="{len(findings)}" '
              f'failures="{failures}">')
    footer = '  </testsuite>\n</testsuites>\n'
    body = "\n".join(cases)
    return header + ("\n" + body if body else "") + "\n" + footer


def summarize_gate(findings: list[dict[str, Any]], *, fail_on: str = "high") -> dict[str, Any]:
    """CI gate summary: how many findings meet/exceed the fail threshold."""
    fail_rank = _SEV_RANK.get(str(fail_on).strip().lower(), -1)
    counts: dict[str, int] = {}
    breaching = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        sev = severity_from_score(objective_base_score(f)) if not _sev(f) else _sev(f)
        counts[sev] = counts.get(sev, 0) + 1
        if _SEV_RANK.get(sev, 4) <= fail_rank:
            breaching += 1
    return {"total": sum(counts.values()), "by_severity": counts,
            "fail_on": fail_on, "breaching": breaching, "passed": breaching == 0}
