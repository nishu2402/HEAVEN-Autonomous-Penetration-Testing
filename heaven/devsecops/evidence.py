"""
HEAVEN — Evidence Package Generator.

Every finding HEAVEN produces should ship with the exact request that proved
it, the response excerpt, and a curl command an operator can paste into a
terminal to reproduce. No "trust the scanner" — show the work.

The evidence-package format is what goes into the operator-facing report and
into the engagement DB. It is JSON-serialisable, rendering-independent, and
designed to be exported into Markdown/HTML/PDF without further enrichment.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EvidencePackage:
    """A single finding's full evidence trail."""
    finding_id: str
    vuln_type: str
    target: str
    severity: str
    confidence: float
    confidence_bucket: str = ""

    # Probe / proof
    technique: str = ""
    payload: str = ""
    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_excerpt: str = ""        # Truncated, not full body
    response_size_bytes: int = 0

    # Why we believe it
    reasons: list[str] = field(default_factory=list)
    fp_check_evidence: dict = field(default_factory=dict)

    # Reproduction
    curl_command: str = ""
    repro_steps: list[str] = field(default_factory=list)

    # Remediation
    cwe_id: str = ""
    cve_id: str = ""
    remediation: str = ""

    # Operator workflow
    notes: str = ""
    status: str = "open"
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    def to_markdown(self) -> str:
        """Render as a Markdown block suitable for a pentest report."""
        lines = [
            f"### {self.vuln_type.upper()} — {self.target}",
            "",
            f"**ID:** `{self.finding_id}`  ",
            f"**Severity:** {self.severity}  ",
            f"**Confidence:** {self.confidence:.2f} ({self.confidence_bucket})  ",
        ]
        if self.cve_id:
            lines.append(f"**CVE:** {self.cve_id}  ")
        if self.cwe_id:
            lines.append(f"**CWE:** {self.cwe_id}  ")
        lines.append(f"**Status:** {self.status}")
        lines.append("")

        if self.technique:
            lines.append(f"**Technique:** `{self.technique}`")
            lines.append("")

        # The proof
        lines.append("#### Proof of issue")
        lines.append("")
        lines.append("**Request:**")
        lines.append("```http")
        req = f"{self.request_method} {self.request_url}"
        lines.append(req)
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body[:500])
            if len(self.request_body) > 500:
                lines.append("[... truncated ...]")
        lines.append("```")
        lines.append("")

        lines.append(f"**Response:** HTTP {self.response_status} ({self.response_size_bytes} bytes)")
        if self.response_excerpt:
            lines.append("```")
            lines.append(self.response_excerpt[:1000])
            if len(self.response_excerpt) > 1000:
                lines.append("[... truncated ...]")
            lines.append("```")
        lines.append("")

        # Why
        if self.reasons:
            lines.append("**Why this is flagged:**")
            for r in self.reasons:
                lines.append(f"- {r}")
            lines.append("")

        # Repro
        if self.curl_command:
            lines.append("**Reproduce with curl:**")
            lines.append("```bash")
            lines.append(self.curl_command)
            lines.append("```")
            lines.append("")

        if self.repro_steps:
            lines.append("**Manual repro steps:**")
            for i, step in enumerate(self.repro_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Remediation
        if self.remediation:
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(self.remediation)
            lines.append("")

        if self.notes:
            lines.append(f"> Operator notes: {self.notes}")
            lines.append("")

        return "\n".join(lines)


def build_curl(method: str, url: str, headers: Optional[dict] = None,
               body: str = "", payload_param: str = "",
               payload_value: str = "") -> str:
    """
    Build a copy-pasteable curl command for the proof request.

    Uses `shlex.quote` on every value so the command is safe to paste
    even when payloads contain quotes, semicolons, or other shell metas.
    """
    parts = ["curl"]

    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")

    parts.append("-i")  # include response headers in output
    parts.append("--max-time 30")

    if headers:
        for k, v in headers.items():
            # Skip obvious noise
            if k.lower() in ("content-length", "host"):
                continue
            parts.append(f"-H {shlex.quote(f'{k}: {v}')}")

    # Build payload body for non-GET (POST/PUT/PATCH/DELETE-with-body)
    final_url = url
    if payload_param and payload_value:
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            final_url = f"{url}{sep}{payload_param}={payload_value}"
        else:
            # Form-encoded body
            if not body:
                body = f"{payload_param}={payload_value}"
            elif payload_param not in body:
                body = f"{body}&{payload_param}={payload_value}"

    if body:
        parts.append(f"--data {shlex.quote(body)}")

    parts.append(shlex.quote(final_url))
    return " ".join(parts)


def package_finding(finding: dict, scan_id: str = "") -> EvidencePackage:
    """
    Convert a finding dict from the validator/scanner pipeline into a
    full EvidencePackage.

    The input may be a `ValidationResult` dataclass dumped to dict, a raw
    nuclei-style finding, or anything else the orchestrator produces.
    """
    from datetime import datetime, timezone

    target = (finding.get("target") or finding.get("target_url")
              or finding.get("host") or finding.get("url") or "")
    vuln_type = (finding.get("vuln_type") or finding.get("type") or "unknown").lower()

    evidence = finding.get("evidence", {}) or {}

    # Build request representation. Method/param/URL may live at top-level
    # OR inside evidence (depending on whether the finding came straight
    # from the validator or was rehydrated from the engagement DB).
    method = (finding.get("method") or evidence.get("method") or "GET")
    request_url = (finding.get("request_url") or evidence.get("request_url")
                   or evidence.get("url") or target)
    request_headers = evidence.get("request_headers", {}) or {}
    request_body = evidence.get("request_body", "") or finding.get("request_body", "")

    # Build response representation
    response_excerpt = (
        finding.get("response_snippet", "")
        or evidence.get("response_excerpt", "")
        or evidence.get("response_body", "")
    )
    if len(response_excerpt) > 4000:
        response_excerpt = response_excerpt[:4000] + "\n... [truncated by HEAVEN] ..."

    # Build repro
    payload = evidence.get("payload", "") or finding.get("payload", "")
    param = (finding.get("param") or evidence.get("param") or "")
    curl = build_curl(
        method=method, url=request_url,
        headers=request_headers, body=request_body,
        payload_param=param, payload_value=payload,
    )

    # Reasons / FP check trail
    reasons = (
        finding.get("fp_check_reasons", [])
        or finding.get("reasons", [])
        or []
    )

    return EvidencePackage(
        finding_id=finding.get("id", ""),
        vuln_type=vuln_type,
        target=target,
        severity=finding.get("severity", "info"),
        confidence=float(finding.get("confidence", 0.0)),
        confidence_bucket=finding.get("confidence_bucket", ""),
        technique=evidence.get("technique", ""),
        payload=payload,
        request_method=method,
        request_url=request_url,
        request_headers=request_headers,
        request_body=request_body or "",
        response_status=int(evidence.get("status", 0) or 0),
        response_headers=evidence.get("response_headers", {}) or {},
        response_excerpt=response_excerpt,
        response_size_bytes=len(response_excerpt),
        reasons=reasons,
        fp_check_evidence=finding.get("fp_check_evidence", {}) or {},
        curl_command=curl,
        repro_steps=finding.get("repro_steps", []),
        cwe_id=finding.get("cwe_id", ""),
        cve_id=finding.get("cve_id", ""),
        remediation=finding.get("patch", "") or finding.get("remediation", ""),
        notes=finding.get("operator_notes", ""),
        status=finding.get("status", "open"),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def export_findings_markdown(findings: list[dict], engagement_name: str = "") -> str:
    """Render multiple findings as a single Markdown report."""
    from datetime import datetime, timezone
    out = []
    out.append("# HEAVEN Findings Report")
    if engagement_name:
        out.append(f"\n**Engagement:** {engagement_name}")
    out.append(f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    out.append(f"\n**Total findings:** {len(findings)}")
    out.append("")

    # Severity histogram
    by_sev: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "info")
        by_sev[s] = by_sev.get(s, 0) + 1
    out.append("## Severity breakdown\n")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in by_sev:
            out.append(f"- **{sev.title()}:** {by_sev[sev]}")
    out.append("")

    # Per-finding sections, sorted by severity then confidence
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_rank.get(f.get("severity", "info"), 9),
                       -float(f.get("confidence", 0.0))),
    )
    out.append("## Findings\n")
    for f in sorted_findings:
        pkg = package_finding(f)
        out.append(pkg.to_markdown())
        out.append("---\n")

    return "\n".join(out)


def export_findings_csv(findings: list[dict]) -> str:
    """Render findings as CSV — for ticket-system import."""
    import csv
    import io
    buf = io.StringIO()
    fields = [
        "id", "target", "vuln_type", "title", "severity", "confidence",
        "confidence_bucket", "cve_id", "risk_score", "status",
        "first_seen_at", "operator_notes",
    ]
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for f in findings:
        # Normalise field names from various sources
        row = {
            "id": f.get("id", ""),
            "target": f.get("target", "") or f.get("target_url", ""),
            "vuln_type": f.get("vuln_type", "") or f.get("type", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", "info"),
            "confidence": f.get("confidence", 0.0),
            "confidence_bucket": f.get("confidence_bucket", ""),
            "cve_id": f.get("cve_id", ""),
            "risk_score": f.get("risk_score", 0.0),
            "status": f.get("status", "open"),
            "first_seen_at": f.get("first_seen_at", ""),
            "operator_notes": f.get("operator_notes", ""),
        }
        w.writerow(row)
    return buf.getvalue()
