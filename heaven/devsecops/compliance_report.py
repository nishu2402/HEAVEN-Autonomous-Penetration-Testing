"""
HEAVEN — Professional Penetration-Test Report Generator

Produces a single self-contained, **print-ready** HTML report that doubles as a
PDF: open it in any browser and use "Print → Save as PDF" (a button is built
in). The layout follows the structure clients expect from a professional
penetration-testing deliverable:

  1. Cover page (classification, engagement, overall risk)
  2. Confidentiality notice
  3. Document control + table of contents
  4. Executive summary (narrative + severity distribution)
  5. Scope & methodology (targets, standards, tools)
  6. Risk-rating methodology (severity scale + remediation SLAs)
  7. Findings summary table
  8. Detailed findings (description, impact, evidence/PoC, remediation, refs)
  9. OWASP Top 10 coverage
 10. Remediation roadmap (prioritised)
 11. Appendix (standards, glossary, disclaimer)

All scan-controlled text is HTML-escaped, so a finding title/target/evidence can
never break the layout or inject markup into the deliverable.
"""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

from heaven.devsecops import frameworks as _fw
from heaven.devsecops.dns_inventory import dns_totals as _dns_totals
from heaven.devsecops.dns_inventory import normalize_dns as _normalize_dns
from heaven.devsecops.inventory import device_name_label as _device_name_label
from heaven.devsecops.inventory import device_type_label as _device_type_label
from heaven.devsecops.inventory import inventory_totals as _inventory_totals
from heaven.devsecops.inventory import looks_like_ip as _looks_like_ip
from heaven.devsecops.inventory import mac_label as _mac_label
from heaven.devsecops.inventory import normalize_assets as _normalize_assets
from heaven.utils.cvss import is_confirmed_finding as _is_confirmed

# Severity → presentation. Colours are chosen to print cleanly on white paper.
SEVERITY_META: dict[str, dict[str, Any]] = {
    "critical": {"label": "Critical", "color": "#b00020", "cvss": "9.0-10.0",
                 "sla": "24-48 hours", "order": 0},
    "high":     {"label": "High",     "color": "#e8590c", "cvss": "7.0-8.9",
                 "sla": "1 week",      "order": 1},
    "medium":   {"label": "Medium",   "color": "#b8860b", "cvss": "4.0-6.9",
                 "sla": "1 month",     "order": 2},
    "low":      {"label": "Low",      "color": "#2563eb", "cvss": "0.1-3.9",
                 "sla": "90 days",     "order": 3},
    "info":     {"label": "Info",     "color": "#6b7280", "cvss": "0.0",
                 "sla": "Best effort", "order": 4},
}

_BRAND = "#4f46e5"          # HEAVEN indigo (matches the app's light-theme accent)
_BRAND_EMERALD = "#12b981"  # HEAVEN emerald

# The "Ascendant Aegis" mark, inlined so reports are fully self-contained (no
# external asset). Kept in lock-step with heaven-ui/src/components/Logo.jsx and
# heaven-ui/public/heaven-mark.svg. No blur filter — crisp for print/PDF.
_LOGO_SVG = (
    "<svg width=\"58\" height=\"58\" viewBox=\"0 0 128 128\" fill=\"none\" "
    "xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"HEAVEN\">"
    "<defs>"
    "<linearGradient id=\"rpEdge\" x1=\"18\" y1=\"12\" x2=\"110\" y2=\"118\" gradientUnits=\"userSpaceOnUse\">"
    "<stop offset=\"0\" stop-color=\"#6D7CFF\"/><stop offset=\"0.5\" stop-color=\"#22D3EE\"/>"
    "<stop offset=\"1\" stop-color=\"#34E5A3\"/></linearGradient>"
    "<linearGradient id=\"rpMono\" x1=\"48\" y1=\"45\" x2=\"80\" y2=\"88\" gradientUnits=\"userSpaceOnUse\">"
    "<stop offset=\"0\" stop-color=\"#8AA0FF\"/><stop offset=\"0.5\" stop-color=\"#34E5A3\"/>"
    "<stop offset=\"1\" stop-color=\"#22D3EE\"/></linearGradient></defs>"
    "<polygon points=\"64,10 110,37 110,91 64,118 18,91 18,37\" fill=\"#0B1220\" "
    "stroke=\"url(#rpEdge)\" stroke-width=\"5\" stroke-linejoin=\"round\"/>"
    "<polygon points=\"64,22 101,44 101,84 64,106 27,84 27,44\" stroke=\"url(#rpEdge)\" "
    "stroke-width=\"1.1\" stroke-opacity=\"0.35\" stroke-linejoin=\"round\"/>"
    "<g stroke=\"url(#rpMono)\" stroke-width=\"7.5\" stroke-linecap=\"round\" "
    "stroke-linejoin=\"round\" fill=\"none\">"
    "<path d=\"M48 50V88\"/><path d=\"M80 50V88\"/><path d=\"M48 72 64 54 80 72\"/></g>"
    "<circle cx=\"64\" cy=\"45\" r=\"4.6\" fill=\"#EAFBF4\"/></svg>"
)


def _esc(value: Any) -> str:
    """HTML-escape any value (scan output is untrusted)."""
    return html.escape("" if value is None else str(value), quote=True)


def _fmt_cvss(value: Any) -> str:
    """Render a CVSS score as a clean 1-dp string.

    A raw float from an upstream feed can carry binary-representation noise
    (``9.2000000000001``); shown verbatim in a narrow report column it wraps
    across three lines. Always round to one decimal; non-numeric values pass
    through unchanged so a text score like ``"n/a"`` is preserved.
    """
    if value is None or value == "":
        return ""
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return str(value)


def _short(text: Any, limit: int = 220) -> str:
    """Summarise long text at a WORD boundary (never mid-word).

    Used for at-a-glance table cells (e.g. the remediation roadmap) where the
    full text lives elsewhere. A hard ``text[:limit]`` produced the "…ends in
    the middle of a word" artifact; this trims back to the last space so the
    ellipsis only ever follows a whole word.
    """
    s = " ".join(str(text or "").split())
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0].rstrip(",;:.")
    return (cut or s[:limit]) + "…"


def _clip_sentence(text: Any, limit: int = 200) -> str:
    """Trim to a whole word within ``limit``, ending cleanly with a period.

    Unlike :func:`_short`, this never appends an ellipsis — a roadmap step reads
    as a finished instruction, not a truncated fragment ("…apply a WAF rule
    targeting…" looked unprofessional). The complete remediation lives in the
    finding detail; the roadmap carries a concise, whole-sentence summary."""
    s = " ".join(str(text or "").split())
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0].rstrip(",;:. ")
    return (cut or s[:limit]) + "."


def roadmap_action_lines(text: Any) -> list[str]:
    """Break a (possibly multi-step) remediation into concise roadmap lines.

    Each numbered step becomes its own line so "1. … 2. …" no longer runs
    together on one line, the verbose Verify/Reference trailer is dropped (it's
    in the finding detail), an exploit warning is kept, and nothing is truncated
    mid-word with an ellipsis. Returns at least one line."""
    if not str(text or "").strip():
        return ["Review and remediate per the finding detail."]
    raw = [ln.strip() for ln in str(text).replace("\r", "").split("\n") if ln.strip()]
    if len(raw) <= 1:
        return [_clip_sentence(raw[0] if raw else text, 240)]
    steps: list[str] = []
    warn = ""
    for ln in raw:
        low = ln.lower()
        if low.startswith(("verify:", "reference:", "references:", "see http", "note:")):
            continue
        if ln.startswith("⚠"):
            warn = _clip_sentence(ln, 200)  # kept even past the 3-step cap
            continue
        if len(steps) < 3:
            steps.append(_clip_sentence(ln, 200))
    if warn:
        steps.append(warn)
    return steps or [_clip_sentence(text, 240)]


def _sev_of(f: dict) -> str:
    s = (f.get("severity") or "info").lower()
    return s if s in SEVERITY_META else "info"


def _conf_of(f: dict) -> str:
    """Confirmation status label for a finding — 'Confirmed' or 'Potential'.

    Confirmed = proven by direct observation / active validation; Potential =
    inferred from a version banner or a heuristic indicator (never suppressed,
    but excluded from the confirmed-risk headline). Single source of truth in
    ``heaven.utils.cvss``.
    """
    return "Confirmed" if _is_confirmed(f) else "Potential"


def _conf_pill(f: dict) -> str:
    """A small coloured pill for a finding's confirmation status."""
    label = _conf_of(f)
    cls = "conf-confirmed" if label == "Confirmed" else "conf-potential"
    return f'<span class="confpill {cls}">{label}</span>'


def _wrap_tables(body: str) -> str:
    """Put every ``<table>`` in a horizontally-scrollable ``.tablewrap`` box so a
    wide table scrolls inside its own frame instead of forcing the whole report
    page to scroll sideways. Idempotent for our own output (nothing is
    pre-wrapped), and it leaves the table markup itself untouched."""
    body = re.sub(r"<table(\b[^>]*)>", r'<div class="tablewrap"><table\1>', body)
    return body.replace("</table>", "</table></div>")


class ComplianceReportGenerator:

    # vuln_type substring → (OWASP 2025 control id, name)
    # Canonical OWASP Top 10 (2025) — always rendered in full so the report is
    # a genuine coverage matrix (present vs not-observed), not just a list of hits.
    # Sourced from the single canon in ``frameworks.OWASP_2025`` so the report,
    # the coverage self-grade, the methodology page and the UI never diverge.
    OWASP_2025 = list(_fw.OWASP_2025)

    # Canonical OWASP API Security Top 10 (2023) — the API-specific companion to
    # the web Top 10. API findings carry an ``owasp_api`` tag (set by the API
    # scanner) and are scored here, never double-counted in the web matrix.
    # Ids match ``coverage_grader.OWASP_API_2023`` so the report and the Coverage
    # self-grade can never disagree.
    OWASP_API_2023 = [
        ("API1", "Broken Object Level Authorization"),
        ("API2", "Broken Authentication"),
        ("API3", "Broken Object Property Level Authorization"),
        ("API4", "Unrestricted Resource Consumption"),
        ("API5", "Broken Function Level Authorization"),
        ("API6", "Unrestricted Access to Sensitive Business Flows"),
        ("API7", "Server Side Request Forgery"),
        ("API8", "Security Misconfiguration"),
        ("API9", "Improper Inventory Management"),
        ("API10", "Unsafe Consumption of APIs"),
    ]

    # Fallback vuln_type → OWASP category, used only when a finding carries no
    # enriched ``owasp`` field. Broad keyword coverage so no real finding is
    # silently dropped from the matrix.
    # Fallback vuln_type substring → (OWASP 2025 id, name). Ordered: the first
    # key that is a substring of the vuln_type/title wins, so more-specific keys
    # (e.g. error-handling) precede broad ones. Values use the 2025 taxonomy —
    # SSRF now lives under A01, component/supply-chain risk under A03, and
    # error-mishandling under the new A10.
    OWASP_MAP = {
        # A10 Mishandling of Exceptional Conditions (new in 2025) — checked first
        # so a verbose-error / stack-trace leak isn't swallowed by A02.
        "verbose_error": ("A10:2025", "Mishandling of Exceptional Conditions"),
        "stack_trace": ("A10:2025", "Mishandling of Exceptional Conditions"),
        "error_message": ("A10:2025", "Mishandling of Exceptional Conditions"),
        "unhandled_exception": ("A10:2025", "Mishandling of Exceptional Conditions"),
        "fail_open": ("A10:2025", "Mishandling of Exceptional Conditions"),
        # A01 Broken Access Control (now also absorbs SSRF, A10:2021)
        "access_control": ("A01:2025", "Broken Access Control"),
        "idor": ("A01:2025", "Broken Access Control"),
        "bola": ("A01:2025", "Broken Access Control"),
        "lfi": ("A01:2025", "Broken Access Control"),
        "path_traversal": ("A01:2025", "Broken Access Control"),
        "directory_traversal": ("A01:2025", "Broken Access Control"),
        "unauthorized": ("A01:2025", "Broken Access Control"),
        "cors": ("A01:2025", "Broken Access Control"),
        "csrf": ("A01:2025", "Broken Access Control"),
        "ssrf": ("A01:2025", "Broken Access Control"),
        # A02 Security Misconfiguration (was A05:2021 — moved up to #2)
        "xxe": ("A02:2025", "Security Misconfiguration"),
        "misconfig": ("A02:2025", "Security Misconfiguration"),
        "security_header": ("A02:2025", "Security Misconfiguration"),
        "missing_header": ("A02:2025", "Security Misconfiguration"),
        "clickjack": ("A02:2025", "Security Misconfiguration"),
        "directory_listing": ("A02:2025", "Security Misconfiguration"),
        "default_page": ("A02:2025", "Security Misconfiguration"),
        "exposed_admin": ("A02:2025", "Security Misconfiguration"),
        "cookie": ("A02:2025", "Security Misconfiguration"),
        # A03 Software Supply Chain Failures (was A06:2021 Vulnerable & Outdated
        # Components, broadened; supply-chain integrity findings land here too)
        "vulnerable_component": ("A03:2025", "Software Supply Chain Failures"),
        "vulnerable_dependency": ("A03:2025", "Software Supply Chain Failures"),
        "vulnerable_service": ("A03:2025", "Software Supply Chain Failures"),
        "outdated": ("A03:2025", "Software Supply Chain Failures"),
        "known_vuln": ("A03:2025", "Software Supply Chain Failures"),
        "cve": ("A03:2025", "Software Supply Chain Failures"),
        "supply_chain": ("A03:2025", "Software Supply Chain Failures"),
        # A04 Cryptographic Failures (was A02:2021)
        "sensitive_data": ("A04:2025", "Cryptographic Failures"),
        "crypto": ("A04:2025", "Cryptographic Failures"),
        "ssl": ("A04:2025", "Cryptographic Failures"),
        "tls": ("A04:2025", "Cryptographic Failures"),
        "cipher": ("A04:2025", "Cryptographic Failures"),
        "certificate": ("A04:2025", "Cryptographic Failures"),
        "cleartext": ("A04:2025", "Cryptographic Failures"),
        # A05 Injection (was A03:2021)
        "sqli": ("A05:2025", "Injection"),
        "sql_injection": ("A05:2025", "Injection"),
        "xss": ("A05:2025", "Injection"),
        "command_injection": ("A05:2025", "Injection"),
        "code_injection": ("A05:2025", "Injection"),
        "rce": ("A05:2025", "Injection"),
        "rfi": ("A05:2025", "Injection"),
        "template_injection": ("A05:2025", "Injection"),
        "ssti": ("A05:2025", "Injection"),
        "ldap_injection": ("A05:2025", "Injection"),
        "header_injection": ("A05:2025", "Injection"),
        # A06 Insecure Design (was A04:2021)
        "insecure_design": ("A06:2025", "Insecure Design"),
        "open_redirect": ("A06:2025", "Insecure Design"),
        "business_logic": ("A06:2025", "Insecure Design"),
        # A07 Authentication Failures (was A07:2021, renamed)
        "broken_auth": ("A07:2025", "Authentication Failures"),
        "auth": ("A07:2025", "Authentication Failures"),
        "default_cred": ("A07:2025", "Authentication Failures"),
        "weak_cred": ("A07:2025", "Authentication Failures"),
        "weak_password": ("A07:2025", "Authentication Failures"),
        "session": ("A07:2025", "Authentication Failures"),
        "jwt": ("A07:2025", "Authentication Failures"),
        # A08 Software or Data Integrity Failures (was A08:2021, renamed)
        "deserial": ("A08:2025", "Software or Data Integrity Failures"),
        "integrity": ("A08:2025", "Software or Data Integrity Failures"),
        "unsigned": ("A08:2025", "Software or Data Integrity Failures"),
        # A09 Security Logging and Alerting Failures (was A09:2021, renamed)
        "logging": ("A09:2025", "Security Logging and Alerting Failures"),
        "monitoring": ("A09:2025", "Security Logging and Alerting Failures"),
    }

    SEV_ORDER = {k: v["order"] for k, v in SEVERITY_META.items()}

    # ── public entry point ──────────────────────────────────────────────

    def generate_html_report(self, findings: list[dict],
                             engagement_name: str = "",
                             output_path: Optional[Path] = None,
                             meta: Optional[dict] = None,
                             assets: Optional[list[dict]] = None,
                             dns_records: Optional[list[dict]] = None,
                             compliance_framework: Optional[str] = None) -> str:
        """Render the full professional report as one HTML string.

        `meta` (all optional) may carry: client, assessor, period, version,
        scope (list of targets). Anything absent is derived from the findings.

        `assets` (optional) are the raw network-scan host records; when present
        a "Host & Service Inventory" section (open ports / service versions /
        OS) is inserted, so the report documents the attack surface, not just
        the findings.

        `compliance_framework` (optional) is a framework id (``hipaa``,
        ``uk_gdpr``, …); when valid, a control-coverage section mapping the
        findings to that framework's controls is added, and the cover / TOC name
        it. Unknown ids are ignored (a normal report).
        """
        from heaven.devsecops import compliance_frameworks as _cf
        meta = meta or {}
        findings = findings or []
        eng = engagement_name or meta.get("client") or "HEAVEN Engagement"
        fw = _cf.get_framework(compliance_framework) if compliance_framework else None
        compliance_title = fw.title if fw else ""

        ordered = sorted(findings, key=lambda f: (
            self.SEV_ORDER.get(_sev_of(f), 4),
            -float(f.get("risk_score") or 0),
        ))
        # Two tallies: the full severity breakdown (every finding) and the
        # *confirmed-only* breakdown. Overall Risk is driven by confirmed
        # findings so that unauthenticated, version-based "potential" matches
        # (which can't be proven from the outside) never inflate the headline —
        # yet every potential finding still appears in full below.
        counts = {k: 0 for k in SEVERITY_META}
        confirmed_counts = {k: 0 for k in SEVERITY_META}
        for f in findings:
            sev = _sev_of(f)
            counts[sev] += 1
            if _is_confirmed(f):
                confirmed_counts[sev] += 1
        confirmed_total = sum(confirmed_counts.values())
        potential_total = len(findings) - confirmed_total

        overall = self._overall_risk(confirmed_counts)
        scope = meta.get("scope") or sorted(
            {str(f.get("target")) for f in findings if f.get("target")}
        )
        generated = datetime.now(UTC).strftime("%d %B %Y, %H:%M UTC")
        version = meta.get("version") or "1.0"
        assessor = meta.get("assessor") or "HEAVEN Autonomous Penetration-Testing Platform"

        inventory = _normalize_assets(assets) if assets else []
        dns_inv = _normalize_dns(dns_records) if dns_records else []
        has_api = self.has_api_findings(findings)
        has_iot = self.has_iot_findings(findings)
        has_ot = self.has_ot_findings(findings)
        sections = [
            self._styles(),
            self._toolbar(),
            self._cover(eng, overall, counts, len(findings), len(scope),
                        generated, version, confirmed_total, potential_total,
                        compliance_title),
            self._confidentiality(eng),
            self._doc_control(eng, assessor, version, generated, len(scope), len(findings), overall),
            self._toc(bool(inventory), has_api, has_iot, has_ot, bool(dns_inv),
                      has_content=any(
                          (f.get("vuln_type") or f.get("type") or "") in
                          ("directory_listing", "sensitive_file") for f in findings),
                      compliance_title=compliance_title),
            self._exec_summary(eng, counts, len(findings), overall, ordered,
                               len(scope), confirmed_counts, confirmed_total,
                               potential_total),
            self._scope_methodology(scope),
            self._inventory(inventory),
            self._content_discovery(findings),
            self._dns_enumeration(dns_inv),
            self._risk_methodology(),
            self._findings_summary(ordered),
            self._detailed_findings(ordered),
            self._owasp_coverage(findings),
        ]
        # API / IoT / OT engagements are scored against their own frameworks —
        # each shown only when the scan actually produced findings of that kind.
        if has_api:
            sections.append(self._owasp_api_coverage(findings))
        if has_iot:
            sections.append(self._owasp_iot_coverage(findings))
        if has_ot:
            sections.append(self._ot_ics_coverage(findings))
        # Compliance-framework control coverage (HIPAA / GDPR / PCI / …) — only
        # when the operator requested a specific framework.
        if fw is not None:
            sections.append(self._compliance_coverage(findings, fw))
        sections += [
            self._roadmap(ordered),
            self._appendix(),
            self._footer(),
        ]
        # Wrap every table in a horizontally-scrollable box so a wide table (long
        # target URLs, the coverage matrices) scrolls inside its own frame rather
        # than pushing the whole page sideways. One central pass covers every
        # section — Findings Summary, coverage matrices, inventory, DNS, meta.
        body = _wrap_tables("".join(sections[1:]))
        html_doc = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>Penetration Test Report · {_esc(eng)}</title>"
            + sections[0]
            + "</head><body>"
            + body
            + "</body></html>"
        )
        if output_path:
            Path(output_path).write_text(html_doc, encoding="utf-8")
        return html_doc

    # ── helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _overall_risk(counts: dict[str, int]) -> str:
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev):
                return SEVERITY_META[sev]["label"]
        return "Informational"

    @staticmethod
    def _styles() -> str:
        return """<style>
        :root{--brand:#4f46e5;--brand2:#12b981;--ink:#1a1f29;--muted:#5b6472;--line:#e3e7ee;--bg:#fff;}
        *{box-sizing:border-box;}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
             color:var(--ink);background:#f4f6f9;margin:0;line-height:1.55;font-size:14px;}
        .page{background:var(--bg);max-width:850px;margin:24px auto;padding:48px 56px;
              box-shadow:0 1px 4px rgba(0,0,0,.08);}
        h1,h2,h3{color:var(--ink);font-weight:700;line-height:1.25;}
        h2{font-size:20px;margin:0 0 16px;padding-bottom:8px;border-bottom:2px solid var(--brand);}
        h3{font-size:15px;margin:22px 0 6px;}
        p{margin:0 0 12px;} a{color:var(--brand);}
        /* Any wide table scrolls WITHIN its own box instead of spilling past the
           page — the report body never scrolls sideways. */
        .tablewrap{overflow-x:auto;max-width:100%;margin:8px 0 4px;-webkit-overflow-scrolling:touch;}
        .tablewrap>table{margin:0;}
        table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 4px;}
        th{background:#f0f3f8;text-align:left;padding:8px 10px;border:1px solid var(--line);
           font-weight:600;color:#33405a;overflow-wrap:anywhere;word-break:break-word;}
        td{padding:8px 10px;border:1px solid var(--line);vertical-align:top;
           overflow-wrap:anywhere;word-break:break-word;}
        .muted{color:var(--muted);} .small{font-size:12px;}
        .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;
              font-weight:700;color:#fff;letter-spacing:.02em;}
        /* Confirmation status: Confirmed (solid emerald) vs Potential (amber outline). */
        .confpill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:10.5px;
                  font-weight:700;letter-spacing:.02em;border:1px solid transparent;white-space:nowrap;}
        .conf-confirmed{background:#e7f7ef;color:#0f7a4d;border-color:#9fe0c1;}
        .conf-potential{background:#fdf3e0;color:#9a6a12;border-color:#f0d08a;}
        .kpis{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0;}
        .kpi{flex:1;min-width:110px;border:1px solid var(--line);border-radius:10px;
             padding:14px;text-align:center;background:#fcfdff;}
        .kpi .n{font-size:30px;font-weight:800;line-height:1;} .kpi .l{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
        .bar{height:14px;border-radius:7px;overflow:hidden;display:flex;border:1px solid var(--line);background:#fff;}
        .bar span{display:block;height:100%;}
        .legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;margin-top:8px;}
        .legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle;}
        .finding{border:1px solid var(--line);border-radius:10px;margin:16px 0;overflow:hidden;}
        .finding-head{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#fafbfd;border-bottom:1px solid var(--line);}
        .finding-head .id{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);}
        .finding-head .ttl{font-weight:700;font-size:15px;}
        .finding-body{padding:8px 16px 16px;}
        .meta{width:100%;font-size:12.5px;margin:6px 0 12px;}
        .meta td:first-child{width:150px;color:var(--muted);background:#fafbfd;font-weight:600;}
        pre{background:#0d1117;color:#d6deeb;padding:12px 14px;border-radius:8px;overflow-x:auto;
            font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;}
        .block-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;margin:14px 0 4px;}
        .cover{min-height:78vh;display:flex;flex-direction:column;justify-content:center;}
        .brandbar{display:flex;align-items:center;gap:14px;margin-bottom:34px;}
        .brandbar svg{flex-shrink:0;}
        .brandbar .bn{font-size:26px;font-weight:800;letter-spacing:.14em;color:var(--brand);line-height:1;}
        .brandbar .bt{font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:5px;}
        .classif{display:inline-block;border:1.5px solid #b00020;color:#b00020;font-weight:800;
                  font-size:12px;letter-spacing:.18em;padding:4px 12px;border-radius:4px;}
        .cover h1{font-size:40px;margin:24px 0 6px;letter-spacing:-.5px;}
        .cover .sub{font-size:17px;color:var(--muted);}
        .riskbadge{display:inline-block;margin-top:28px;padding:14px 26px;border-radius:12px;
                   color:#fff;font-weight:800;font-size:18px;letter-spacing:.04em;}
        .toc ol{margin:0;padding-left:22px;} .toc li{margin:5px 0;}
        .toc a{text-decoration:none;color:var(--ink);} .toc a:hover{color:var(--brand);}
        .note{background:#fff8e6;border:1px solid #f0d98c;border-radius:8px;padding:14px 16px;font-size:13px;}
        .toolbar{position:fixed;top:16px;right:16px;z-index:99;}
        .btn{background:var(--brand);color:#fff;border:0;border-radius:8px;padding:10px 16px;
             font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 2px 8px rgba(79,70,229,.35);}
        @media print{
          body{background:#fff;} .page{box-shadow:none;margin:0;max-width:none;padding:0;}
          .no-print{display:none!important;}
          .section{page-break-before:always;} .cover{page-break-after:always;min-height:90vh;}
          .finding,tr{page-break-inside:avoid;}
          @page{size:A4;margin:16mm 14mm;}
        }
        </style>"""

    @staticmethod
    def _toolbar() -> str:
        return ("<div class=\"toolbar no-print\">"
                "<button class=\"btn\" onclick=\"window.print()\">🖨 Print / Save as PDF</button>"
                "</div>")

    def _cover(self, eng: str, overall: str, counts: dict, total: int,
               scope_n: int, generated: str, version: str,
               confirmed_total: int = 0, potential_total: int = 0,
               compliance_title: str = "") -> str:
        col = next((m["color"] for m in SEVERITY_META.values()
                    if m["label"] == overall), _BRAND)
        # The headline reflects confirmed risk; potential (version-based /
        # unverified) findings are called out so nothing is hidden.
        pot_note = (f' &nbsp;·&nbsp; {potential_total} potential (unverified)'
                    if potential_total else "")
        compliance_line = (
            f'<div><strong style="color:var(--ink)">Compliance mapping:</strong> '
            f'{_esc(compliance_title)}</div>' if compliance_title else "")
        return f"""<div class="page"><div class="cover">
          <div class="brandbar">{_LOGO_SVG}
            <div><div class="bn">HEAVEN</div>
              <div class="bt">Autonomous Penetration-Testing Platform</div></div>
          </div>
          <div><span class="classif">CONFIDENTIAL</span></div>
          <h1>Penetration Test Report</h1>
          <div class="sub">{_esc(eng)}</div>
          <div class="riskbadge" style="background:{col}">Overall Risk: {_esc(overall)}</div>
          <div class="small muted" style="margin-top:8px">Overall risk is rated
            from confirmed findings; potential findings are verified separately.</div>
          <div style="margin-top:40px;color:var(--muted);font-size:13px;line-height:2">
            <div><strong style="color:var(--ink)">Findings:</strong> {total}
               &nbsp;·&nbsp; {counts['critical']} critical, {counts['high']} high,
               {counts['medium']} medium, {counts['low']} low</div>
            <div><strong style="color:var(--ink)">Confirmed vs potential:</strong>
               {confirmed_total} confirmed{pot_note}</div>
            <div><strong style="color:var(--ink)">Targets in scope:</strong> {scope_n}</div>
            {compliance_line}
            <div><strong style="color:var(--ink)">Report date:</strong> {_esc(generated)}</div>
            <div><strong style="color:var(--ink)">Version:</strong> {_esc(version)}</div>
            <div><strong style="color:var(--ink)">Prepared by:</strong> HEAVEN Autonomous Penetration-Testing Platform</div>
          </div>
        </div></div>"""

    def _confidentiality(self, eng: str) -> str:
        return f"""<div class="page section"><h2>Confidentiality Notice</h2>
          <p class="note">This document contains confidential and proprietary information about the
          security posture of <strong>{_esc(eng)}</strong>. It is intended solely for the named
          recipient and authorised stakeholders. It details vulnerabilities that could be exploited
          to compromise systems and data; unauthorised disclosure, copying, or distribution is
          strictly prohibited and may expose the organisation to significant risk.</p>
          <p class="small muted">Distribute on a strict need-to-know basis and store in accordance with
          your organisation's data-classification policy. Destroy securely when no longer required.</p>
        </div>"""

    def _doc_control(self, eng, assessor, version, generated, scope_n, total, overall) -> str:
        return f"""<div class="page section"><h2>Document Control</h2>
          <table>
            <tr><th style="width:200px">Field</th><th>Detail</th></tr>
            <tr><td>Engagement</td><td>{_esc(eng)}</td></tr>
            <tr><td>Assessor</td><td>{_esc(assessor)}</td></tr>
            <tr><td>Report version</td><td>{_esc(version)}</td></tr>
            <tr><td>Date generated</td><td>{_esc(generated)}</td></tr>
            <tr><td>Targets in scope</td><td>{scope_n}</td></tr>
            <tr><td>Total findings</td><td>{total}</td></tr>
            <tr><td>Overall risk rating</td><td><strong>{_esc(overall)}</strong></td></tr>
            <tr><td>Classification</td><td>CONFIDENTIAL</td></tr>
          </table>
          <h3>Revision History</h3>
          <table>
            <tr><th>Version</th><th>Date</th><th>Author</th><th>Description</th></tr>
            <tr><td>{_esc(version)}</td><td>{_esc(generated)}</td><td>HEAVEN</td>
                <td>Automated assessment report generated from engagement findings.</td></tr>
          </table>
        </div>"""

    @staticmethod
    def _toc(has_inventory: bool = False, has_api: bool = False,
             has_iot: bool = False, has_ot: bool = False,
             has_dns: bool = False, has_content: bool = False,
             compliance_title: str = "") -> str:
        items = [
            ("exec", "Executive Summary"),
            ("scope", "Scope & Methodology"),
        ]
        if has_inventory:
            items.append(("inventory", "Host & Service Inventory"))
        if has_content:
            items.append(("content-discovery", "Content Discovery"))
        if has_dns:
            items.append(("dns", "DNS Enumeration"))
        items += [
            ("risk", "Risk Rating Methodology"),
            ("summary", "Findings Summary"),
            ("details", "Detailed Findings"),
            ("owasp", "OWASP Top 10 Coverage"),
        ]
        if has_api:
            items.append(("owasp-api", "OWASP API Security Top 10 (2023) Coverage"))
        if has_iot:
            items.append(("owasp-iot", "OWASP IoT Top 10 (2018) Coverage"))
        if has_ot:
            items.append(("ot-ics", "OT / ICS Security Coverage (IEC 62443)"))
        if compliance_title:
            items.append(("compliance", f"{compliance_title} Compliance Mapping"))
        items += [
            ("roadmap", "Remediation Roadmap"),
            ("appendix", "Appendix"),
        ]
        lis = "".join(f'<li><a href="#{i}">{_esc(t)}</a></li>' for i, t in items)
        return f'<div class="page section"><h2>Table of Contents</h2><div class="toc"><ol>{lis}</ol></div></div>'

    def _exec_summary(self, eng, counts, total, overall, ordered, scope_n,
                      confirmed_counts=None, confirmed_total=0,
                      potential_total=0) -> str:
        # Posture (and Overall Risk) is driven by *confirmed* findings — those
        # proven by direct observation or active validation — so an
        # unauthenticated, version-based match that can't be confirmed from the
        # outside never drives the headline. Falls back to the full counts when a
        # caller doesn't supply the confirmed breakdown.
        cc = confirmed_counts if confirmed_counts is not None else counts
        crit, high = cc["critical"], cc["high"]
        if crit or high:
            posture = (f"The assessment confirmed <strong>{crit} critical</strong> and "
                       f"<strong>{high} high</strong>-severity issues that require prompt "
                       "remediation. Exploitation of these could lead to unauthorised access, "
                       "data exposure, or full system compromise.")
        elif cc["medium"]:
            posture = ("No confirmed critical or high-severity issues were identified. The "
                       "medium-severity findings below should be remediated to reduce residual risk.")
        else:
            posture = ("No confirmed high-impact vulnerabilities were identified during this "
                       "assessment. The environment demonstrated a strong security posture.")
        if potential_total:
            posture += (f" A further <strong>{potential_total}</strong> potential "
                        "finding(s), inferred from service version banners and not "
                        "confirmed from the outside, are listed separately; verify the "
                        "running versions (authenticated check or vendor advisory) before "
                        "treating them as present.")

        # severity distribution bar
        bar = ""
        legend = ""
        for sev, m in SEVERITY_META.items():
            n = counts[sev]
            if total:
                bar += f'<span style="background:{m["color"]};width:{(n/total)*100:.1f}%"></span>'
            legend += (f'<span><i style="background:{m["color"]}"></i>'
                       f'{m["label"]}: <strong>{n}</strong></span>')

        top = ordered[:5]
        top_rows = "".join(
            f'<tr><td><span class="pill" style="background:{SEVERITY_META[_sev_of(f)]["color"]}">'
            f'{SEVERITY_META[_sev_of(f)]["label"]}</span></td>'
            f'<td>{_conf_pill(f)}</td>'
            f'<td>{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</td>'
            f'<td class="small">{_esc(f.get("target") or "—")}</td></tr>'
            for f in top
        ) or '<tr><td colspan="4" class="muted">No findings.</td></tr>'

        return f"""<div class="page section" id="exec"><h2>Executive Summary</h2>
          <p>This report presents the results of a penetration test of <strong>{_esc(eng)}</strong>,
          covering <strong>{scope_n}</strong> in-scope target(s). A total of <strong>{total}</strong>
          finding(s) were identified, yielding an overall risk rating of
          <strong>{_esc(overall)}</strong>. {posture}</p>
          <div class="kpis">
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['critical']['color']}">{counts['critical']}</div><div class="l">Critical</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['high']['color']}">{counts['high']}</div><div class="l">High</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['medium']['color']}">{counts['medium']}</div><div class="l">Medium</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['low']['color']}">{counts['low']}</div><div class="l">Low</div></div>
            <div class="kpi"><div class="n" style="color:{SEVERITY_META['info']['color']}">{counts['info']}</div><div class="l">Info</div></div>
          </div>
          <h3>Severity Distribution</h3>
          <div class="bar">{bar}</div>
          <div class="legend">{legend}</div>
          <p class="small muted" style="margin-top:10px">Of these, <strong>{confirmed_total}</strong>
            finding(s) are <span class="confpill conf-confirmed">Confirmed</span> (proven by direct
            observation or active validation) and <strong>{potential_total}</strong> are
            <span class="confpill conf-potential">Potential</span> (inferred from a service version
            banner — the "backport" caveat applies — and not confirmed from the outside). The Overall
            Risk rating above counts confirmed findings only.</p>
          <h3>Key Findings</h3>
          <table><tr><th style="width:90px">Severity</th><th style="width:88px">Confirmation</th>
            <th>Finding</th><th>Target</th></tr>{top_rows}</table>
        </div>"""

    def _scope_methodology(self, scope: list[str]) -> str:
        if scope:
            rows = "".join(f'<tr><td class="small">{i+1}</td><td>{_esc(t)}</td></tr>'
                           for i, t in enumerate(scope))
            scope_tbl = f'<table><tr><th style="width:50px">#</th><th>Target</th></tr>{rows}</table>'
        else:
            scope_tbl = '<p class="muted">No explicit scope recorded; findings list their own targets.</p>'
        return f"""<div class="page section" id="scope"><h2>Scope &amp; Methodology</h2>
          <h3>In-Scope Targets</h3>
          {scope_tbl}
          <h3>Testing Approach</h3>
          <p>Testing followed a structured methodology aligned with industry standards. Activities
          progressed through reconnaissance, enumeration, vulnerability identification, exploitation
          (where safe and authorised), and impact analysis. Each finding was validated to reduce false
          positives and rated using the CVSS-based scale described in the next section.</p>
          <h3>Standards &amp; Frameworks Referenced</h3>
          <table>
            <tr><th style="width:230px">Framework</th><th>Use</th></tr>
            <tr><td>OWASP Top 10 (2025)</td><td>Web application risk categorisation</td></tr>
            <tr><td>PTES</td><td>Penetration Testing Execution Standard phases</td></tr>
            <tr><td>NIST SP 800-115</td><td>Technical assessment methodology</td></tr>
            <tr><td>MITRE ATT&amp;CK</td><td>Adversary technique mapping (where applicable)</td></tr>
            <tr><td>CVSS v3.1 / EPSS / CISA KEV</td><td>Severity, exploit-likelihood &amp; known-exploited enrichment</td></tr>
          </table>
        </div>"""

    @staticmethod
    def _inventory(inventory: list[dict]) -> str:
        """Host & service inventory — open ports, service versions and OS.

        ``inventory`` is already normalised (see inventory.normalize_assets).
        Renders nothing when empty so non-network engagements skip the section.
        """
        if not inventory:
            return ""
        tot = _inventory_totals(inventory)
        host_blocks: list[str] = []
        for h in inventory:
            os_txt = h.get("os_label") or "OS not determined"
            ports = h.get("ports") or []
            if ports:
                rows = "".join(
                    f'<tr><td class="small">{_esc(p.get("port"))}</td>'
                    f'<td class="small">{_esc(p.get("protocol") or "tcp")}</td>'
                    f'<td>{_esc(p.get("service") or "—")}</td>'
                    f'<td>{_esc(p.get("service_version") or "—")}</td>'
                    f'<td class="small">{_esc(p.get("cpe") or "—")}</td></tr>'
                    for p in ports
                )
                tbl = ('<table><tr><th style="width:64px">Port</th>'
                       '<th style="width:60px">Proto</th><th style="width:120px">Service</th>'
                       f'<th>Version</th><th>CPE</th></tr>{rows}</table>')
            else:
                tbl = '<p class="muted small">No open ports observed.</p>'
            meta_bits: list[str] = []
            ip = h.get("ip") or ""
            if ip and _looks_like_ip(ip) and ip != h.get("host"):
                meta_bits.append(f'IP: {_esc(ip)}')
            if _device_name_label(h):
                meta_bits.append(f'Device: {_esc(_device_name_label(h))}')
            if _device_type_label(h):
                meta_bits.append(f'Type: {_esc(_device_type_label(h))}')
            if _mac_label(h):
                meta_bits.append(f'MAC: {_esc(_mac_label(h))}')
            meta_html = (f'<p class="muted small">{" &middot; ".join(meta_bits)}</p>'
                         if meta_bits else "")
            host_blocks.append(
                f'<h3>{_esc(h.get("host"))} '
                f'<span class="muted small">— {_esc(os_txt)}</span></h3>{meta_html}{tbl}'
            )
        return f"""<div class="page section" id="inventory"><h2>Host &amp; Service Inventory</h2>
          <p>The network scan mapped <strong>{tot['hosts']}</strong> host(s) exposing
          <strong>{tot['open_ports']}</strong> open port(s) across
          <strong>{tot['distinct_services']}</strong> distinct service(s). Ports, service
          versions and operating systems are reported exactly as observed by the scanner.
          An OS marked <em>(heuristic — unconfirmed)</em> was inferred from a TTL value, not a
          full stack fingerprint, and should be treated as indicative only. Where the scan
          observed them, a host's device name, device type and MAC address are shown; a MAC
          address appears only for a host on the same local segment scanned with sufficient
          privileges (it is an ARP fact, so routed/remote hosts have none).</p>
          {''.join(host_blocks)}
        </div>"""

    @staticmethod
    def _content_discovery(findings: list[dict]) -> str:
        """Content Discovery — every interesting path directory brute-forcing found.

        Consolidates the ``directory_listing`` / ``sensitive_file`` findings (the
        200 / 3xx / 401 / 403 / … hits from the dir fuzzer) into one table — Path,
        Status, Severity, URL — so an operator sees all discovered paths together
        instead of scattered through the detailed findings. Renders nothing when
        no directory hits exist. The findings themselves still appear (and are
        scored) in the detailed section; this is an at-a-glance index.
        """
        _rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        hits = [f for f in findings
                if (f.get("vuln_type") or f.get("type") or "") in
                ("directory_listing", "sensitive_file")]
        if not hits:
            return ""
        hits.sort(key=lambda f: (
            -_rank.get(str(f.get("severity") or "info").lower(), 0),
            int((f.get("evidence") or {}).get("status_code") or 0),
        ))
        rows: list[str] = []
        for f in hits:
            ev = f.get("evidence") or {}
            status = ev.get("status_code") or "—"
            path = ev.get("path") or f.get("target") or "—"
            m = SEVERITY_META[_sev_of(f)]
            url = f.get("target") or ""
            loc = ev.get("location")
            url_cell = _esc(url)
            if loc:
                url_cell += f' <span class="muted small">&rarr; {_esc(loc)}</span>'
            rows.append(
                f'<tr><td class="small">{_esc(path)}</td>'
                f'<td class="small">{_esc(status)}</td>'
                f'<td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                f'<td class="small">{url_cell}</td></tr>'
            )
        return f"""<div class="page section" id="content-discovery">
          <h2>Content Discovery</h2>
          <p>Directory and file brute-forcing discovered
          <strong>{len(hits)}</strong> interesting path(s) — admin panels, exposed
          files, backups, API docs and other resources returning a live status
          code (200 / 3xx / 401 / 403 …). Each is listed below and detailed, with
          remediation, in the Findings section.</p>
          <table><tr><th>Path</th><th style="width:70px">Status</th>
          <th style="width:90px">Severity</th><th>URL</th></tr>
          {''.join(rows)}</table>
        </div>"""

    @staticmethod
    def _dns_enumeration(dns_inv: list[dict]) -> str:
        """DNS enumeration — records + resolved subdomains per domain.

        ``dns_inv`` is already normalised (see dns_inventory.normalize_dns).
        Renders nothing when empty so non-DNS engagements skip the section.
        """
        if not dns_inv:
            return ""
        tot = _dns_totals(dns_inv)
        blocks: list[str] = []
        for n in dns_inv:
            recs = n.get("records") or {}
            rrows = "".join(
                f'<tr><td class="small">{_esc(rt)}</td><td>{_esc(val)}</td></tr>'
                for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")
                for val in recs.get(rt, [])
            )
            rec_tbl = (f'<table><tr><th style="width:64px">Type</th><th>Record</th></tr>'
                       f'{rrows}</table>' if rrows
                       else '<p class="muted small">No records resolved.</p>')

            subs = n.get("subdomains") or []
            if subs:
                srows = "".join(
                    f'<tr><td>{_esc(s.get("name"))}</td>'
                    f'<td class="small">{_esc(", ".join(s.get("addresses") or []) or "—")}</td></tr>'
                    for s in subs
                )
                sub_tbl = (f'<h4 class="small">Subdomains discovered ({len(subs)})</h4>'
                           f'<table><tr><th>Subdomain</th><th>Addresses</th></tr>{srows}</table>')
            else:
                sub_tbl = ""

            dnssec = "enabled" if (n.get("dnssec") or {}).get("enabled") else "not detected"
            wild = " · Wildcard DNS present" if n.get("wildcard") else ""
            blocks.append(
                f'<h3>{_esc(n.get("domain"))} '
                f'<span class="muted small">— DNSSEC: {dnssec}{_esc(wild)}</span></h3>'
                f'{rec_tbl}{sub_tbl}'
            )
        return f"""<div class="page section" id="dns"><h2>DNS Enumeration</h2>
          <p>DNS reconnaissance mapped <strong>{tot['domains']}</strong> domain(s) exposing
          <strong>{tot['records']}</strong> DNS record(s), <strong>{tot['subdomains']}</strong>
          resolved subdomain(s) and <strong>{tot['mail_servers']}</strong> mail server(s).
          Records are reported exactly as returned by authoritative DNS; a subdomain is
          listed only because it actually resolved.</p>
          {''.join(blocks)}
        </div>"""

    @staticmethod
    def _risk_methodology() -> str:
        rows = ""
        for sev, m in SEVERITY_META.items():
            rows += (f'<tr><td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td>{m["cvss"]}</td><td>{m["sla"]}</td></tr>')
        return f"""<div class="page section" id="risk"><h2>Risk Rating Methodology</h2>
          <p>Each finding is assigned a severity derived from its CVSS v3.1 base score and adjusted for
          real-world exploitability (EPSS) and whether the issue is on the CISA Known Exploited
          Vulnerabilities catalog. Recommended remediation timeframes (SLAs) are guidance and should be
          tailored to the organisation's risk appetite.</p>
          <table>
            <tr><th style="width:130px">Severity</th><th>CVSS range</th><th>Recommended remediation SLA</th></tr>
            {rows}
          </table>
        </div>"""

    def _findings_summary(self, ordered: list[dict]) -> str:
        if not ordered:
            return '<div class="page section" id="summary"><h2>Findings Summary</h2><p class="muted">No findings recorded.</p></div>'
        rows = ""
        for i, f in enumerate(ordered, 1):
            sev = _sev_of(f)
            m = SEVERITY_META[sev]
            cvss = self._finding_cvss(f)
            ctx = self._finding_contextual_cvss(f)
            rows += (f'<tr><td class="small">{i}</td>'
                     f'<td><a href="#f{i}">{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</a></td>'
                     f'<td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td>{_conf_pill(f)}</td>'
                     f'<td class="small">{_esc(cvss)}</td>'
                     f'<td class="small">{_esc(ctx)}</td>'
                     f'<td class="small">{_esc(f.get("target") or "—")}</td></tr>')
        return f"""<div class="page section" id="summary"><h2>Findings Summary</h2>
          <p class="muted small">The <b>Confirmation</b> column separates
          <span class="confpill conf-confirmed">Confirmed</span> findings (proven by direct
          observation or active validation) from <span class="confpill conf-potential">Potential</span>
          ones (inferred from a service version banner and not confirmed from the outside — vendors
          routinely backport fixes without bumping the banner). The <b>CVSS</b> column is the
          standards base score for the finding's weakness class — reduced for a detection the scanner
          flags as unconfirmed or low-confidence, so it never over-states a heuristic "indicator".
          <b>Contextual</b> is the per-finding CVSS Temporal + Environmental score, adjusted for this
          finding's exploit maturity (EPSS / public exploit / CISA KEV), detection confidence and the
          asset's criticality &amp; exposure. Severity always matches the score band.</p>
          <table>
            <tr><th style="width:40px">#</th><th>Finding</th><th style="width:90px">Severity</th>
                <th style="width:88px">Confirmation</th>
                <th style="width:56px">CVSS</th><th style="width:74px">Contextual</th>
                <th>Target</th></tr>
            {rows}
          </table>
        </div>"""

    def _detailed_findings(self, ordered: list[dict]) -> str:
        if not ordered:
            return '<div class="page section" id="details"><h2>Detailed Findings</h2><p class="muted">No findings recorded.</p></div>'
        cards = ""
        for i, f in enumerate(ordered, 1):
            cards += self._finding_card(i, f)
        return f'<div class="page section" id="details"><h2>Detailed Findings</h2>{cards}</div>'

    def _finding_card(self, idx: int, f: dict) -> str:
        sev = _sev_of(f)
        m = SEVERITY_META[sev]
        ev = f.get("evidence") or {}
        title = f.get("title") or f.get("vuln_type") or "Finding"
        cvss = self._finding_cvss(f)
        contextual = self._finding_contextual_cvss(f)

        # Classification: an IoT/OT finding is labelled against its own
        # framework (OWASP IoT Top 10 / IEC 62443), a web finding against the
        # OWASP Top 10 (2025).
        if _fw.has_iot_ot_tag(f):
            owasp_label, owasp = ("OWASP IoT Top 10" if f.get("owasp_iot")
                                  else "IEC 62443"), _fw.framework_label(f)
        else:
            owasp_label = "OWASP"
            # Upgrade a legacy 2021 tag stored on the finding to its 2025 label.
            owasp = _fw.normalize_owasp(f.get("owasp") or "") or self._owasp_for(f.get("vuln_type", ""))
        meta_rows = [
            ("Target", f.get("target") or "—", False),
            ("Severity", m["label"], False),
            ("Confirmation", _conf_pill(f), True),
            ("CVSS base (class)", cvss, False),
            ("Contextual CVSS", contextual, False),
            ("Risk score", f.get("risk_score") if f.get("risk_score") is not None else "—", False),
            ("Confidence", f"{float(f.get('confidence', 0)):.0%}" if f.get("confidence") is not None else "—", False),
            ("CWE", f.get("cwe") or "—", False),
            (owasp_label, owasp or "—", False),
            # CVE links straight to the live NVD record — dynamic, not a bare string.
            ("CVE", self._cve_links(f), True),
            ("MITRE ATT&CK", f.get("mitre_technique") or "—", False),
            ("CVSS vector", f.get("cvss_vector") or "—", False),
            ("Status", (f.get("status") or "open").title(), False),
        ]
        meta_html = "".join(
            f"<tr><td>{_esc(k)}</td><td>{v if raw else _esc(v)}</td></tr>"
            for k, v, raw in meta_rows
        )

        def block(label: str, text: Any) -> str:
            if not text:
                return ""
            return f'<div class="block-label">{_esc(label)}</div><p>{_esc(text)}</p>'

        description = ev.get("description") or f.get("description") or ""
        impact = ev.get("impact") or ""
        remediation = ev.get("remediation") or f.get("remediation") or ""
        # Numbered remediation steps render one-per-line (not one run-on paragraph).
        rem_html = (f'<div class="block-label">Remediation</div>'
                    f'<p>{self._steps_html(remediation)}</p>') if remediation else ""

        # Evidence / PoC — EVERY finding gets at least one proof block (explicit
        # artefacts when present, else synthesised honest evidence), so no finding
        # in the report is left without a "how this was determined".
        poc_parts = []
        for label, is_code, text in self._proof_blocks(f):
            if is_code:
                poc_parts.append(
                    f'<div class="block-label">{_esc(label)}</div><pre>{_esc(text)}</pre>')
            else:
                poc_parts.append(
                    f'<div class="block-label">{_esc(label)}</div>'
                    f'<p>{_esc(text).replace(chr(10), "<br>")}</p>')
        poc_html = "".join(poc_parts)

        # Candidate-CVE awareness table (version-undetermined "potential" finding):
        # every CVE known for the product with its published score and the exact
        # affected-version range it REQUIRES — full awareness, none asserted present.
        candidates_html = ""
        cand = ev.get("candidate_details") or []
        if cand:
            rows = "".join(
                "<tr>"
                f"<td><a href=\"https://nvd.nist.gov/vuln/detail/{_esc(str(d.get('cve','')))}\">"
                f"{_esc(str(d.get('cve','')))}</a></td>"
                f"<td>{_esc(_fmt_cvss(d.get('cvss')))}</td>"
                f"<td>{_esc(str(d.get('severity','')).title())}</td>"
                f"<td>{_esc(str(d.get('affected_versions','') or '—'))}</td>"
                f"<td>{'public' if d.get('exploit_available') else '—'}</td>"
                f"<td>{_esc(str(d.get('title','')))}</td>"
                "</tr>"
                for d in cand
            )
            hint = ev.get("how_to_confirm")
            hint_html = (f'<p class="small muted">How to confirm the version: '
                         f'{_esc(hint)}</p>') if hint else ""
            candidates_html = (
                '<div class="block-label">Candidate CVEs '
                '(unverified, version not confirmed)</div>'
                '<div class="tablewrap"><table><thead><tr>'
                '<th>CVE</th><th>CVSS</th><th>Severity</th>'
                '<th>Affected versions</th><th>Exploit</th><th>Description</th>'
                f'</tr></thead><tbody>{rows}</tbody></table></div>{hint_html}'
            )

        # References
        refs = ev.get("references") or f.get("references") or []
        refs_html = ""
        if refs:
            lis = "".join(f'<li><a href="{_esc(r)}">{_esc(r)}</a></li>' for r in refs)
            refs_html = f'<div class="block-label">References</div><ul class="small">{lis}</ul>'

        notes = f.get("operator_notes") or ""

        return f"""<div class="finding" id="f{idx}">
          <div class="finding-head">
            <span class="pill" style="background:{m['color']}">{m['label']}</span>
            <span class="id">#{idx}</span>
            <span class="ttl">{_esc(title)}</span>
          </div>
          <div class="finding-body">
            <table class="meta">{meta_html}</table>
            {block("Description", description)}
            {block("Impact", impact)}
            {poc_html}
            {candidates_html}
            {rem_html}
            {refs_html}
            {block("Assessor Notes", notes)}
          </div>
        </div>"""

    def _proof_blocks(self, f: dict) -> list[tuple[str, bool, str]]:
        """Ordered proof/evidence blocks for one finding as ``(label, is_code,
        text)`` — GUARANTEED non-empty.

        Every finding in the report must show how it was determined, not just the
        ones that carry a full HTTP transaction. Precedence:
          1. explicit technical artefacts (payload / request / response / curl /
             proof / poc) shown verbatim — the strongest evidence;
          2. otherwise a synthesised, honest set: an ``Observed`` summary of the
             non-HTTP evidence fields, the detection rationale, and a read-only
             command that re-observes the finding (never a fabricated curl);
          3. an absolute one-line fallback, so NO finding is proof-less.
        Shared by the HTML and PDF reporters so both stay identical.
        """
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        blocks: list[tuple[str, bool, str]] = []
        for key, label in (("payload", "Payload"), ("request", "HTTP Request"),
                           ("response", "HTTP Response"),
                           ("curl", "Reproduction (curl)"),
                           ("proof", "Proof"), ("poc", "Proof of Concept")):
            val = ev.get(key)
            if val:
                snippet = str(val)
                if len(snippet) > 4000:
                    snippet = snippet[:4000] + "\n… (truncated)"
                blocks.append((label, True, snippet))
        if blocks:
            return blocks

        from heaven.devsecops.evidence import (  # local import avoids a cycle
            _HTTP_EVIDENCE_KEYS,
            _evidence_value,
            build_repro_command,
        )
        _skip = _HTTP_EVIDENCE_KEYS | {
            "candidate_details", "how_to_confirm", "signals", "reasons",
            "fp_check_reasons", "candidate_cves", "candidate_cve_count",
            "highest_candidate_cvss", "verification",
        }
        observed = [
            f"{k.replace('_', ' ')}: {_evidence_value(v)}"
            for k, v in (ev or {}).items()
            if k not in _skip and v not in (None, "", [], {})
        ]
        if observed:
            blocks.append(("Observed", True, "\n".join(observed[:12])))
        reasons = (f.get("reasons") or ev.get("reasons")
                   or f.get("fp_check_reasons") or [])
        if reasons:
            blocks.append(("Detection Rationale", False,
                           "\n".join(f"• {r}" for r in reasons[:8])))
        cmd, _note = build_repro_command(
            f.get("vuln_type") or "", f.get("target") or "", ev)
        if cmd:
            blocks.append(("Reproduce (read-only)", True, cmd))
        if not blocks:
            vt = (f.get("vuln_type") or "issue").replace("_", " ")
            tgt = f.get("target") or "the target"
            blocks.append((
                "Evidence", False,
                f"Identified by HEAVEN's {vt} check against {tgt}. See the "
                "description, classification and references above; this finding "
                "class has no single-command reproduction."))
        return blocks

    def _finding_cvss(self, f: dict) -> str:
        """Best per-finding CVSS base score to display (1-dp string), or '—'.

        Genuinely per-finding — not a flat severity default. Precedence, most
        authoritative first:
          1. a real published base score carried on the finding (NVD / OSV / CVE);
          2. the KB 'typical' base score curated for the finding's class;
          3. the CVSS v3.1 base score computed from the class's curated vector;
          4. the base score computed from the finding's own vector;
          5. the ML-predicted score (severity-anchored — last numeric resort);
          6. '—' when nothing scoreable exists.
        This means a CVE finding shows its true NVD score, and two different
        vulnerability classes no longer collapse to the same severity constant.
        """
        from heaven.utils import cvss as _cvss

        # 1-4. the one authoritative per-finding resolver (published CVE/NVD/OSV
        # score → KB class typical → class-vector base score → the finding's own
        # vector) — genuinely per-finding, never a flat per-severity constant.
        s = _cvss.objective_base_score(f)
        if s > 0:
            return f"{s:.1f}"
        # 5. the ML-predicted score (severity-anchored) — a number beats nothing
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        for src in (f, ev):
            try:
                v = float(src.get("predicted_cvss_score"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if 0.0 < v <= 10.0:
                return f"{v:.1f}"
        return "—"

    def _finding_contextual_cvss(self, f: dict) -> str:
        """Per-finding CVSS **contextual** score (Temporal + Environmental).

        Genuinely dynamic and instance-specific — unlike the class-level base
        score, this folds in the finding's own real signals (exploit maturity
        from EPSS / public-exploit / KEV, the detector's confidence, and the
        asset's criticality + exposure), so two findings of the *same class*
        differ when their evidence differs. Degrades to the base score when a
        finding carries no such signals. Returns a 1-dp string, or '—'.
        """
        from heaven.utils import cvss as _cvss
        s = _cvss.contextual_score(f)
        return f"{s:.1f}" if s > 0 else "—"

    @staticmethod
    def _steps_html(text: Any) -> str:
        """Render a numbered / multi-step remediation with each step on its own
        line. Handles both newline-separated strings (already the format
        ``component_remediation`` emits) and legacy inline ``1. … 2. …`` text, so
        the fix reads as a checklist rather than one confusing paragraph."""
        import re
        s = str(text or "").strip()
        if not s:
            return ""
        # Inline-numbered text → break before each 'N. ' step marker. The
        # look-ahead won't fire on version numbers like '9.9' (no space after
        # the dot) or 'CVE-2024-6387'.
        if "\n" not in s:
            s = re.sub(r"\s+(?=\d{1,2}\.\s)", "\n", s)
        # Break before trailing verify / reference / exploit-warning markers too.
        s = re.sub(r"\s+(?=(?:Verify:|Reference:|⚠|■))", "\n", s)
        lines = [ln.strip() for ln in s.split("\n") if ln.strip()]
        return "<br>".join(_esc(ln) for ln in lines)

    def _owasp_for(self, vuln_type: str) -> str:
        vt = (vuln_type or "").lower()
        for key, (cid, cn) in self.OWASP_MAP.items():
            if key in vt:
                return f"{cid} {cn}"
        return ""

    @staticmethod
    def _cve_links(f: dict) -> str:
        """Render a finding's CVE(s) as links to the live NVD record.

        Only strings matching the strict CVE pattern are emitted, so injecting
        the anchor as raw (un-escaped) HTML is safe.
        """
        import re
        raw = str(f.get("cve_id") or f.get("cve") or "")
        cves: list[str] = []
        seen: set[str] = set()
        for c in re.findall(r"CVE-\d{4}-\d{4,}", raw, re.IGNORECASE):
            cu = c.upper()
            if cu not in seen:
                seen.add(cu)
                cves.append(cu)
        if not cves:
            return "—"
        return ", ".join(
            f'<a href="https://nvd.nist.gov/vuln/detail/{c}" target="_blank" '
            f'rel="noopener noreferrer">{c}</a>'
            for c in cves
        )

    def _owasp_category_id(self, f: dict) -> str:
        """The OWASP-2025 control id for one finding, e.g. ``A05:2025``.

        Prefers the category ``vuln_kb`` already enriched onto the finding
        (``owasp`` field) — upgrading any legacy 2021 tag to its 2025 id via the
        crosswalk — so the report agrees with the per-finding detail view. Falls
        back to a keyword match on vuln_type/title. '' if none.
        """
        # IoT/OT findings are scored against their own frameworks (OWASP IoT Top
        # 10 / IEC 62443) — never bucket them into the web OWASP-2025 matrix.
        if _fw.has_iot_ot_tag(f):
            return ""
        # API findings are scored against the OWASP API Security Top 10 (2023);
        # keep them out of the web (2025) matrix so nothing is double-counted.
        if f.get("owasp_api"):
            return ""
        raw = str(f.get("owasp") or f.get("owasp_category") or "").strip()
        cid = _fw.owasp_2025_id(raw)  # upgrades a legacy 2021 tag to its 2025 id
        if cid:
            return cid
        hay = f"{f.get('vuln_type', '')} {f.get('type', '')} {f.get('title', '')}".lower()
        for key, (cid, _cn) in self.OWASP_MAP.items():
            if key in hay:
                return cid
        return ""

    def _owasp_coverage(self, findings: list[dict]) -> str:
        # Bucket each finding under its OWASP category — dynamically, from the
        # actual finding set (its enriched category first, keyword fallback
        # second) so every real finding lands in the matrix.
        buckets: dict[str, list[dict]] = {cid: [] for cid, _ in self.OWASP_2025}
        for f in findings:
            cid = self._owasp_category_id(f)
            if cid in buckets:
                buckets[cid].append(f)

        covered = sum(1 for cid, _ in self.OWASP_2025 if buckets[cid])
        rows = ""
        for cid, cn in self.OWASP_2025:
            hits = buckets[cid]
            n = len(hits)
            status = "Findings present" if hits else "Not observed"
            color = "#b00020" if hits else "#1a7f37"
            # Link the category to the concrete findings that landed in it.
            examples = ""
            if hits:
                worst = sorted(hits, key=lambda x: SEVERITY_META.get(
                    _sev_of(x), {}).get("order", 4))[:4]
                items = "".join(
                    f"<li>{_esc(h.get('title') or h.get('vuln_type') or 'Finding')}"
                    f" <span class='small muted'>({_esc(_sev_of(h))}"
                    f"{' · ' + _esc(str(h.get('target'))) if h.get('target') else ''})</span></li>"
                    for h in worst)
                more = f"<li class='small muted'>+{n - len(worst)} more…</li>" if n > len(worst) else ""
                examples = f"<ul class='small' style='margin:4px 0 0 16px'>{items}{more}</ul>"
            rows += (f'<tr><td class="small">{_esc(cid)}</td>'
                     f'<td>{_esc(cn)}{examples}</td>'
                     f'<td style="color:{color};font-weight:600">{status}</td>'
                     f'<td class="small">{n}</td></tr>')
        return f"""<div class="page section" id="owasp"><h2>OWASP Top 10 (2025) Coverage</h2>
          <p class="small muted">Every identified finding mapped to its OWASP Top 10 (2025) risk
          category — {covered} of 10 categories have findings in this engagement. Categories marked
          <em>Not observed</em> had no matching finding (either tested-clean or out of this scan's scope).</p>
          <table>
            <tr><th style="width:90px">Control</th><th>Category &amp; findings</th><th style="width:130px">Status</th><th style="width:70px">Count</th></tr>
            {rows}
          </table>
        </div>"""

    def _framework_rows(self, categories, bucket_fn, findings) -> tuple[str, int]:
        """Shared matrix body: bucket findings by category id, render one row
        each (present/not-observed + linked example findings). Returns
        ``(rows_html, covered_count)``."""
        buckets: dict[str, list[dict]] = {cid: [] for cid, _ in categories}
        for f in findings:
            cid = bucket_fn(f)
            if cid in buckets:
                buckets[cid].append(f)
        covered = sum(1 for cid, _ in categories if buckets[cid])
        rows = ""
        for cid, cn in categories:
            hits = buckets[cid]
            n = len(hits)
            status = "Findings present" if hits else "Not observed"
            color = "#b00020" if hits else "#1a7f37"
            examples = ""
            if hits:
                worst = sorted(hits, key=lambda x: SEVERITY_META.get(
                    _sev_of(x), {}).get("order", 4))[:4]
                items = "".join(
                    f"<li>{_esc(h.get('title') or h.get('vuln_type') or 'Finding')}"
                    f" <span class='small muted'>({_esc(_sev_of(h))}"
                    f"{' · ' + _esc(str(h.get('target'))) if h.get('target') else ''})</span></li>"
                    for h in worst)
                more = f"<li class='small muted'>+{n - len(worst)} more…</li>" if n > len(worst) else ""
                examples = f"<ul class='small' style='margin:4px 0 0 16px'>{items}{more}</ul>"
            rows += (f'<tr><td class="small">{_esc(cid)}</td>'
                     f'<td>{_esc(cn)}{examples}</td>'
                     f'<td style="color:{color};font-weight:600">{status}</td>'
                     f'<td class="small">{n}</td></tr>')
        return rows, covered

    @staticmethod
    def has_iot_findings(findings: list[dict]) -> bool:
        return any(f.get("owasp_iot") for f in findings)

    @staticmethod
    def has_ot_findings(findings: list[dict]) -> bool:
        return any(f.get("iec62443") for f in findings)

    @staticmethod
    def has_api_findings(findings: list[dict]) -> bool:
        return any(f.get("owasp_api") for f in findings)

    @staticmethod
    def _api_category_id(f: dict) -> str:
        """The OWASP API Top 10 (2023) id for a finding (e.g. ``API1``), or ''."""
        import re
        m = re.match(r"\s*(API\d{1,2})", str(f.get("owasp_api") or ""))
        return m.group(1) if m else ""

    def _owasp_api_coverage(self, findings: list[dict]) -> str:
        """OWASP API Security Top 10 (2023) matrix — the API-specific companion
        to the web OWASP Top 10. Rendered only when the engagement produced API
        findings (REST / GraphQL / gRPC)."""
        rows, covered = self._framework_rows(
            self.OWASP_API_2023, self._api_category_id, findings)
        return f"""<div class="page section" id="owasp-api"><h2>OWASP API Security Top 10 (2023) Coverage</h2>
          <p class="small muted">API findings (REST / GraphQL / gRPC) mapped to the
          <a href="https://owasp.org/API-Security/editions/2023/en/0x11-t10/">OWASP API Security Top 10 (2023)</a>
          — {covered} of 10 categories have findings. API-layer authorization and resource-consumption
          risks are scored here, not under the web OWASP Top 10, so neither matrix double-counts.</p>
          <table>
            <tr><th style="width:90px">Category</th><th>Risk &amp; findings</th><th style="width:130px">Status</th><th style="width:70px">Count</th></tr>
            {rows}
          </table>
        </div>"""

    def _owasp_iot_coverage(self, findings: list[dict]) -> str:
        """OWASP IoT Top 10 (2018) matrix — the right standard for consumer /
        building-automation device findings. Rendered only when the engagement
        produced IoT findings."""
        rows, covered = self._framework_rows(
            _fw.OWASP_IOT_2018, _fw.iot_category_id, findings)
        return f"""<div class="page section" id="owasp-iot"><h2>OWASP IoT Top 10 (2018) Coverage</h2>
          <p class="small muted">Consumer and building-automation device findings mapped to the
          <a href="{_fw.OWASP_IOT_REFERENCE}">OWASP IoT Top 10 (2018)</a> — {covered} of 10
          categories have findings. This is the IoT-specific companion to the web OWASP Top 10:
          device authentication, insecure network services and default settings are scored here,
          not under the web risks.</p>
          <table>
            <tr><th style="width:90px">Category</th><th>Risk &amp; findings</th><th style="width:130px">Status</th><th style="width:70px">Count</th></tr>
            {rows}
          </table>
        </div>"""

    def _ot_ics_coverage(self, findings: list[dict]) -> str:
        """IEC 62443-3-3 foundational-requirement matrix (with MITRE ATT&CK for
        ICS context) — the OT/ICS standard. Rendered only when the engagement
        produced industrial-protocol findings."""
        rows, covered = self._framework_rows(
            _fw.IEC_62443_FR, _fw.ot_category_id, findings)
        return f"""<div class="page section" id="ot-ics"><h2>OT / ICS Security Coverage (IEC 62443)</h2>
          <p class="small muted">Industrial-control findings mapped to the
          <a href="{_fw.IEC_62443_REFERENCE}">IEC 62443-3-3</a> foundational requirements and
          cross-referenced to <a href="{_fw.ATTACK_ICS_REFERENCE}">MITRE ATT&amp;CK for ICS</a> —
          {covered} of 7 requirements have findings. A read-only external scan primarily exercises
          FR1 (authentication) and FR5 (network segmentation); the full list is shown so coverage is
          an honest statement, not a cherry-picked subset.</p>
          <table>
            <tr><th style="width:90px">Requirement</th><th>Foundational requirement &amp; findings</th><th style="width:130px">Status</th><th style="width:70px">Count</th></tr>
            {rows}
          </table>
        </div>"""

    def _compliance_coverage(self, findings: list[dict], fw) -> str:
        """Control-coverage matrix for one compliance framework.

        Maps every finding onto the framework's controls (via
        ``compliance_frameworks.covered_controls``) and renders a present /
        not-observed matrix with linked example findings — the same visual grammar
        as the OWASP matrix. Explicitly an evidence-coverage view, never an
        attestation of compliance."""
        from heaven.devsecops import compliance_frameworks as _cf
        buckets = _cf.covered_controls(fw, findings)
        total = len(fw.controls)
        covered = sum(1 for cid, _ in fw.controls if buckets[cid])
        rows = ""
        for cid, cn in fw.controls:
            hits = buckets[cid]
            n = len(hits)
            status = "Findings present" if hits else "Not observed"
            color = "#b00020" if hits else "#1a7f37"
            examples = ""
            if hits:
                worst = sorted(hits, key=lambda x: SEVERITY_META.get(
                    _sev_of(x), {}).get("order", 4))[:4]
                items = "".join(
                    f"<li>{_esc(h.get('title') or h.get('vuln_type') or 'Finding')}"
                    f" <span class='small muted'>({_esc(_sev_of(h))}"
                    f"{' · ' + _esc(str(h.get('target'))) if h.get('target') else ''})</span></li>"
                    for h in worst)
                more = f"<li class='small muted'>+{n - len(worst)} more…</li>" if n > len(worst) else ""
                examples = f"<ul class='small' style='margin:4px 0 0 16px'>{items}{more}</ul>"
            rows += (f'<tr><td class="small">{_esc(cid)}</td>'
                     f'<td>{_esc(cn)}{examples}</td>'
                     f'<td style="color:{color};font-weight:600">{status}</td>'
                     f'<td class="small">{n}</td></tr>')
        ref = (f' <a href="{_esc(fw.reference)}" target="_blank" rel="noopener noreferrer">'
               f'{_esc(fw.title)}</a>' if fw.reference else _esc(fw.title))
        return f"""<div class="page section" id="compliance"><h2>{_esc(fw.title)} Compliance Mapping</h2>
          <p class="small muted">Identified findings mapped to{ref}
          ({_esc(fw.subtitle)}) — {covered} of {total} controls have findings providing
          evidence of a gap in this engagement. A control marked <em>Not observed</em> had no
          matching finding: either tested-clean, out of this scan's scope, or a
          governance / physical / policy control this technical assessment cannot evidence.</p>
          <p class="note">This is a <strong>control-coverage view</strong> to guide remediation
          and audit preparation — it maps technical findings to controls and is <strong>not an
          attestation of compliance</strong>, which requires a full audit of policy, process and
          physical safeguards beyond the scope of an automated assessment.</p>
          <table>
            <tr><th style="width:120px">Control</th><th>Requirement &amp; findings</th>
                <th style="width:130px">Status</th><th style="width:70px">Count</th></tr>
            {rows}
          </table>
        </div>"""

    def _roadmap(self, ordered: list[dict]) -> str:
        # Every finding earns a roadmap row — the list is the full remediation
        # backlog, ordered by severity (``ordered`` is already sorted). Capping it
        # at the top 25 critical/high/medium items silently dropped real work the
        # client is paying to see.
        rows = ""
        for i, f in enumerate(ordered, 1):
            sev = _sev_of(f)
            m = SEVERITY_META[sev]
            ev = f.get("evidence") or {}
            action = ev.get("remediation") or f.get("remediation") or ""
            # Each numbered step on its own line; concise, whole sentences, no
            # mid-word ellipsis. The full remediation is in the finding detail.
            lines = roadmap_action_lines(action)
            action_html = "<br>".join(_esc(ln) for ln in lines)
            rows += (f'<tr><td class="small">{i}</td>'
                     f'<td><span class="pill" style="background:{m["color"]}">{m["label"]}</span></td>'
                     f'<td>{_esc(f.get("title") or f.get("vuln_type") or "Finding")}</td>'
                     f'<td class="small">{action_html}</td>'
                     f'<td class="small">{m["sla"]}</td></tr>')
        return f"""<div class="page section" id="roadmap"><h2>Remediation Roadmap</h2>
          <p>Recommended remediation order, prioritised by severity, covering all
          {len(ordered)} findings. Address higher-severity items first; SLAs are
          guidance and should be adapted to your risk appetite.</p>
          <table>
            <tr><th style="width:40px">#</th><th style="width:90px">Severity</th><th>Finding</th>
                <th>Recommended action</th><th style="width:100px">Target SLA</th></tr>
            {rows}
          </table>
        </div>"""

    @staticmethod
    def _appendix() -> str:
        gloss = [
            ("CVSS", "Common Vulnerability Scoring System, a 0-10 severity score."),
            ("CVSS base", "The base score: a property of the weakness class, so two findings "
                          "of the same class share it."),
            ("Contextual CVSS", "The CVSS Temporal plus Environmental score: the base adjusted for "
                                "THIS finding's exploit maturity (EPSS / public exploit / CISA KEV), "
                                "detection confidence and the asset's criticality and exposure. "
                                "Genuinely per-finding, so it varies even within one weakness class."),
            ("EPSS", "Exploit Prediction Scoring System, the probability a vuln will be exploited."),
            ("CISA KEV", "Catalog of vulnerabilities known to be actively exploited."),
            ("CWE", "Common Weakness Enumeration, the category of the underlying weakness."),
            ("OWASP Top 10", "The ten most critical web application security risks."),
            ("False positive", "A reported issue that is not actually exploitable."),
        ]
        grows = "".join(f"<tr><td style='width:150px'><strong>{_esc(t)}</strong></td><td>{_esc(d)}</td></tr>"
                        for t, d in gloss)
        return f"""<div class="page section" id="appendix"><h2>Appendix</h2>
          <h3>Tooling</h3>
          <p class="small">Assessment performed with the HEAVEN Autonomous Penetration-Testing Platform,
          which orchestrates reconnaissance, vulnerability scanning, NVD/EPSS/KEV enrichment, and
          ML-assisted risk scoring.</p>
          <h3>Glossary</h3>
          <table>{grows}</table>
          <h3>Disclaimer</h3>
          <p class="small muted">This assessment reflects the security posture observed at the time of
          testing within the agreed scope. It does not guarantee the absence of other vulnerabilities.
          Security is an ongoing process; re-testing is recommended after remediation and following
          significant changes to the environment.</p>
        </div>"""

    @staticmethod
    def _footer() -> str:
        year = datetime.now(UTC).year
        return (f'<div class="page" style="text-align:center;color:var(--muted);font-size:12px">'
                f'Generated by HEAVEN · {year} · CONFIDENTIAL</div>')
