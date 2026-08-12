"""
HEAVEN — Remediation Retest Report

Turns the raw scan-diff buckets (``heaven.devsecops.diff_finder``) into the
client-facing deliverable a real engagement produces after the customer says
"we've fixed the findings, please re-test": a **remediation posture** headline
(how many of the original findings are verified fixed) plus four sections in
plain remediation language:

  • Remediated      — findings present at baseline, no longer observed (fixed).
  • Still open      — findings present at baseline and still observed.
  • Reintroduced    — findings that had been marked fixed but came back (URGENT).
  • Newly introduced— findings first seen after the baseline (new surface).

The remediation rate counts only the findings that existed at baseline (the set
actually under retest); newly-introduced findings are reported separately so a
new issue never flatters or penalises the remediation percentage. Nothing is
fabricated — every row comes straight from the diff engine's timestamped buckets.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from heaven.devsecops.diff_finder import DiffReport, FindingDiffRow

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
    "low": "#2563eb", "info": "#64748b",
}


def retest_posture(report: DiffReport) -> dict[str, Any]:
    """Remediation posture for a retest.

    ``prior_total`` is the set under retest (findings that existed at baseline):
    remediated + still-open (still-open includes reintroduced). Newly-introduced
    findings are excluded from the rate and reported separately.
    """
    remediated = len(report.resolved)
    reintroduced = len(report.regressed)
    still_open = len(report.unchanged) + reintroduced
    newly_introduced = len(report.new)
    prior_total = remediated + still_open
    rate = round(100.0 * remediated / prior_total, 1) if prior_total else None
    return {
        "prior_total": prior_total,
        "remediated": remediated,
        "still_open": still_open,
        "reintroduced": reintroduced,
        "newly_introduced": newly_introduced,
        "remediation_rate": rate,
        "regressed_critical_or_high": report.regressed_critical_or_high,
        "critical_new": report.critical_new,
    }


def _verdict(posture: dict[str, Any]) -> tuple[str, str]:
    """(label, colour) summarising the retest outcome."""
    if posture["reintroduced"]:
        return "Action required — previously-fixed findings returned", "#dc2626"
    rate = posture["remediation_rate"]
    if rate is None:
        return "No baseline findings to retest", "#64748b"
    if rate >= 100.0:
        return "All baseline findings remediated", "#16a34a"
    if rate >= 50.0:
        return "Partial remediation", "#d97706"
    return "Limited remediation", "#dc2626"


def _sorted(rows: list[FindingDiffRow]) -> list[FindingDiffRow]:
    return sorted(rows, key=lambda r: _SEV_RANK.get(r.severity, 4))


def _rows_html(rows: list[FindingDiffRow]) -> str:
    if not rows:
        return '<p class="empty">None.</p>'
    out = ['<table><thead><tr><th>Severity</th><th>Type</th><th>Target</th>'
           '<th>Finding</th></tr></thead><tbody>']
    for r in _sorted(rows):
        color = _SEV_COLOR.get(r.severity, "#64748b")
        out.append(
            f'<tr><td><span class="sev" style="background:{color}">'
            f'{html.escape(r.severity.upper())}</span></td>'
            f'<td><code>{html.escape(r.vuln_type)}</code></td>'
            f'<td>{html.escape((r.target or "")[:80])}</td>'
            f'<td>{html.escape((r.title or r.vuln_type)[:100])}</td></tr>'
        )
    out.append("</tbody></table>")
    return "".join(out)


def render_retest_html(report: DiffReport, *, engagement_name: str = "",
                       baseline_label: str = "", current_label: str = "") -> str:
    """Render a standalone, self-contained HTML remediation-retest report."""
    posture = retest_posture(report)
    verdict, vcolor = _verdict(posture)
    rate = posture["remediation_rate"]
    rate_str = f"{rate:.0f}%" if rate is not None else "—"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    eng = html.escape(engagement_name or "Engagement")
    base = html.escape(baseline_label or report.baseline_scan_id[:8])
    curr = html.escape(current_label or report.current_scan_id[:8])

    reintro_banner = ""
    if posture["reintroduced"]:
        reintro_banner = (
            f'<div class="banner">⚠ {posture["reintroduced"]} previously-fixed '
            f'finding(s) were observed again — '
            f'{posture["regressed_critical_or_high"]} critical/high.</div>'
        )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remediation Retest — {eng}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; background: #f8fafc; color: #0f172a; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  header {{ border-bottom: 3px solid {vcolor}; padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: #64748b; font-size: 13px; }}
  .verdict {{ display: inline-block; margin-top: 12px; padding: 6px 14px; border-radius: 999px;
             background: {vcolor}; color: #fff; font-weight: 600; font-size: 14px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
          gap: 12px; margin: 24px 0; }}
  .kpi {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; text-align: center; }}
  .kpi .n {{ font-size: 28px; font-weight: 700; }}
  .kpi .l {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .04em; }}
  .rate .n {{ color: {vcolor}; }}
  .banner {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b;
            padding: 12px 16px; border-radius: 8px; margin: 16px 0; font-weight: 600; }}
  section {{ margin-top: 28px; }}
  h2 {{ font-size: 16px; margin: 0 0 10px; padding-bottom: 6px; border-bottom: 1px solid #e2e8f0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; color: #64748b; font-weight: 600; padding: 6px 8px;
       border-bottom: 2px solid #e2e8f0; font-size: 11px; text-transform: uppercase; }}
  td {{ padding: 7px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  code {{ background: #f1f5f9; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .sev {{ color: #fff; font-size: 10px; font-weight: 700; padding: 2px 7px; border-radius: 4px; }}
  .empty {{ color: #94a3b8; font-style: italic; margin: 4px 0; }}
  .overflow {{ overflow-x: auto; }}
  footer {{ margin-top: 40px; color: #94a3b8; font-size: 12px; text-align: center; }}
</style></head><body><div class="wrap">
<header>
  <h1>Remediation Retest Report</h1>
  <div class="meta">{eng} &middot; baseline <code>{base}</code> → retest <code>{curr}</code>
       &middot; generated {generated}</div>
  <div class="verdict">{html.escape(verdict)}</div>
</header>
{reintro_banner}
<div class="kpis">
  <div class="kpi rate"><div class="n">{rate_str}</div><div class="l">Remediated</div></div>
  <div class="kpi"><div class="n">{posture['remediated']}</div><div class="l">Fixed</div></div>
  <div class="kpi"><div class="n">{posture['still_open']}</div><div class="l">Still open</div></div>
  <div class="kpi"><div class="n">{posture['reintroduced']}</div><div class="l">Reintroduced</div></div>
  <div class="kpi"><div class="n">{posture['newly_introduced']}</div><div class="l">Newly introduced</div></div>
</div>
<p class="meta">Remediation rate is measured against the {posture['prior_total']}
   finding(s) present at the baseline (the set under retest). Newly-introduced
   findings are reported separately and do not affect the rate.</p>

<section><h2>✅ Remediated — verified fixed ({len(report.resolved)})</h2>
  <div class="overflow">{_rows_html(report.resolved)}</div></section>
<section><h2>⚠ Reintroduced — was fixed, observed again ({len(report.regressed)})</h2>
  <div class="overflow">{_rows_html(report.regressed)}</div></section>
<section><h2>◯ Still open — present at baseline, still observed ({len(report.unchanged)})</h2>
  <div class="overflow">{_rows_html(report.unchanged)}</div></section>
<section><h2>🆕 Newly introduced — first seen after baseline ({len(report.new)})</h2>
  <div class="overflow">{_rows_html(report.new)}</div></section>

<footer>Generated by HEAVEN — Autonomous Penetration Testing. Buckets are derived
  from timestamped finding observations; no results are inferred.</footer>
</div></body></html>
"""
