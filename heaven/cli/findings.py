"""HEAVEN — Findings-related CLI commands: `findings`, `show`, `mark`, `replay`, `export`, `report`."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output
from heaven.utils.logger import HAS_RICH


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by severity")
@click.option("--status", type=click.Choice(["open", "verified", "false_positive", "accepted_risk", "fixed"]),
              help="Filter by status")
@click.option("--target", help="Filter by target (substring match)")
@click.option("--vuln-type", help="Filter by vulnerability type (sqli, xss, ...)")
@click.option("--min-confidence", type=float, default=0.0,
              help="Minimum confidence (0.0-1.0)")
@click.option("--limit", type=int, default=100, help="Max rows to show")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "ids"]),
              default="table", help="Output format")
def findings(engagement: Optional[str], severity: Optional[str],
             status: Optional[str], target: Optional[str],
             vuln_type: Optional[str], min_confidence: float,
             limit: int, fmt: str) -> None:
    """List findings from the engagement DB."""
    # Global --json forces machine-readable output regardless of --format.
    if json_output():
        fmt = "json"
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement))
    results = store.list_findings(
        severity=severity, status=status, target=target,
        vuln_type=vuln_type, min_confidence=min_confidence, limit=limit,
    )
    if not results:
        if fmt == "json":
            print("[]")
        else:
            _print("[yellow]No findings match.[/yellow]")
        return

    from heaven.utils.cvss import is_confirmed_finding
    if fmt == "json":
        print(json.dumps([
            {**f.__dict__, "evidence": f.evidence,
             "confirmation": "Confirmed" if is_confirmed_finding(f.__dict__) else "Potential"}
            for f in results
        ], indent=2, default=str))
    elif fmt == "ids":
        for f in results:
            print(f.id)
    else:
        for f in results:
            sev_color = {"critical": "bold red", "high": "red",
                         "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity, "dim")
            confirmed = is_confirmed_finding(f.__dict__)
            conf_tag = ("[green]CONFIRMED[/green]" if confirmed
                        else "[yellow]POTENTIAL[/yellow]")
            _print(
                f"  [{sev_color}]{f.severity[:4].upper():4}[/{sev_color}] "
                f"{conf_tag} {f.id}  conf={f.confidence:.2f}  "
                f"{f.vuln_type:18} {f.target[:40]:40} [dim]{f.status}[/dim]"
            )
        _print(f"\n[dim]{len(results)} finding(s) shown.[/dim]")


@click.command()
@click.argument("finding_id")
@click.option("--engagement", help="Engagement name")
def show(finding_id: str, engagement: Optional[str]) -> None:
    """Show full details for a single finding (request, response, repro)."""
    from heaven.engagement import EngagementStore
    from heaven.devsecops.evidence import package_finding
    store = EngagementStore(_engagement_db_path(engagement))
    f = store.get_finding(finding_id)
    if not f:
        _print(f"[red]Finding not found:[/red] {finding_id}")
        sys.exit(2)
    finding_dict = {
        "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
        "title": f.title, "severity": f.severity, "confidence": f.confidence,
        "confidence_bucket": f.confidence_bucket, "cve_id": f.cve_id,
        "risk_score": f.risk_score, "status": f.status,
        "operator_notes": f.operator_notes, "evidence": f.evidence,
    }
    pkg = package_finding(finding_dict)
    if HAS_RICH:
        from rich.markdown import Markdown
        from heaven.utils.logger import console
        if console:
            console.print(Markdown(pkg.to_markdown()))
            return
    print(pkg.to_markdown())


@click.command()
@click.argument("finding_id")
@click.argument("status", type=click.Choice([
    "open", "verified", "false_positive", "accepted_risk", "fixed",
]))
@click.option("--engagement", help="Engagement name")
@click.option("--notes", default="", help="Operator notes for the status change")
def mark(finding_id: str, status: str, engagement: Optional[str], notes: str) -> None:
    """Mark a finding's status (verified, false-positive, accepted-risk, fixed)."""
    from heaven.engagement import EngagementStore
    store = EngagementStore(_engagement_db_path(engagement))
    if store.update_finding_status(finding_id, status, notes=notes):
        _print(f"[green]Updated[/green] {finding_id} → {status}")
    else:
        _print(f"[red]Finding not found:[/red] {finding_id}")
        sys.exit(2)


@click.command()
@click.argument("finding_id")
@click.option("--engagement", help="Engagement name")
def replay(finding_id: str, engagement: Optional[str]) -> None:
    """Print the curl command needed to manually re-verify a finding."""
    from heaven.engagement import EngagementStore
    from heaven.devsecops.evidence import package_finding
    store = EngagementStore(_engagement_db_path(engagement))
    f = store.get_finding(finding_id)
    if not f:
        _print(f"[red]Finding not found:[/red] {finding_id}")
        sys.exit(2)
    finding_dict = {
        "target": f.target, "vuln_type": f.vuln_type,
        "evidence": f.evidence, **(f.evidence or {}),
    }
    pkg = package_finding(finding_dict)
    if pkg.curl_command:
        print(pkg.curl_command)
    else:
        _print(f"[yellow]No reproducible request stored for {finding_id}.[/yellow]")
        sys.exit(1)


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output file")
@click.option("--format", "fmt",
              type=click.Choice(["markdown", "csv", "json", "sarif", "junit",
                                 "burp", "proxy-jsonl"]),
              default="markdown", help="Export format")
@click.option("--fail-on",
              type=click.Choice(["critical", "high", "medium", "low", "none"]),
              default="medium",
              help="JUnit only: findings at/above this severity become failing tests.")
@click.option("--severity",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by minimum severity")
@click.option("--status", type=click.Choice([
    "open", "verified", "false_positive", "accepted_risk", "fixed",
]), help="Only export findings in this status")
@click.option("--min-confidence", type=float, default=0.0)
def export(engagement: Optional[str], output: str, fmt: str, fail_on: str,
           severity: Optional[str], status: Optional[str],
           min_confidence: float) -> None:
    """Export engagement findings.

    Formats:
      markdown    Human-readable report with curl repros (default)
      csv         For Jira / spreadsheet import
      json        Raw findings, full evidence
      sarif       SARIF 2.1.0 for GitHub/GitLab code-scanning dashboards
      junit       JUnit XML for CI — fails the build on --fail-on severity
      burp        Burp Suite XML — load into Site Map, replay in Repeater
      proxy-jsonl JSONL with full request/response, for mitmproxy / Caido
    """
    from heaven.engagement import EngagementStore
    from heaven.devsecops.evidence import (
        export_findings_markdown, export_findings_csv,
    )
    store = EngagementStore(_engagement_db_path(engagement))
    eng = store.get_engagement()

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if severity:
        keep_sev = {s for s, r in sev_rank.items() if r <= sev_rank[severity]}
    else:
        keep_sev = set(sev_rank.keys())

    all_findings = store.list_findings(
        status=status, min_confidence=min_confidence, limit=10000,
    )
    all_findings = [f for f in all_findings if f.severity in keep_sev]

    finding_dicts = []
    for f in all_findings:
        d = {
            "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
            "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "confidence_bucket": f.confidence_bucket,
            "cve_id": f.cve_id, "risk_score": f.risk_score,
            "first_seen_at": f.first_seen_at, "last_seen_at": f.last_seen_at,
            "status": f.status, "operator_notes": f.operator_notes,
            "evidence": f.evidence,
        }
        finding_dicts.append(d)

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "markdown":
        from heaven.cli.assets import (
            _collect_engagement_assets,
            _collect_engagement_dns,
        )
        text = export_findings_markdown(finding_dicts,
                                         engagement_name=eng.name if eng else "",
                                         assets=_collect_engagement_assets(engagement),
                                         dns_records=_collect_engagement_dns(engagement))
        out_path.write_text(text)
    elif fmt == "csv":
        out_path.write_text(export_findings_csv(finding_dicts))
    elif fmt == "json":
        out_path.write_text(json.dumps(finding_dicts, indent=2, default=str))
    elif fmt == "sarif":
        from heaven.devsecops.ci_export import findings_to_sarif_str
        out_path.write_text(findings_to_sarif_str(
            finding_dicts, engagement_name=eng.name if eng else ""))
    elif fmt == "junit":
        from heaven.devsecops.ci_export import findings_to_junit, summarize_gate
        out_path.write_text(findings_to_junit(
            finding_dicts, engagement_name=eng.name if eng else "", fail_on=fail_on))
        gate = summarize_gate(finding_dicts, fail_on=fail_on)
        _print(f"[dim]JUnit gate (fail-on {fail_on}): "
               f"{gate['breaching']} failing / {gate['total']} total[/dim]")
    elif fmt == "burp":
        from heaven.devsecops.burp_export import export_burp_xml
        out_path.write_text(export_burp_xml(
            finding_dicts, engagement_name=eng.name if eng else ""))
        _print("[dim]Import into Burp:[/dim] [cyan]File → Import → Items[/cyan]")
    elif fmt == "proxy-jsonl":
        from heaven.devsecops.burp_export import export_proxy_history_jsonl
        out_path.write_text(export_proxy_history_jsonl(finding_dicts))

    _print(f"[green]Exported {len(finding_dicts)} findings → {output} ({fmt})[/green]")


@click.command()
@click.argument("finding_id")
@click.option("--engagement", help="Engagement name")
def remediate(finding_id: str, engagement: Optional[str]) -> None:
    """Generate AI-assisted remediation guidance for one finding.

    Uses the configured LLM provider (ANTHROPIC / OPENAI / GEMINI). When no key
    is set it falls back to the finding's knowledge-base remediation, so the
    command always returns something actionable.
    """
    from heaven.engagement import EngagementStore
    from heaven.devsecops.ai_remediation import AIRemediationEngine
    from heaven.devsecops.vuln_kb import enrich_finding
    store = EngagementStore(_engagement_db_path(engagement))
    f = store.get_finding(finding_id)
    if not f:
        _print(f"[red]Finding not found:[/red] {finding_id}")
        sys.exit(2)

    enriched = enrich_finding({
        "id": f.id, "target": f.target, "vuln_type": f.vuln_type,
        "title": f.title, "severity": f.severity, "cve_id": f.cve_id,
        "evidence": f.evidence,
    })
    ev = enriched.get("evidence") or {}
    finding_dict = {
        "title": f.title, "target": f.target, "vuln_type": f.vuln_type,
        "description": ev.get("description") or f.title,
        # Static KB remediation is the graceful fallback used when no LLM is set.
        "patch": ev.get("remediation") or "",
    }

    engine = AIRemediationEngine()
    text = engine.generate_patch(finding_dict)

    if json_output():
        print(json.dumps({"finding_id": finding_id, "remediation": text,
                          "ai_generated": bool(engine.available)}, indent=2))
        return

    if not engine.available:
        _print("[yellow]No LLM configured — showing knowledge-base remediation. "
               "Set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY for "
               "AI-tailored guidance.[/yellow]")
    if HAS_RICH:
        from rich.markdown import Markdown
        from heaven.utils.logger import console
        if console:
            console.print(Markdown(text))
            return
    print(text)


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--i-have-authorization", is_flag=True,
              help="REQUIRED. Confirms you are authorized to send active probes to the "
                   "engagement's in-scope hosts.")
@click.option("--limit", type=int, default=200, help="Max Potential findings to consider")
def verify(engagement: Optional[str], i_have_authorization: bool, limit: int) -> None:
    """Actively verify Potential (version-banner) findings with SAFE probes.

    A network version banner does not prove a CVE is exploitable (vendors
    backport fixes without bumping the banner). For a curated set of well-known
    CVEs — e.g. Apache path-traversal (CVE-2021-41773/42013), Shellshock
    (CVE-2014-6271) — HEAVEN runs a SAFE, read-only behavioural probe. A probe
    that fires promotes the finding Potential → Confirmed and persists the proof;
    a negative probe leaves the finding untouched (never fabricated, never
    deleted). Requires --i-have-authorization.
    """
    import asyncio

    from heaven.engagement import EngagementStore
    from heaven.utils.cvss import is_confirmed_finding
    from heaven.vulnscan.active_verifier import (
        supported_cves, verify_finding, _finding_cve, _PROBES,
    )

    store = EngagementStore(_engagement_db_path(engagement))
    rows = store.list_findings(limit=limit)
    # Only Potential findings whose CVE has a registered safe probe.
    targets = [
        f for f in rows
        if _finding_cve(f.__dict__) in _PROBES and not is_confirmed_finding(f.__dict__)
    ]

    if json_output() and not targets:
        print(json.dumps({"candidates": 0, "promoted": 0,
                          "supported_cves": supported_cves()}, indent=2))
        return
    if not targets:
        _print("[yellow]No Potential findings with a safe active-verification probe.[/yellow]")
        _print(f"[dim]Supported CVEs: {', '.join(supported_cves())}[/dim]")
        return
    if not i_have_authorization:
        _print(f"[yellow]{len(targets)} finding(s) can be actively verified:[/yellow]")
        for f in targets:
            _print(f"  [dim]{f.id}[/dim]  {_finding_cve(f.__dict__):16} {f.target}")
        _print("\n[red]Refusing to probe without authorization.[/red] "
               "Re-run with [cyan]--i-have-authorization[/cyan].")
        sys.exit(3)

    async def _run() -> list[dict]:
        promoted: list[dict] = []
        for f in targets:
            fd = {
                "id": f.id, "target": f.target, "host": f.target,
                "port": (f.evidence or {}).get("port"),
                "vuln_type": f.vuln_type, "cve": f.cve_id,
                "severity": f.severity, "confidence": f.confidence,
                "source": (f.evidence or {}).get("source", ""),
                "evidence": dict(f.evidence or {}),
            }
            out = await verify_finding(fd, authorized=True)
            rec = (out.get("evidence") or {}).get("active_verification") or {}
            if rec.get("proved"):
                # Persist the confirmed proof back into the engagement store.
                store.upsert_finding(f.scan_id or f.id, out)
                promoted.append({"id": f.id, "cve": _finding_cve(fd),
                                 "target": f.target, "technique": rec.get("technique")})
        return promoted

    promoted = asyncio.run(_run())

    if json_output():
        print(json.dumps({"candidates": len(targets), "probed": len(targets),
                          "promoted": len(promoted), "promotions": promoted,
                          "supported_cves": supported_cves()}, indent=2))
        return

    _print(f"[cyan]Probed {len(targets)} Potential finding(s).[/cyan]")
    if promoted:
        _print(f"[green]✔ Promoted {len(promoted)} → Confirmed:[/green]")
        for p in promoted:
            _print(f"  [green]CONFIRMED[/green] {p['cve']:16} {p['target']} "
                   f"[dim]({p['technique']})[/dim]")
    else:
        _print("[dim]No probe fired — findings remain Potential "
               "(patched, endpoint disabled, or not reachable).[/dim]")


@click.command()
@click.option("--engagement")
@click.option("--output", "-o", required=True, type=click.Path())
@click.option("--framework",
              type=click.Choice(["OWASP_TOP10", "NIST_CSF"]),
              default="OWASP_TOP10")
def report(engagement: Optional[str], output: str, framework: str) -> None:
    """Generate compliance-mapped HTML report."""
    from heaven.engagement import EngagementStore
    from heaven.devsecops.compliance_report import ComplianceReportGenerator
    store = EngagementStore(_engagement_db_path(engagement))
    findings_list = store.list_findings(limit=10000)
    finding_dicts = [{"id": f.id, "target": f.target, "vuln_type": f.vuln_type,
                      "title": f.title, "severity": f.severity,
                      "confidence": f.confidence,
                      "predicted_cvss_score": f.risk_score,
                      "priority_score": f.risk_score} for f in findings_list]
    eng = store.get_engagement()
    from heaven.cli.assets import (
        _collect_engagement_assets,
        _collect_engagement_dns,
    )
    gen = ComplianceReportGenerator()
    gen.generate_html_report(finding_dicts,
                              engagement_name=eng.name if eng else "",
                              output_path=Path(output),
                              assets=_collect_engagement_assets(engagement),
                              dns_records=_collect_engagement_dns(engagement))
    _print(f"[green]Report written:[/green] {output} ({len(finding_dicts)} findings)")
    sev: dict[str, int] = {}
    for f in finding_dicts:
        s = str(f.get("severity") or "info").lower()
        sev[s] = sev.get(s, 0) + 1
    for s, n in sorted(sev.items()):
        _print(f"  {s:10}: {n}")


def register(cli: click.Group) -> None:
    cli.add_command(findings)
    cli.add_command(show)
    cli.add_command(mark)
    cli.add_command(replay)
    cli.add_command(remediate)
    cli.add_command(verify)
    cli.add_command(export)
    cli.add_command(report)
