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

    if fmt == "json":
        print(json.dumps([
            {**f.__dict__, "evidence": f.evidence} for f in results
        ], indent=2, default=str))
    elif fmt == "ids":
        for f in results:
            print(f.id)
    else:
        for f in results:
            sev_color = {"critical": "bold red", "high": "red",
                         "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity, "dim")
            _print(
                f"  [{sev_color}]{f.severity[:4].upper():4}[/{sev_color}] "
                f"{f.id}  conf={f.confidence:.2f}  {f.vuln_type:18} {f.target[:40]:40} "
                f"[dim]{f.status}[/dim]"
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
              type=click.Choice(["markdown", "csv", "json", "sarif", "burp", "proxy-jsonl"]),
              default="markdown", help="Export format")
@click.option("--severity",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter by minimum severity")
@click.option("--status", type=click.Choice([
    "open", "verified", "false_positive", "accepted_risk", "fixed",
]), help="Only export findings in this status")
@click.option("--min-confidence", type=float, default=0.0)
def export(engagement: Optional[str], output: str, fmt: str,
           severity: Optional[str], status: Optional[str],
           min_confidence: float) -> None:
    """Export engagement findings.

    Formats:
      markdown    Human-readable report with curl repros (default)
      csv         For Jira / spreadsheet import
      json        Raw findings, full evidence
      sarif       SARIF 2.1.0 for code-scanning dashboards
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
        text = export_findings_markdown(finding_dicts,
                                         engagement_name=eng.name if eng else "")
        out_path.write_text(text)
    elif fmt == "csv":
        out_path.write_text(export_findings_csv(finding_dicts))
    elif fmt == "json":
        out_path.write_text(json.dumps(finding_dicts, indent=2, default=str))
    elif fmt == "sarif":
        from heaven.devsecops.aggregator import export_sarif
        out_path.write_text(json.dumps(
            export_sarif({"vulnerabilities": finding_dicts}), indent=2,
        ))
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
    gen = ComplianceReportGenerator()
    gen.generate_html_report(finding_dicts,
                              engagement_name=eng.name if eng else "",
                              output_path=Path(output))
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
    cli.add_command(export)
    cli.add_command(report)
