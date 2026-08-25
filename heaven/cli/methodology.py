"""HEAVEN — `heaven methodology` (browse pen-test & compliance mappings).

Covers the pen-test methodologies (OWASP WSTG, NIST SP 800-115, PTES) and the
compliance/control frameworks (Cyber Essentials + Plus, ISO/IEC 27001:2022,
PCI DSS, CIS Controls v8.1, NIST CSF 2.0, SOC 2).
"""

from __future__ import annotations

import json as _json
import sys
from pathlib import Path

import click

from heaven.cli._helpers import _print
import logging
logger = logging.getLogger(__name__)



_DOCS_DIR = Path(__file__).resolve().parents[2] / "docs" / "methodology"

# Short, memorable aliases → doc stem. The full stem is always accepted too, so
# ``--standard iso_27001`` and ``--standard iso`` both work. Kept here (not a
# hardcoded ``click.Choice``) so a newly-added ``docs/methodology/*.md`` is
# selectable without editing the CLI.
_STANDARD_ALIAS: dict[str, str] = {
    "owasp": "owasp_testing_guide", "wstg": "owasp_testing_guide",
    "nist": "nist_800_115", "800-115": "nist_800_115",
    "ptes": "ptes",
    "ce": "cyber_essentials", "cyber-essentials": "cyber_essentials",
    "ce-plus": "cyber_essentials_plus", "ceplus": "cyber_essentials_plus",
    "cyber-essentials-plus": "cyber_essentials_plus",
    "iso": "iso_27001", "iso27001": "iso_27001", "27001": "iso_27001",
    "pci": "pci_dss", "pci-dss": "pci_dss", "pcidss": "pci_dss",
    "cis": "cis_controls_v8", "cis8": "cis_controls_v8", "cis-v8": "cis_controls_v8",
    "csf": "nist_csf", "nist-csf": "nist_csf",
    "soc2": "soc2", "soc": "soc2",
}


def _resolve_standard(value: str) -> str:
    """Alias or stem → canonical doc stem (unchanged if already a stem)."""
    v = value.strip().lower()
    return _STANDARD_ALIAS.get(v, v)


@click.group(name="methodology")
def methodology() -> None:
    """Browse the pen-test & compliance mapping documents shipped with HEAVEN.

    Pen-test methodologies (OWASP WSTG, NIST SP 800-115, PTES) and compliance
    frameworks (Cyber Essentials + Plus, ISO/IEC 27001, PCI DSS, CIS v8.1,
    NIST CSF 2.0, SOC 2).
    """


@methodology.command("list")
def list_docs() -> None:
    """List the methodology documents available."""
    if not _DOCS_DIR.exists():
        _print(f"[red]Methodology docs not found at {_DOCS_DIR}[/red]")
        sys.exit(2)
    _print(f"[cyan]Methodology docs at[/cyan] {_DOCS_DIR}")
    for md in sorted(_DOCS_DIR.glob("*.md")):
        size_kb = md.stat().st_size // 1024
        _print(f"  - {md.stem:30}  ({size_kb} KiB)")
    _print("\n[dim]Use `heaven methodology show <name>` to print one.[/dim]")


@methodology.command("show")
@click.argument("name")
def show(name: str) -> None:
    """Print one methodology mapping doc to stdout.

    NAME is the filename stem, e.g. owasp_testing_guide, nist_800_115, ptes,
    cyber_essentials, iso_27001, pci_dss, cis_controls_v8, nist_csf, soc2.
    """
    candidate = _DOCS_DIR / f"{name}.md"
    if not candidate.exists():
        _print(f"[red]Doc not found:[/red] {candidate}")
        _print("[dim]Available:[/dim]")
        for md in sorted(_DOCS_DIR.glob("*.md")):
            _print(f"  - {md.stem}")
        sys.exit(2)
    content = candidate.read_text(encoding="utf-8")
    # Try to render via Rich if available, else plain print
    try:
        from rich.markdown import Markdown
        from heaven.utils.logger import HAS_RICH, console
        if HAS_RICH and console:
            console.print(Markdown(content))
            return
    except Exception:
        logger.debug("suppressed non-fatal exception", exc_info=True)
    print(content)


@methodology.command("coverage")
@click.option("--engagement", "-e", default=None,
              help="Engagement to overlay (default: the active engagement).")
@click.option("--standard", "-s", default=None,
              help="Limit output to one standard — a doc stem (e.g. iso_27001) "
                   "or a short alias (owasp, nist, ptes, ce, ce-plus, iso, pci, "
                   "cis, csf, soc2).")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def coverage(engagement: str | None, standard: str | None, as_json: bool) -> None:
    """Live methodology coverage for an engagement.

    Shows each standard's automated-vs-manual coverage (computed from the
    mapping docs) and how many of those tests the engagement's real findings
    actually exercised — the same data the web Methodology page renders, so CLI
    and UI stay in sync.
    """
    from heaven import methodology as _m

    # Pull the engagement's findings for the live overlay (best-effort).
    findings: list[dict] = []
    eng_name = engagement or ""
    try:
        from heaven.cli._helpers import _engagement_db_path
        from heaven.engagement import EngagementStore, get_active_engagement
        eng_name = engagement or get_active_engagement() or ""
        store = EngagementStore(_engagement_db_path(engagement))
        findings = [
            {"id": f.id, "vuln_type": f.vuln_type, "title": f.title,
             "severity": f.severity, "target": f.target,
             "owasp": getattr(f, "owasp", "")}
            for f in store.list_findings(limit=10000)
        ]
    except Exception:
        findings = []

    built = _m.build(findings, _DOCS_DIR)
    built["engagement"]["name"] = eng_name

    stds = built["standards"]
    if standard:
        wanted = _resolve_standard(standard)
        stds = [s for s in stds if s["name"] == wanted]
        if not stds:
            available = ", ".join(s["name"] for s in built["standards"])
            _print(f"[red]Unknown standard:[/red] {standard}")
            _print(f"[dim]Available:[/dim] {available}")
            sys.exit(2)

    if as_json:
        payload = {"engagement": built["engagement"],
                   "standards": [{"name": s["name"], "summary": s["summary"]} for s in stds]}
        print(_json.dumps(payload, indent=2))
        return

    eng = built["engagement"]
    label = eng_name or "(none)"
    _print(f"[bold cyan]Methodology coverage[/bold cyan]  ·  engagement: [bold]{label}[/bold]")
    _print(f"[dim]{eng['findings_total']} finding(s) · "
           f"{len(eng['modules_active'])} detector(s) active · "
           f"{len(eng['owasp_categories'])} OWASP categor(ies)[/dim]\n")

    for s in stds:
        summ = s["summary"]
        cov_pct = (100 * summ["covered"] // summ["total"]) if summ["total"] else 0
        _print(f"[bold]{s['meta_title']}[/bold] [dim]({s['subtitle']})[/dim]")
        _print(f"  Tests mapped      : {summ['total']}")
        _print(f"  Automated by HEAVEN: {summ['covered']}  ({cov_pct}%)"
               f"   [dim]auto {summ['automated']} · partial {summ['partial']} · manual {summ['manual']}[/dim]")
        _print(f"  Exercised here    : [green]{summ.get('exercised', 0)}[/green]"
               f"  [dim](rows whose detector produced a finding)[/dim]\n")

    if not findings:
        _print("[yellow]No findings in this engagement yet — run a scan to populate live coverage.[/yellow]")


def register(cli: click.Group) -> None:
    cli.add_command(methodology)
