"""HEAVEN — `sbom` CLI command: export a CycloneDX SBOM for an engagement.

Components come from the services HEAVEN discovered (product/version per open
port); the SBOM's ``vulnerabilities`` section carries any CVE-bearing findings.
Same generator backs ``GET /api/sbom`` so CLI and webapp produce identical SBOMs.
"""

from __future__ import annotations

import json
from typing import Optional

import click

from heaven.cli._helpers import _engagement_db_path, _print, json_output


@click.command()
@click.option("--engagement", help="Engagement name")
@click.option("--output", "-o", type=click.Path(),
              help="Output file (default: heaven-sbom.json)")
def sbom(engagement: Optional[str], output: Optional[str]) -> None:
    """Generate a CycloneDX SBOM from discovered services + CVE findings."""
    from heaven.engagement import EngagementStore
    from heaven.devsecops.sbom import collect_scan_data, generate_cyclonedx_sbom

    store = EngagementStore(_engagement_db_path(engagement))
    scan_data = collect_scan_data(store)
    out = output or "heaven-sbom.json"
    doc = generate_cyclonedx_sbom(scan_data, output_path=out)
    n_comp = len(doc.get("components", []))
    n_vuln = len(doc.get("vulnerabilities", []))

    if json_output():
        print(json.dumps(doc, indent=2))
        return

    _print(f"[green]SBOM written:[/green] {out} [dim](CycloneDX "
           f"{doc.get('specVersion', '1.5')})[/dim]")
    _print(f"  components (services) : {n_comp}")
    _print(f"  vulnerabilities (CVEs): {n_vuln}")
    if n_comp == 0:
        _print("[dim]No service/version data yet — run a network scan with "
               "service detection first, then re-run [cyan]heaven sbom[/cyan].[/dim]")


def register(cli: click.Group) -> None:
    cli.add_command(sbom)
