"""
HEAVEN — Report Aggregator & SARIF Export
Compiles scan findings into structured JSON and SARIF for GitHub integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.aggregator")


def compile_json_report(scan_data: dict, output_path: Optional[str] = None) -> dict:
    """Compile all findings into a structured JSON report."""
    report = {
        "schema_version": "1.0",
        "tool": {
            "name": "HEAVEN", 
            "version": "1.0.0",
            "author": "Nisarg Chasmawala (Shroff)"
        },
        "scan_id": scan_data.get("scan_id", str(uuid4())),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_assets": scan_data.get("total_assets", 0),
            "total_vulnerabilities": scan_data.get("total_vulns", 0),
            "critical": scan_data.get("critical", 0),
            "high": scan_data.get("high", 0),
            "medium": scan_data.get("medium", 0),
            "low": scan_data.get("low", 0),
            "info": scan_data.get("info", 0),
            "confirmed": scan_data.get("confirmed", 0),
            "secrets_found": scan_data.get("secrets", 0),
            "honeypots_detected": scan_data.get("honeypots", 0),
        },
        "vulnerabilities": scan_data.get("vulnerabilities", []),
        "secrets": scan_data.get("secrets_list", []),
        "assets": scan_data.get("assets", []),
        "risk_scores": scan_data.get("risk_scores", []),
    }

    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2, default=str))
        logger.info(f"JSON report written to {output_path}")

    return report


def export_sarif(scan_data: dict, output_path: str = "heaven-results.sarif") -> dict:
    """Export findings in SARIF 2.1.0 format for GitHub Security tab."""
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HEAVEN",
                    "version": "1.0.0",
                    "organization": "Nisarg Chasmawala (Shroff)",
                    "informationUri": "https://github.com/heaven-security",
                    "rules": [],
                }
            },
            "results": [],
        }],
    }

    rules_seen = set()
    run: dict[str, Any] = sarif["runs"][0]

    for vuln in scan_data.get("vulnerabilities", []):
        rule_id = vuln.get("cve_id") or vuln.get("title", "unknown")

        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": vuln.get("title", rule_id),
                "shortDescription": {"text": vuln.get("title", "")},
                "fullDescription": {"text": vuln.get("description", "")},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(vuln.get("severity", "info"))
                },
                "properties": {
                    "cvss": vuln.get("cvss_base", 0),
                    "risk_score": vuln.get("risk_score", 0),
                },
            })

        run["results"].append({
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(vuln.get("severity", "info")),
            "message": {"text": vuln.get("description", vuln.get("title", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": vuln.get("asset", "unknown")},
                }
            }],
            "properties": {
                "asset": vuln.get("asset", ""),
                "port": vuln.get("port", 0),
                "risk_score": vuln.get("risk_score", 0),
                "validated": vuln.get("validated", False),
            },
        })

    Path(output_path).write_text(json.dumps(sarif, indent=2))
    logger.info(f"SARIF report written to {output_path}")
    return sarif


def _severity_to_sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(severity.lower(), "note")


async def generate_report(scan_id: str = "", scan_data: Optional[dict[Any, Any]] = None, **kwargs) -> dict[str, Any]:
    """Main entry point (called by orchestrator)."""
    logger.info("Generating scan reports...")
    scan_data = scan_data or {}
    
    # Calculate summaries
    vulns = scan_data.get("vulnerabilities", [])
    scan_data["total_vulns"] = len(vulns)
    scan_data["critical"] = sum(1 for v in vulns if v.get("severity") == "critical")
    scan_data["high"] = sum(1 for v in vulns if v.get("severity") == "high")
    scan_data["medium"] = sum(1 for v in vulns if v.get("severity") == "medium")
    scan_data["low"] = sum(1 for v in vulns if v.get("severity") == "low")
    
    import os
    os.makedirs("data", exist_ok=True)
    
    json_path = f"data/report_{scan_id}.json"
    sarif_path = f"data/report_{scan_id}.sarif"
    
    compile_json_report(scan_data, json_path)
    export_sarif(scan_data, sarif_path)
    
    return {"json_report": json_path, "sarif_report": sarif_path}
