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
            "version": "2.1.0",
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


def export_sarif(scan_data: dict, output_path: Optional[str] = None) -> dict:
    """Export findings in SARIF 2.1.0 for GitHub/GitLab code scanning.

    Delegates to :func:`heaven.devsecops.ci_export.findings_to_sarif`, which
    emits correct ``artifactLocation`` URIs (the target), ``partialFingerprints``
    and a numeric ``security-severity``. Writes to ``output_path`` only when one
    is given — passing no path returns the dict with no side effects (the earlier
    default silently wrote a stray ``heaven-results.sarif`` into the CWD).
    """
    from heaven.devsecops.ci_export import findings_to_sarif
    sarif = findings_to_sarif(scan_data.get("vulnerabilities", []))
    if output_path:
        Path(output_path).write_text(json.dumps(sarif, indent=2, default=str))
        logger.info(f"SARIF report written to {output_path}")
    return sarif


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
    
    # Write into the configured data dir so the writer stays consistent with the
    # API report-download reader (which resolves paths via get_config().data_dir)
    # and honours HEAVEN_DATA_DIR. Defaults to CWD-relative "data" — unchanged.
    try:
        from heaven.config import get_config
        base = Path(get_config().data_dir)
    except Exception:  # pragma: no cover - config is always importable in practice
        base = Path("data")
    base.mkdir(parents=True, exist_ok=True)

    json_path = str(base / f"report_{scan_id}.json")
    sarif_path = str(base / f"report_{scan_id}.sarif")

    compile_json_report(scan_data, json_path)
    export_sarif(scan_data, sarif_path)

    return {"json_report": json_path, "sarif_report": sarif_path}
