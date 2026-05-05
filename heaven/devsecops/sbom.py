"""
HEAVEN — SBOM Generator
Generates a CycloneDX JSON Software Bill of Materials from discovered assets.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from heaven.utils.logger import get_logger

logger = get_logger("devsecops.sbom")

def generate_cyclonedx_sbom(scan_data: dict[str, Any], output_path: str = "heaven-sbom.json") -> dict:
    """Generate a CycloneDX v1.4 SBOM from discovered assets."""
    
    components = []
    
    # Extract components from assets
    for asset in scan_data.get("assets", []):
        if not isinstance(asset, dict):
            continue
            
        target = asset.get("target", "unknown")
        for port, details in asset.get("ports", {}).items():
            if not isinstance(details, dict):
                continue
                
            service = details.get("service", "")
            product = details.get("product", "")
            version = details.get("version", "")
            
            if product:
                components.append({
                    "type": "application",
                    "name": product,
                    "version": version or "unknown",
                    "description": f"Service running on port {port} at {target}",
                    "purl": f"pkg:generic/{product}@{version}" if version else f"pkg:generic/{product}",
                })
                
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "HEAVEN Security",
                    "name": "HEAVEN Scanner",
                    "version": "1.0.0"
                }
            ]
        },
        "components": components
    }
    
    try:
        Path(output_path).write_text(json.dumps(sbom, indent=2))
        logger.info(f"SBOM generated successfully at: {output_path}")
    except Exception as e:
        logger.error(f"Failed to write SBOM: {e}")
        
    return sbom
