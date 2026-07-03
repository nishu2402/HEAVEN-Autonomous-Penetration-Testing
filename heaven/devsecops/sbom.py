"""
HEAVEN — SBOM Generator

Produces a CycloneDX 1.5 JSON Software Bill of Materials from the services
HEAVEN actually discovered during a scan, and folds any CVE-bearing findings
into the SBOM's ``vulnerabilities`` section (a lightweight VEX-style record).

Wired into the ``heaven sbom`` CLI command and ``GET /api/sbom``. The input is
assembled by :func:`collect_scan_data` from an engagement store, so the SBOM
reflects real recon output rather than a hand-built payload.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

from heaven import __version__
from heaven.utils.logger import get_logger

logger = get_logger("devsecops.sbom")


def _iter_ports(asset: dict) -> Iterable[tuple[str, dict]]:
    """Yield ``(port, details)`` for an asset in either shape.

    The network scanner emits ``{"open_ports": [{"port", "service",
    "version", "cpe", ...}]}``; older/other producers may use the legacy
    ``{"ports": {port: {"product", "version"}}}`` mapping. Handle both so the
    SBOM is populated regardless of which producer filled the asset.
    """
    open_ports = asset.get("open_ports")
    if isinstance(open_ports, list):
        for p in open_ports:
            if isinstance(p, dict):
                yield str(p.get("port", "")), p
        return
    ports = asset.get("ports")
    if isinstance(ports, dict):
        for port, details in ports.items():
            if isinstance(details, dict):
                yield str(port), details


def _component_name(details: dict) -> str:
    """Best available service identifier for a discovered port."""
    return (details.get("product") or details.get("service")
            or details.get("name") or "").strip()


def generate_cyclonedx_sbom(scan_data: dict[str, Any],
                            output_path: Optional[str] = None) -> dict:
    """Build a CycloneDX 1.5 SBOM dict from discovered assets + findings.

    - ``scan_data["assets"]``: list of host dicts (scanner or legacy shape).
      Every open service that carries a product/service name becomes a
      ``component`` with a ``purl`` and, when known, its ``cpe``.
    - ``scan_data["vulnerabilities"]`` / ``["findings"]``: entries carrying a
      CVE id become CycloneDX ``vulnerabilities``.

    Writes JSON to ``output_path`` when provided; always returns the dict.
    """
    components: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for asset in scan_data.get("assets", []) or []:
        if not isinstance(asset, dict):
            continue
        host = (asset.get("host") or asset.get("target")
                or asset.get("ip") or "unknown")
        for port, details in _iter_ports(asset):
            name = _component_name(details)
            if not name:
                continue
            version = str(details.get("version") or "").strip()
            key = (host, port, name, version)
            if key in seen:
                continue
            seen.add(key)
            comp: dict[str, Any] = {
                "type": "application",
                "bom-ref": f"{host}:{port}/{name}",
                "name": name,
                "version": version or "unknown",
                "description": f"Service on {host}:{port}",
                "purl": (f"pkg:generic/{name}@{version}" if version
                         else f"pkg:generic/{name}"),
            }
            cpe = details.get("cpe")
            if cpe:
                comp["cpe"] = cpe
            components.append(comp)

    vulnerabilities: list[dict[str, Any]] = []
    seen_cve: set[str] = set()
    raw_vulns = (scan_data.get("vulnerabilities")
                 or scan_data.get("findings") or [])
    for v in raw_vulns:
        if not isinstance(v, dict):
            continue
        cve = v.get("cve_id") or v.get("cve")
        if not cve or cve in seen_cve:
            continue
        seen_cve.add(cve)
        entry: dict[str, Any] = {
            "id": cve,
            "source": {"name": "NVD",
                       "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            "description": v.get("title") or v.get("description") or "",
        }
        rating = v.get("risk_score") or v.get("predicted_cvss_score")
        try:
            if rating:
                entry["ratings"] = [{"score": float(rating), "method": "CVSSv3"}]
        except (TypeError, ValueError):
            pass
        vulnerabilities.append(entry)

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{
                "vendor": "HEAVEN Security",
                "name": "HEAVEN Scanner",
                "version": __version__,
            }],
        },
        "components": components,
    }
    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    if output_path:
        try:
            Path(output_path).write_text(json.dumps(sbom, indent=2))
            logger.info(
                "SBOM generated at %s (%d components, %d vulnerabilities)",
                output_path, len(components), len(vulnerabilities),
            )
        except Exception as e:  # noqa: BLE001 — writing must never crash a scan
            logger.error(f"Failed to write SBOM: {e}")

    return sbom


def collect_scan_data(store) -> dict[str, Any]:
    """Assemble SBOM input from an :class:`EngagementStore`.

    Pulls assets from every scan's stored summary and every CVE-bearing
    finding. Robust to scans that recorded no assets — the SBOM then simply
    carries the CVE findings with an empty component list.
    """
    assets: list[dict] = []
    for s in store.list_scans(limit=200):
        raw = s.get("summary_json")
        if not raw:
            continue
        try:
            summ = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            continue
        for a in (summ.get("assets") or []):
            if isinstance(a, dict):
                assets.append(a)

    findings: list[dict] = []
    for f in store.list_findings(limit=10000):
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        findings.append({
            "cve_id": f.cve_id,
            "title": f.title,
            "risk_score": f.risk_score,
            "description": ev.get("description", ""),
        })

    return {"assets": assets, "vulnerabilities": findings}
