"""
HEAVEN — CVE Mapper
Maps discovered services to CPE strings and correlates with known vulnerabilities.
Includes fuzzy CPE matching and zero-day heuristic detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.mapper")

# Service name → CPE vendor/product mapping
CPE_MAP = {
    "ssh": [("openssh", "openssh")],
    "http": [("apache", "http_server"), ("nginx", "nginx"), ("microsoft", "iis")],
    "https": [("apache", "http_server"), ("nginx", "nginx"), ("microsoft", "iis")],
    "ftp": [("vsftpd", "vsftpd"), ("proftpd", "proftpd"), ("pureftpd", "pure-ftpd")],
    "mysql": [("oracle", "mysql"), ("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "redis": [("redis", "redis")],
    "mongodb": [("mongodb", "mongodb")],
    "mssql": [("microsoft", "sql_server")],
    "smtp": [("postfix", "postfix"), ("exim", "exim")],
    "rdp": [("microsoft", "remote_desktop")],
    "vnc": [("realvnc", "vnc"), ("tightvnc", "tightvnc")],
    "elasticsearch": [("elastic", "elasticsearch")],
}


@dataclass
class CPEMatch:
    cpe: str
    confidence: float = 1.0
    source: str = ""


def generate_cpe_from_banner(service: str, banner: str, version: str = "") -> list[CPEMatch]:
    """Generate CPE 2.3 strings from service info with fuzzy matching."""
    matches = []

    # Try exact service mapping
    cpe_entries = CPE_MAP.get(service.lower(), [])

    # Banner-based detection for ambiguous services (HTTP)
    banner_lower = banner.lower()
    if service.lower() in ("http", "https"):
        if "nginx" in banner_lower:
            cpe_entries = [("nginx", "nginx")]
        elif "apache" in banner_lower:
            cpe_entries = [("apache", "http_server")]
        elif "iis" in banner_lower:
            cpe_entries = [("microsoft", "iis")]
        elif "lighttpd" in banner_lower:
            cpe_entries = [("lighttpd", "lighttpd")]

    for vendor, product in cpe_entries:
        ver = version or _extract_version_from_banner(banner, product)
        if ver:
            cpe = f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
            matches.append(CPEMatch(cpe=cpe, confidence=0.9, source="banner"))
        else:
            # Wildcard version — lower confidence
            cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
            matches.append(CPEMatch(cpe=cpe, confidence=0.5, source="service_name"))

    return matches


def _extract_version_from_banner(banner: str, product: str) -> str:
    """Extract version from banner text."""
    patterns = [
        rf"{re.escape(product)}[/\s]+v?(\d+\.\d+[\.\d]*)",
        r"(\d+\.\d+\.\d+)",
        r"(\d+\.\d+)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def detect_zero_day_indicators(service: str, version: str, banner: str) -> list[dict]:
    """
    Heuristic zero-day detection based on anomalous behavior patterns.
    This does NOT find actual zero-days but flags conditions worth investigating.
    """
    indicators = []

    # Services running debug/development modes in production
    debug_patterns = [
        (r"debug|development|dev mode", "Service running in debug/development mode"),
        (r"stack trace|traceback", "Service leaking stack traces"),
        (r"internal server error.*detail", "Verbose error responses"),
    ]
    for pat, desc in debug_patterns:
        if re.search(pat, banner, re.IGNORECASE):
            indicators.append({
                "type": "anomalous_behavior",
                "description": desc,
                "severity": "high",
                "confidence": 0.7,
            })

    # Version gaps (no updates for known vulnerable versions)
    known_vuln_versions = {
        "openssh": ["7.4", "7.5", "7.6", "7.7", "8.0", "8.1"],
        "apache": ["2.4.49", "2.4.50"],  # Path traversal CVE-2021-41773
        "nginx": ["1.18.0", "1.20.0"],
    }
    if service.lower() in known_vuln_versions:
        if version in known_vuln_versions[service.lower()]:
            indicators.append({
                "type": "known_vulnerable_version",
                "description": f"{service} {version} has known unpatched vulnerabilities",
                "severity": "high",
                "confidence": 0.9,
            })

    return indicators


async def map_vulnerabilities(host_results: list[dict], nvd_client: Any) -> list[dict]:
    """Map discovered services to vulnerabilities via NVD lookup."""
    all_vulns = []

    for host in host_results:
        for port_info in host.get("open_ports", []):
            service = port_info.get("service", "")
            banner = port_info.get("banner", "")
            version = port_info.get("version", "")

            # Generate CPEs
            cpe_matches = generate_cpe_from_banner(service, banner, version)

            for cpe_match in cpe_matches:
                # NVD lookup
                cves = await nvd_client.search_by_cpe(cpe_match.cpe)
                for cve in cves:
                    all_vulns.append({
                        "host": host.get("host", "unknown"),
                        "port": port_info.get("port", 0),
                        "cve": cve.cve_id,
                        "title": cve.title,
                        "severity": cve.severity,
                        "cvss": cve.cvss_base,
                        "cpe": cpe_match.cpe,
                        "cpe_confidence": cpe_match.confidence,
                    })

            # Zero-day heuristics
            zday_indicators = detect_zero_day_indicators(service, version, banner)
            for ind in zday_indicators:
                all_vulns.append({
                    "host": host.get("host", "unknown"),
                    "port": port_info.get("port", 0),
                    "cve": "HEAVEN-ZDAY-HEURISTIC",
                    "title": ind["description"],
                    "severity": ind["severity"],
                    "cvss": 0.0,
                    "type": "zero_day_heuristic",
                    "confidence": ind["confidence"],
                })

    return all_vulns
