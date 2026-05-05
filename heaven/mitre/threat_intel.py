"""
HEAVEN — Threat Intelligence Correlation Engine
Maps findings to known APT groups, campaigns, and CISA KEV catalog.
Adjusts risk scoring based on active threat actor usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("mitre.threat_intel")

# ═══════════════════════════════════════════
# CISA KEV (Known Exploited Vulnerabilities) — top entries
# Full catalog fetched at runtime from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# ═══════════════════════════════════════════

CISA_KEV_SNAPSHOT: dict[str, dict] = {
    "CVE-2024-3094": {"vendor": "Tukaani", "product": "XZ Utils", "date_added": "2024-03-29",
                       "due_date": "2024-04-19", "notes": "Backdoor in liblzma"},
    "CVE-2024-21762": {"vendor": "Fortinet", "product": "FortiOS", "date_added": "2024-02-09",
                        "due_date": "2024-02-16", "notes": "Out-of-bound write RCE"},
    "CVE-2023-44487": {"vendor": "IETF", "product": "HTTP/2", "date_added": "2023-10-10",
                        "due_date": "2023-10-31", "notes": "Rapid Reset DDoS"},
    "CVE-2023-4966": {"vendor": "Citrix", "product": "NetScaler", "date_added": "2023-10-18",
                       "due_date": "2023-11-08", "notes": "Citrix Bleed"},
    "CVE-2024-1709": {"vendor": "ConnectWise", "product": "ScreenConnect", "date_added": "2024-02-22",
                       "due_date": "2024-03-01", "notes": "Auth bypass"},
    "CVE-2023-22515": {"vendor": "Atlassian", "product": "Confluence", "date_added": "2023-10-05",
                        "due_date": "2023-10-26", "notes": "Privilege escalation"},
    "CVE-2021-44228": {"vendor": "Apache", "product": "Log4j", "date_added": "2021-12-10",
                        "due_date": "2021-12-24", "notes": "Log4Shell RCE"},
    "CVE-2021-34473": {"vendor": "Microsoft", "product": "Exchange Server", "date_added": "2021-11-03",
                        "due_date": "2021-11-17", "notes": "ProxyShell"},
    "CVE-2023-46805": {"vendor": "Ivanti", "product": "Connect Secure", "date_added": "2024-01-10",
                        "due_date": "2024-01-22", "notes": "Auth bypass"},
    "CVE-2024-27198": {"vendor": "JetBrains", "product": "TeamCity", "date_added": "2024-03-07",
                        "due_date": "2024-03-28", "notes": "Auth bypass RCE"},
}

# Known APT groups and their common TTPs
APT_PROFILES: dict[str, dict] = {
    "APT28": {"aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"],
              "origin": "Russia", "targets": ["government", "military", "media"],
              "techniques": ["T1566", "T1059", "T1078", "T1190", "T1550"],
              "cves": ["CVE-2023-23397", "CVE-2023-38831"]},
    "APT29": {"aliases": ["Cozy Bear", "NOBELIUM", "Midnight Blizzard"],
              "origin": "Russia", "targets": ["government", "tech", "think_tanks"],
              "techniques": ["T1195.002", "T1078", "T1098", "T1550", "T1059.001"],
              "cves": ["CVE-2021-21972", "CVE-2021-34527"]},
    "APT41": {"aliases": ["Winnti", "BARIUM", "Wicked Panda"],
              "origin": "China", "targets": ["tech", "healthcare", "gaming", "telecom"],
              "techniques": ["T1190", "T1059", "T1068", "T1055", "T1003"],
              "cves": ["CVE-2021-44228", "CVE-2021-26855"]},
    "Lazarus": {"aliases": ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
                "origin": "North Korea", "targets": ["finance", "crypto", "defense"],
                "techniques": ["T1566.001", "T1059.007", "T1195.002", "T1497"],
                "cves": ["CVE-2023-42793", "CVE-2022-47966"]},
    "Volt Typhoon": {"aliases": ["VANGUARD PANDA", "Bronze Silhouette"],
                     "origin": "China", "targets": ["critical_infrastructure", "telecom", "government"],
                     "techniques": ["T1190", "T1078", "T1059.001", "T1036", "T1070"],
                     "cves": ["CVE-2023-46805", "CVE-2024-21887"]},
    "Sandworm": {"aliases": ["IRIDIUM", "Seashell Blizzard", "Voodoo Bear"],
                 "origin": "Russia", "targets": ["energy", "government", "critical_infrastructure"],
                 "techniques": ["T1190", "T1059", "T1485", "T1486", "T1561"],
                 "cves": ["CVE-2023-44487", "CVE-2022-41040"]},
}


@dataclass
class ThreatContext:
    """Threat intelligence context for a vulnerability."""
    cve_id: str = ""
    in_kev: bool = False
    kev_details: Optional[dict] = None
    associated_groups: list[dict] = field(default_factory=list)
    active_exploitation: bool = False
    risk_adjustment: float = 1.0
    threat_level: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id, "in_kev": self.in_kev,
            "kev_details": self.kev_details,
            "associated_groups": self.associated_groups,
            "active_exploitation": self.active_exploitation,
            "risk_adjustment": self.risk_adjustment,
            "threat_level": self.threat_level,
        }


class ThreatIntelEngine:
    """
    Correlates scan findings with real-world threat intelligence.
    Adjusts risk scores based on active exploitation data.
    """

    def __init__(self):
        self._kev_cache: dict[str, dict] = dict(CISA_KEV_SNAPSHOT)
        self._contexts: list[ThreatContext] = []

    async def fetch_kev_catalog(self) -> None:
        """Fetch latest CISA KEV catalog."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cveID", "")
                        if cve:
                            self._kev_cache[cve] = {
                                "vendor": vuln.get("vendorProject", ""),
                                "product": vuln.get("product", ""),
                                "date_added": vuln.get("dateAdded", ""),
                                "due_date": vuln.get("dueDate", ""),
                                "notes": vuln.get("shortDescription", ""),
                            }
                    logger.info(f"KEV catalog updated: {len(self._kev_cache)} entries")
        except Exception as e:
            logger.warning(f"KEV fetch failed: {e} — using snapshot ({len(self._kev_cache)} entries)")

    def enrich_finding(self, finding: dict) -> ThreatContext:
        """Enrich a vulnerability finding with threat intelligence."""
        cve_id = finding.get("cve_id", finding.get("cve", ""))
        context = ThreatContext(cve_id=cve_id)

        # Check KEV
        if cve_id in self._kev_cache:
            context.in_kev = True
            context.kev_details = self._kev_cache[cve_id]
            context.active_exploitation = True
            context.risk_adjustment = 2.5  # KEV vulns get 2.5x risk multiplier

        # Check APT group associations
        for group_name, profile in APT_PROFILES.items():
            if cve_id in profile.get("cves", []):
                context.associated_groups.append({
                    "name": group_name,
                    "aliases": profile["aliases"],
                    "origin": profile["origin"],
                    "targets": profile["targets"],
                })
                context.risk_adjustment = max(context.risk_adjustment, 3.0)

        # Check technique-based associations
        techniques = finding.get("mitre_techniques", [])
        for group_name, profile in APT_PROFILES.items():
            for tech in techniques:
                tech_id = tech if isinstance(tech, str) else tech.get("id", "")
                if tech_id in profile.get("techniques", []):
                    if not any(g["name"] == group_name for g in context.associated_groups):
                        context.associated_groups.append({
                            "name": group_name, "aliases": profile["aliases"],
                            "origin": profile["origin"], "match_type": "technique",
                        })

        # Determine threat level
        if context.in_kev and context.associated_groups:
            context.threat_level = "critical"
        elif context.in_kev:
            context.threat_level = "high"
        elif context.associated_groups:
            context.threat_level = "elevated"
        else:
            context.threat_level = "standard"

        self._contexts.append(context)
        return context

    def enrich_all_findings(self, findings: list[dict]) -> list[ThreatContext]:
        """Enrich all findings with threat intelligence."""
        logger.info(f"Enriching {len(findings)} findings with threat intelligence...")
        contexts = [self.enrich_finding(f) for f in findings]
        kev_count = sum(1 for c in contexts if c.in_kev)
        apt_count = sum(1 for c in contexts if c.associated_groups)
        logger.info(f"Threat enrichment: {kev_count} in KEV, {apt_count} linked to APT groups")
        return contexts

    def get_threat_landscape(self) -> dict:
        """Overview of threat landscape from scan results."""
        group_counts: dict[str, int] = {}
        for ctx in self._contexts:
            for g in ctx.associated_groups:
                group_counts[g["name"]] = group_counts.get(g["name"], 0) + 1

        return {
            "total_enriched": len(self._contexts),
            "in_kev": sum(1 for c in self._contexts if c.in_kev),
            "actively_exploited": sum(1 for c in self._contexts if c.active_exploitation),
            "apt_linked": sum(1 for c in self._contexts if c.associated_groups),
            "threat_groups": dict(sorted(group_counts.items(), key=lambda x: x[1], reverse=True)),
            "threat_levels": {
                level: sum(1 for c in self._contexts if c.threat_level == level)
                for level in ["critical", "high", "elevated", "standard"]
            },
        }
