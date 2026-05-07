"""
HEAVEN — Cyber Kill Chain (Lockheed Martin) Mapping & Coverage Reporting.

This is a *defensive reporting* module. It maps findings (vulnerabilities,
misconfigurations, exposed services) onto the seven Lockheed Cyber Kill Chain
phases so reports can show which phases of an attacker's workflow are enabled
by the issues HEAVEN detected.

This module DOES NOT execute kill chain phases. It does not weaponize, deliver,
install, or exfiltrate. It only categorizes findings for reporting.

Phases (Lockheed CKC v1):
  1. Reconnaissance   — info gathering (exposed services, leaks, OSINT)
  2. Weaponization    — attacker-side; HEAVEN flags conditions that make this easy
  3. Delivery         — entry vectors (phishing exposure, exposed upload endpoints)
  4. Exploitation     — vulns that grant code execution or auth bypass
  5. Installation     — persistence enablers (writable webroots, weak SSH, etc.)
  6. Command & Control — outbound channels, exposed mgmt interfaces, weak egress filtering
  7. Actions on Objectives — data exposure (open S3, public DBs, exfil paths)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable

from heaven.utils.logger import get_logger

logger = get_logger("mitre.kill_chain")


class KillChainPhase(IntEnum):
    """Lockheed Cyber Kill Chain phases (canonical 7-phase model)."""
    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    EXPLOITATION = 4
    INSTALLATION = 5
    COMMAND_AND_CONTROL = 6
    ACTIONS_ON_OBJECTIVES = 7

    @property
    def label(self) -> str:
        return {
            1: "Reconnaissance",
            2: "Weaponization",
            3: "Delivery",
            4: "Exploitation",
            5: "Installation",
            6: "Command & Control",
            7: "Actions on Objectives",
        }[self.value]


# ── Vuln-type → kill chain phase(s) ──
# A finding can light up multiple phases (e.g. SSRF enables both Exploitation
# and Actions-on-Objectives via cloud-metadata exfil).
VULN_KILLCHAIN_MAP: dict[str, list[KillChainPhase]] = {
    # Recon enablers
    "open_port": [KillChainPhase.RECONNAISSANCE],
    "service_banner_leak": [KillChainPhase.RECONNAISSANCE],
    "directory_listing": [KillChainPhase.RECONNAISSANCE],
    "info_disclosure": [KillChainPhase.RECONNAISSANCE],
    "subdomain_takeover_candidate": [KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY],
    "git_secret": [KillChainPhase.RECONNAISSANCE, KillChainPhase.EXPLOITATION],
    "exposed_admin_panel": [KillChainPhase.RECONNAISSANCE, KillChainPhase.DELIVERY],
    # Weaponization-enabling conditions
    "outdated_software": [KillChainPhase.WEAPONIZATION, KillChainPhase.EXPLOITATION],
    "known_cve": [KillChainPhase.WEAPONIZATION, KillChainPhase.EXPLOITATION],
    # Delivery
    "exposed_upload": [KillChainPhase.DELIVERY],
    "missing_email_authentication": [KillChainPhase.DELIVERY],  # SPF/DKIM/DMARC gap
    "open_redirect": [KillChainPhase.DELIVERY],
    "subdomain_takeover": [KillChainPhase.DELIVERY],
    # Exploitation — code execution / auth bypass
    "sqli": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "xss": [KillChainPhase.EXPLOITATION, KillChainPhase.DELIVERY],
    "ssrf": [KillChainPhase.EXPLOITATION, KillChainPhase.RECONNAISSANCE,
             KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "ssti": [KillChainPhase.EXPLOITATION],
    "xxe": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "command_injection": [KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION],
    "buffer_overflow": [KillChainPhase.EXPLOITATION],
    "deserialization": [KillChainPhase.EXPLOITATION],
    "path_traversal": [KillChainPhase.EXPLOITATION, KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "auth_bypass": [KillChainPhase.EXPLOITATION],
    "default_credentials": [KillChainPhase.EXPLOITATION],
    "weak_ssh": [KillChainPhase.EXPLOITATION, KillChainPhase.INSTALLATION],
    "jwt_none_alg": [KillChainPhase.EXPLOITATION],
    "jwt_weak_secret": [KillChainPhase.EXPLOITATION],
    "request_smuggling": [KillChainPhase.EXPLOITATION],
    # Installation enablers
    "writable_webroot": [KillChainPhase.INSTALLATION],
    "world_writable_config": [KillChainPhase.INSTALLATION],
    "weak_file_permissions": [KillChainPhase.INSTALLATION],
    # C2-related signals (we *detect*, don't establish)
    "exposed_mgmt_interface": [KillChainPhase.COMMAND_AND_CONTROL,
                                KillChainPhase.RECONNAISSANCE],
    "no_egress_filtering": [KillChainPhase.COMMAND_AND_CONTROL],
    "weak_dns_filtering": [KillChainPhase.COMMAND_AND_CONTROL],
    # Actions on Objectives
    "public_s3": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "exposed_database": [KillChainPhase.ACTIONS_ON_OBJECTIVES,
                          KillChainPhase.RECONNAISSANCE],
    "iam_excessive": [KillChainPhase.ACTIONS_ON_OBJECTIVES,
                       KillChainPhase.INSTALLATION],
    "hardcoded_secret": [KillChainPhase.EXPLOITATION,
                          KillChainPhase.ACTIONS_ON_OBJECTIVES],
    "data_exfil_channel": [KillChainPhase.ACTIONS_ON_OBJECTIVES],
}


# ── MITRE ATT&CK technique → kill chain phase ──
# Coarse mapping. ATT&CK is more granular; this rolls up to the 7-phase model.
MITRE_TO_KILLCHAIN: dict[str, KillChainPhase] = {
    # Recon
    "T1589": KillChainPhase.RECONNAISSANCE, "T1590": KillChainPhase.RECONNAISSANCE,
    "T1591": KillChainPhase.RECONNAISSANCE, "T1592": KillChainPhase.RECONNAISSANCE,
    "T1593": KillChainPhase.RECONNAISSANCE, "T1594": KillChainPhase.RECONNAISSANCE,
    "T1595": KillChainPhase.RECONNAISSANCE, "T1596": KillChainPhase.RECONNAISSANCE,
    "T1597": KillChainPhase.RECONNAISSANCE, "T1598": KillChainPhase.RECONNAISSANCE,
    # Resource Development (~weaponization)
    "T1583": KillChainPhase.WEAPONIZATION, "T1584": KillChainPhase.WEAPONIZATION,
    "T1585": KillChainPhase.WEAPONIZATION, "T1587": KillChainPhase.WEAPONIZATION,
    "T1588": KillChainPhase.WEAPONIZATION, "T1608": KillChainPhase.WEAPONIZATION,
    # Initial Access (~delivery + exploitation overlap)
    "T1189": KillChainPhase.DELIVERY,        # Drive-by Compromise
    "T1190": KillChainPhase.EXPLOITATION,    # Exploit Public-Facing App
    "T1133": KillChainPhase.DELIVERY,        # External Remote Services
    "T1200": KillChainPhase.DELIVERY,        # Hardware Additions
    "T1566": KillChainPhase.DELIVERY,        # Phishing
    "T1091": KillChainPhase.DELIVERY,        # Replication Through Removable Media
    "T1195": KillChainPhase.DELIVERY,        # Supply Chain Compromise
    "T1199": KillChainPhase.DELIVERY,        # Trusted Relationship
    "T1078": KillChainPhase.EXPLOITATION,    # Valid Accounts
    # Execution
    "T1059": KillChainPhase.EXPLOITATION, "T1106": KillChainPhase.EXPLOITATION,
    "T1129": KillChainPhase.EXPLOITATION, "T1203": KillChainPhase.EXPLOITATION,
    # Persistence (~installation)
    "T1098": KillChainPhase.INSTALLATION, "T1136": KillChainPhase.INSTALLATION,
    "T1543": KillChainPhase.INSTALLATION, "T1547": KillChainPhase.INSTALLATION,
    "T1574": KillChainPhase.INSTALLATION,
    # Privilege Escalation — keep with installation/exploitation depending on technique
    "T1068": KillChainPhase.EXPLOITATION, "T1548": KillChainPhase.EXPLOITATION,
    # Defense Evasion — straddles, default to installation (attacker hiding)
    "T1027": KillChainPhase.INSTALLATION, "T1070": KillChainPhase.INSTALLATION,
    "T1140": KillChainPhase.INSTALLATION, "T1562": KillChainPhase.INSTALLATION,
    # Credential Access — usually post-exploitation, keep with exploitation
    "T1003": KillChainPhase.EXPLOITATION, "T1110": KillChainPhase.EXPLOITATION,
    "T1552": KillChainPhase.EXPLOITATION, "T1555": KillChainPhase.EXPLOITATION,
    "T1557": KillChainPhase.EXPLOITATION,
    # Discovery — kill chain doesn't have a discrete phase; map to recon
    "T1083": KillChainPhase.RECONNAISSANCE, "T1087": KillChainPhase.RECONNAISSANCE,
    "T1018": KillChainPhase.RECONNAISSANCE, "T1046": KillChainPhase.RECONNAISSANCE,
    # Lateral Movement — installation-ish (attacker establishing footholds)
    "T1021": KillChainPhase.INSTALLATION, "T1080": KillChainPhase.INSTALLATION,
    "T1550": KillChainPhase.INSTALLATION,
    # Collection — pre-exfil, group with Actions-on-Objectives
    "T1005": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1530": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1602": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    # Command & Control
    "T1071": KillChainPhase.COMMAND_AND_CONTROL,
    "T1090": KillChainPhase.COMMAND_AND_CONTROL,
    "T1095": KillChainPhase.COMMAND_AND_CONTROL,
    "T1572": KillChainPhase.COMMAND_AND_CONTROL,
    "T1573": KillChainPhase.COMMAND_AND_CONTROL,
    # Exfiltration / Impact → Actions on Objectives
    "T1041": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1048": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1567": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1485": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1486": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1496": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "T1565": KillChainPhase.ACTIONS_ON_OBJECTIVES,
}


@dataclass
class PhaseCoverage:
    phase: KillChainPhase
    findings: list[dict] = field(default_factory=list)
    techniques: set[str] = field(default_factory=set)
    severity_breakdown: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self) -> dict:
        return {
            "phase_id": int(self.phase),
            "phase": self.phase.label,
            "finding_count": len(self.findings),
            "techniques": sorted(self.techniques),
            "severity_breakdown": dict(self.severity_breakdown),
            "findings": self.findings,
        }


class KillChainAnalyzer:
    """
    Maps findings to Lockheed Cyber Kill Chain phases and produces
    coverage reports.

    Usage:
        analyzer = KillChainAnalyzer()
        analyzer.ingest(findings)         # list of dicts
        report = analyzer.report()        # full per-phase breakdown
        score = analyzer.coverage_score() # 0-100, higher = more phases covered
    """

    def __init__(self):
        self._coverage: dict[KillChainPhase, PhaseCoverage] = {
            phase: PhaseCoverage(phase=phase) for phase in KillChainPhase
        }

    def _phases_for_finding(self, finding: dict) -> list[KillChainPhase]:
        """Resolve which kill chain phase(s) a finding lights up."""
        phases: set[KillChainPhase] = set()

        # 1. Direct mapping by vuln_type / type
        vuln_type = (finding.get("vuln_type") or finding.get("type")
                     or finding.get("category") or "").lower()
        if vuln_type in VULN_KILLCHAIN_MAP:
            phases.update(VULN_KILLCHAIN_MAP[vuln_type])

        # 2. By MITRE technique ID if present
        tech = finding.get("mitre_technique") or finding.get("technique") or ""
        if tech:
            # Normalise — strip sub-technique suffix for top-level lookup
            base = tech.split(".")[0].strip().upper()
            if base in MITRE_TO_KILLCHAIN:
                phases.add(MITRE_TO_KILLCHAIN[base])

        # 3. Heuristic — keyword in description / title
        text = " ".join([
            str(finding.get("title", "")),
            str(finding.get("description", "")),
        ]).lower()
        if not phases:
            if any(k in text for k in ("phishing", "spear", "drive-by")):
                phases.add(KillChainPhase.DELIVERY)
            elif any(k in text for k in ("rce", "remote code execution", "exploit")):
                phases.add(KillChainPhase.EXPLOITATION)
            elif any(k in text for k in ("persistence", "backdoor", "scheduled task", "service install")):
                phases.add(KillChainPhase.INSTALLATION)
            elif any(k in text for k in ("c2", "command and control", "beacon", "tunnel")):
                phases.add(KillChainPhase.COMMAND_AND_CONTROL)
            elif any(k in text for k in ("exfil", "data leak", "dump")):
                phases.add(KillChainPhase.ACTIONS_ON_OBJECTIVES)
            elif any(k in text for k in ("info disclosure", "banner", "version leak", "directory listing")):
                phases.add(KillChainPhase.RECONNAISSANCE)

        return sorted(phases)

    def ingest(self, findings: Iterable[dict]) -> int:
        """Categorise an iterable of findings. Returns the number ingested."""
        count = 0
        for f in findings:
            count += 1
            phases = self._phases_for_finding(f)
            severity = (f.get("severity") or "info").lower()
            tech = f.get("mitre_technique") or f.get("technique") or ""

            if not phases:
                # Couldn't categorise — log for visibility, default to Recon
                logger.debug(f"Could not map finding to kill chain phase: "
                             f"{f.get('title', f.get('type', 'unknown'))}")
                phases = [KillChainPhase.RECONNAISSANCE]

            # Resolve a useful title — fall back chain to make the
            # "Attack workflow" output meaningful.
            title = (f.get("title") or f.get("vuln_type") or f.get("type")
                     or f.get("cve_id") or "Unknown finding")

            for phase in phases:
                cov = self._coverage[phase]
                cov.findings.append({
                    "title": title,
                    "severity": severity,
                    "target": f.get("target", ""),
                    "technique": tech,
                    "cve": f.get("cve_id", ""),
                })
                if tech:
                    cov.techniques.add(tech)
                cov.severity_breakdown[severity] += 1
        return count

    def coverage_score(self) -> int:
        """
        0-100 score based on how many kill chain phases have findings.
        Each covered phase = 100/7 ≈ 14.3 points.
        """
        covered = sum(1 for c in self._coverage.values() if c.findings)
        return round(covered * 100 / len(KillChainPhase))

    def report(self) -> dict:
        """Full per-phase report, including coverage score."""
        phases_data = [self._coverage[phase].to_dict() for phase in KillChainPhase]
        total_findings = sum(c["finding_count"] for c in phases_data)
        return {
            "model": "Lockheed Cyber Kill Chain",
            "phase_count": len(KillChainPhase),
            "phases_with_findings": sum(1 for p in phases_data if p["finding_count"]),
            "coverage_score": self.coverage_score(),
            "total_findings_mapped": total_findings,
            "phases": phases_data,
        }

    def attack_path_summary(self) -> list[dict]:
        """
        Return the chain of phases an attacker could string together end-to-end
        based on findings present. Only returns phases with findings.
        """
        path = []
        for phase in KillChainPhase:
            cov = self._coverage[phase]
            if cov.findings:
                # Pick the highest-severity finding as the representative
                sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                rep = min(cov.findings, key=lambda f: sev_rank.get(f["severity"], 9))
                path.append({
                    "phase": phase.label,
                    "phase_id": int(phase),
                    "representative_finding": rep["title"],
                    "severity": rep["severity"],
                    "total_findings": len(cov.findings),
                })
        return path

    def to_mermaid(self) -> str:
        """Generate a Mermaid diagram of phase coverage."""
        lines = ["graph LR"]
        lines.append("  classDef covered fill:#ff4444,stroke:#aa0000,color:#fff")
        lines.append("  classDef empty fill:#1e1e2e,stroke:#444,color:#888")
        prev = None
        for phase in KillChainPhase:
            cov = self._coverage[phase]
            node_id = f"P{int(phase)}"
            count = len(cov.findings)
            klass = "covered" if count > 0 else "empty"
            label = f"{phase.label}<br/>{count} finding{'s' if count != 1 else ''}"
            lines.append(f"  {node_id}[{label}]:::{klass}")
            if prev is not None:
                lines.append(f"  {prev} --> {node_id}")
            prev = node_id
        return "\n".join(lines)


def analyze_findings(findings: Iterable[dict]) -> dict:
    """Convenience wrapper — single call to get a full kill chain report."""
    analyzer = KillChainAnalyzer()
    analyzer.ingest(findings)
    return analyzer.report()
