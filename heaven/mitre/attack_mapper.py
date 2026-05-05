"""
HEAVEN — MITRE ATT&CK Technique Mapper
Maps every vulnerability finding to ATT&CK Tactics, Techniques, and Sub-techniques.
Covers all 14 tactics from Reconnaissance through Impact.
Generates ATT&CK Navigator heatmap layers for visualization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger("mitre.mapper")


class Tactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEV = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIV_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    C2 = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


TACTIC_NAMES = {
    Tactic.RECONNAISSANCE: "Reconnaissance",
    Tactic.RESOURCE_DEV: "Resource Development",
    Tactic.INITIAL_ACCESS: "Initial Access",
    Tactic.EXECUTION: "Execution",
    Tactic.PERSISTENCE: "Persistence",
    Tactic.PRIV_ESCALATION: "Privilege Escalation",
    Tactic.DEFENSE_EVASION: "Defense Evasion",
    Tactic.CREDENTIAL_ACCESS: "Credential Access",
    Tactic.DISCOVERY: "Discovery",
    Tactic.LATERAL_MOVEMENT: "Lateral Movement",
    Tactic.COLLECTION: "Collection",
    Tactic.C2: "Command and Control",
    Tactic.EXFILTRATION: "Exfiltration",
    Tactic.IMPACT: "Impact",
}


@dataclass
class TechniqueMapping:
    technique_id: str
    technique_name: str
    tactic: Tactic
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    confidence: float = 0.8
    description: str = ""
    mitigations: list[str] = field(default_factory=list)
    detection: str = ""


@dataclass
class AttackMapping:
    """A vulnerability mapped to MITRE ATT&CK."""
    finding_id: str
    finding_title: str
    finding_severity: str
    techniques: list[TechniqueMapping] = field(default_factory=list)
    kill_chain_phase: str = ""
    risk_multiplier: float = 1.0

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "severity": self.finding_severity,
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.technique_name,
                    "sub_id": t.sub_technique_id,
                    "sub_name": t.sub_technique_name,
                    "tactic": TACTIC_NAMES.get(t.tactic, ""),
                    "tactic_id": t.tactic.value,
                    "confidence": t.confidence,
                }
                for t in self.techniques
            ],
            "kill_chain_phase": self.kill_chain_phase,
            "risk_multiplier": self.risk_multiplier,
        }


# ═══════════════════════════════════════════
# CWE → ATT&CK MAPPING DATABASE
# Comprehensive mapping of CWE IDs to MITRE ATT&CK techniques
# ═══════════════════════════════════════════

CWE_TO_ATTACK: dict[str, list[dict]] = {
    # SQL Injection family
    "CWE-89": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": Tactic.EXECUTION},
    ],
    # XSS
    "CWE-79": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": Tactic.COLLECTION},
    ],
    # Command Injection
    "CWE-78": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": Tactic.EXECUTION},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
    ],
    # Path Traversal
    "CWE-22": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": Tactic.DISCOVERY},
        {"id": "T1005", "name": "Data from Local System", "tactic": Tactic.COLLECTION},
    ],
    # SSRF
    "CWE-918": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Broken Authentication
    "CWE-287": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1110", "name": "Brute Force", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Hardcoded Credentials
    "CWE-798": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1552.001", "name": "Credentials In Files", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Deserialization
    "CWE-502": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": Tactic.EXECUTION},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": Tactic.EXECUTION},
    ],
    # XXE
    "CWE-611": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1005", "name": "Data from Local System", "tactic": Tactic.COLLECTION},
    ],
    # CORS Misconfiguration
    "CWE-942": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": Tactic.COLLECTION},
    ],
    # Race Condition
    "CWE-362": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": Tactic.PRIV_ESCALATION},
    ],
    # JWT Issues
    "CWE-347": [
        {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": Tactic.LATERAL_MOVEMENT},
        {"id": "T1134", "name": "Access Token Manipulation", "tactic": Tactic.DEFENSE_EVASION},
    ],
    # Open Redirect
    "CWE-601": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": Tactic.INITIAL_ACCESS},
    ],
    # LDAP Injection
    "CWE-90": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1087", "name": "Account Discovery", "tactic": Tactic.DISCOVERY},
    ],
    # Kerberos Issues
    "CWE-522": [
        {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": Tactic.CREDENTIAL_ACCESS},
        {"id": "T1558.003", "name": "Kerberoasting", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Subdomain Takeover
    "CWE-284": [
        {"id": "T1584.001", "name": "Domains", "tactic": Tactic.RESOURCE_DEV},
    ],
    # Request Smuggling
    "CWE-444": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Weak Crypto
    "CWE-326": [
        {"id": "T1600", "name": "Weaken Encryption", "tactic": Tactic.DEFENSE_EVASION},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": Tactic.CREDENTIAL_ACCESS},
    ],
    # Missing Auth
    "CWE-306": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": Tactic.INITIAL_ACCESS},
    ],
    # Privilege Escalation
    "CWE-269": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": Tactic.PRIV_ESCALATION},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": Tactic.PRIV_ESCALATION},
    ],
    # Information Disclosure
    "CWE-200": [
        {"id": "T1082", "name": "System Information Discovery", "tactic": Tactic.DISCOVERY},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": Tactic.DISCOVERY},
    ],
}

# Vulnerability type → ATT&CK mapping (for findings without CWE)
VULN_TYPE_TO_ATTACK: dict[str, list[dict]] = {
    "sqli": CWE_TO_ATTACK.get("CWE-89", []),
    "xss": CWE_TO_ATTACK.get("CWE-79", []),
    "ssrf": CWE_TO_ATTACK.get("CWE-918", []),
    "rce": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": Tactic.EXECUTION}],
    "lfi": CWE_TO_ATTACK.get("CWE-22", []),
    "default_credentials": CWE_TO_ATTACK.get("CWE-798", []),
    "jwt_none_algorithm": CWE_TO_ATTACK.get("CWE-347", []),
    "jwt_weak_secret": CWE_TO_ATTACK.get("CWE-347", []),
    "subdomain_takeover": CWE_TO_ATTACK.get("CWE-284", []),
    "request_smuggling": CWE_TO_ATTACK.get("CWE-444", []),
    "race_condition": CWE_TO_ATTACK.get("CWE-362", []),
    "kerberoasting": [{"id": "T1558.003", "name": "Kerberoasting", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "asrep_roasting": [{"id": "T1558.004", "name": "AS-REP Roasting", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "dcsync": [{"id": "T1003.006", "name": "DCSync", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "golden_ticket": [{"id": "T1558.001", "name": "Golden Ticket", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "silver_ticket": [{"id": "T1558.002", "name": "Silver Ticket", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "ntlm_relay": [{"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning", "tactic": Tactic.CREDENTIAL_ACCESS}],
    "pass_the_hash": [{"id": "T1550.002", "name": "Pass the Hash", "tactic": Tactic.LATERAL_MOVEMENT}],
    "container_escape": [{"id": "T1611", "name": "Escape to Host", "tactic": Tactic.PRIV_ESCALATION}],
    "k8s_misconfig": [{"id": "T1609", "name": "Container Administration Command", "tactic": Tactic.EXECUTION}],
    "iot_default_creds": CWE_TO_ATTACK.get("CWE-798", []),
    "mqtt_unauth": [{"id": "T1071", "name": "Application Layer Protocol", "tactic": Tactic.C2}],
    "graphql_introspection": [{"id": "T1082", "name": "System Information Discovery", "tactic": Tactic.DISCOVERY}],
    "bola": [{"id": "T1078", "name": "Valid Accounts", "tactic": Tactic.INITIAL_ACCESS}],
    "email_spoofing": [{"id": "T1566", "name": "Phishing", "tactic": Tactic.INITIAL_ACCESS}],
    "spf_bypass": [{"id": "T1566.002", "name": "Spearphishing Link", "tactic": Tactic.INITIAL_ACCESS}],
}


class MITREAttackMapper:
    """
    Core MITRE ATT&CK mapping engine.
    Maps vulnerability findings to ATT&CK Tactics, Techniques, and Sub-techniques.
    """

    def __init__(self):
        self._mappings: list[AttackMapping] = []
        self._technique_counts: dict[str, int] = {}
        self._tactic_counts: dict[str, int] = {}

    def map_finding(self, finding: dict) -> AttackMapping:
        """Map a single vulnerability finding to ATT&CK techniques."""
        cwe = finding.get("cwe", finding.get("cwe_id", ""))
        vuln_type = finding.get("vuln_type", finding.get("type", "")).lower()
        severity = finding.get("severity", "medium")

        techniques = []

        # Try CWE mapping first
        if cwe and cwe in CWE_TO_ATTACK:
            for tech in CWE_TO_ATTACK[cwe]:
                tid = tech["id"]
                sub_id = None
                sub_name = None
                if "." in tid:
                    sub_id = tid
                    sub_name = tech["name"]
                    tid = tid.split(".")[0]
                techniques.append(TechniqueMapping(
                    technique_id=tid, technique_name=tech["name"],
                    tactic=tech["tactic"], sub_technique_id=sub_id,
                    sub_technique_name=sub_name, confidence=0.9,
                ))

        # Fallback to vuln_type mapping
        if not techniques and vuln_type:
            for vtype, techs in VULN_TYPE_TO_ATTACK.items():
                if vtype in vuln_type:
                    for tech in techs:
                        tid = tech["id"]
                        sub_id = None
                        sub_name = None
                        if "." in tid:
                            sub_id = tid
                            sub_name = tech["name"]
                            tid = tid.split(".")[0]
                        techniques.append(TechniqueMapping(
                            technique_id=tid, technique_name=tech["name"],
                            tactic=tech["tactic"], sub_technique_id=sub_id,
                            sub_technique_name=sub_name, confidence=0.75,
                        ))
                    break

        # Risk multiplier based on technique severity in real attacks
        risk_mult = 1.0
        for t in techniques:
            if t.tactic in (Tactic.INITIAL_ACCESS, Tactic.EXECUTION):
                risk_mult = max(risk_mult, 1.5)
            elif t.tactic in (Tactic.PRIV_ESCALATION, Tactic.CREDENTIAL_ACCESS):
                risk_mult = max(risk_mult, 2.0)
            elif t.tactic == Tactic.LATERAL_MOVEMENT:
                risk_mult = max(risk_mult, 2.5)

        mapping = AttackMapping(
            finding_id=finding.get("id", ""),
            finding_title=finding.get("title", ""),
            finding_severity=severity,
            techniques=techniques,
            risk_multiplier=risk_mult,
        )
        self._mappings.append(mapping)

        # Update counts
        for t in techniques:
            self._technique_counts[t.technique_id] = self._technique_counts.get(t.technique_id, 0) + 1
            tactic_name = TACTIC_NAMES.get(t.tactic, "")
            self._tactic_counts[tactic_name] = self._tactic_counts.get(tactic_name, 0) + 1

        return mapping

    def map_all_findings(self, findings: list[dict]) -> list[AttackMapping]:
        """Map all findings to ATT&CK techniques."""
        logger.info(f"Mapping {len(findings)} findings to MITRE ATT&CK...")
        mappings = [self.map_finding(f) for f in findings]
        mapped = sum(1 for m in mappings if m.techniques)
        logger.info(f"ATT&CK mapping complete: {mapped}/{len(findings)} findings mapped")
        return mappings

    def generate_navigator_layer(self, name: str = "HEAVEN Scan") -> dict:
        """Generate ATT&CK Navigator layer JSON for visualization."""
        techniques = []
        for tech_id, count in self._technique_counts.items():
            score = min(count * 20, 100)
            techniques.append({
                "techniqueID": tech_id,
                "score": score,
                "color": self._score_to_color(score),
                "comment": f"Found in {count} vulnerability(ies)",
                "enabled": True,
            })

        return {
            "name": name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"HEAVEN scan results — {len(self._mappings)} findings mapped",
            "techniques": techniques,
            "gradient": {
                "colors": ["#66ff66", "#ffff00", "#ff6600", "#ff0000"],
                "minValue": 0, "maxValue": 100,
            },
            "legendItems": [
                {"label": "Low (1-2 findings)", "color": "#66ff66"},
                {"label": "Medium (3-5 findings)", "color": "#ffff00"},
                {"label": "High (6-10 findings)", "color": "#ff6600"},
                {"label": "Critical (10+ findings)", "color": "#ff0000"},
            ],
        }

    def export_navigator_layer(self, output_path: Path, name: str = "HEAVEN Scan") -> None:
        layer = self.generate_navigator_layer(name)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(layer, indent=2))
        logger.info(f"ATT&CK Navigator layer exported to {output_path}")

    def get_tactic_coverage(self) -> dict:
        """Get coverage across all 14 ATT&CK tactics."""
        coverage = {}
        for tactic in Tactic:
            name = TACTIC_NAMES[tactic]
            count = self._tactic_counts.get(name, 0)
            coverage[name] = {
                "tactic_id": tactic.value,
                "findings_count": count,
                "covered": count > 0,
            }
        covered = sum(1 for v in coverage.values() if v["covered"])
        return {"tactics": coverage, "coverage_pct": round(covered / len(Tactic) * 100, 1)}

    def summary(self) -> dict:
        return {
            "total_mappings": len(self._mappings),
            "unique_techniques": len(self._technique_counts),
            "tactic_coverage": self.get_tactic_coverage(),
            "top_techniques": dict(sorted(self._technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    @staticmethod
    def _score_to_color(score: int) -> str:
        if score >= 80:
            return "#ff0000"
        elif score >= 60:
            return "#ff6600"
        elif score >= 40:
            return "#ffff00"
        return "#66ff66"
