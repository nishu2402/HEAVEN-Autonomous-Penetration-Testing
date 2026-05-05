"""
HEAVEN — Attack Chain Engine (Kill Chain Automator)
The brain of an expert pentester: automatically discovers and chains
vulnerabilities into full attack paths from initial access to crown jewels.

Maps: Recon → Initial Access → Privilege Escalation → Lateral Movement →
      Persistence → Data Exfiltration → Impact

This is what separates a scanner from a real pentester.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum

from heaven.utils.logger import get_logger

logger = get_logger("attack.chain")


class TacticPhase(IntEnum):
    """MITRE ATT&CK aligned kill chain phases."""
    RECON = 1
    INITIAL_ACCESS = 2
    EXECUTION = 3
    PERSISTENCE = 4
    PRIVILEGE_ESCALATION = 5
    DEFENSE_EVASION = 6
    CREDENTIAL_ACCESS = 7
    DISCOVERY = 8
    LATERAL_MOVEMENT = 9
    COLLECTION = 10
    EXFILTRATION = 11
    IMPACT = 12


@dataclass
class AttackNode:
    """A single step in an attack chain."""
    node_id: str
    host: str
    port: int = 0
    vulnerability: str = ""          # CVE or HEAVEN-ID
    technique: str = ""              # MITRE technique ID (T1190, etc.)
    tactic: TacticPhase = TacticPhase.RECON
    description: str = ""
    confidence: float = 0.0          # 0-1
    prerequisites: list[str] = field(default_factory=list)  # Required node_ids
    provides: list[str] = field(default_factory=list)       # Capabilities gained
    evidence: dict = field(default_factory=dict)


@dataclass
class AttackChain:
    """A complete attack path from entry to objective."""
    chain_id: str
    name: str
    nodes: list[AttackNode] = field(default_factory=list)
    total_confidence: float = 0.0
    max_impact: str = "low"
    entry_point: str = ""
    crown_jewel: str = ""
    mitre_tactics: list[str] = field(default_factory=list)
    estimated_time_hours: float = 0.0
    difficulty: str = "medium"       # trivial, easy, medium, hard, expert

    def generate_mermaid_graph(self) -> str:
        """Generate a Mermaid.js flowchart of the attack path."""
        lines = ["graph TD"]
        lines.append("  classDef default fill:#1e1e1e,stroke:#333,stroke-width:2px,color:#fff;")
        lines.append("  classDef recon fill:#0b3d91,stroke:#4fa3e3;")
        lines.append("  classDef exploit fill:#8b0000,stroke:#ff4500;")
        lines.append("  classDef objective fill:#ffd700,stroke:#daa520,color:#000;")
        
        # Start node
        lines.append("  Start((Attacker)):::recon")
        
        if not self.nodes:
            lines.append("  Start -->|No path found| End(((Target)))")
            return "\\n".join(lines)
            
        prev_id = "Start"
        for i, node in enumerate(self.nodes):
            safe_host = str(node.host).replace(".", "_").replace("-", "_").replace(":", "_")
            node_id = f"N{i}_{safe_host}"
            
            # Format label
            label = f"{node.technique}<br/>{node.vulnerability}" if node.vulnerability else f"{node.technique}"
            
            # Add node
            if i == len(self.nodes) - 1:
                # Crown jewel / Final objective
                lines.append(f"  {node_id}[{node.host}<br/>{label}]:::objective")
            else:
                lines.append(f"  {node_id}[{node.host}<br/>{label}]:::exploit")
                
            # Add edge
            action = str(node.provides[0]) if node.provides else "exploits"
            lines.append(f"  {prev_id} -->|{action}| {node_id}")
            prev_id = node_id
            
        return "\\n".join(lines)


# ── Vulnerability-to-Tactic Mapping ──
# Maps vulnerability types to what an attacker gains from them

VULN_CAPABILITY_MAP = {
    # Web vulns
    "sqli": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["db_read", "db_write", "credential_dump", "potential_rce"],
        "technique": "T1190",
        "chains_to": ["credential_access", "data_exfil", "privilege_escalation"],
    },
    "xss": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["session_hijack", "credential_phish", "dom_manipulation"],
        "technique": "T1189",
        "chains_to": ["credential_access", "account_takeover"],
    },
    "ssrf": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["internal_access", "cloud_metadata", "port_scan_internal"],
        "technique": "T1190",
        "chains_to": ["lateral_movement", "cloud_takeover", "credential_access"],
    },
    "ssti": {
        "tactic": TacticPhase.EXECUTION,
        "provides": ["rce", "file_read", "file_write"],
        "technique": "T1059",
        "chains_to": ["persistence", "privilege_escalation", "data_exfil"],
    },
    "command_injection": {
        "tactic": TacticPhase.EXECUTION,
        "provides": ["rce", "file_read", "file_write", "reverse_shell"],
        "technique": "T1059",
        "chains_to": ["persistence", "privilege_escalation", "lateral_movement"],
    },
    "path_traversal": {
        "tactic": TacticPhase.CREDENTIAL_ACCESS,
        "provides": ["file_read", "config_read", "credential_dump"],
        "technique": "T1083",
        "chains_to": ["credential_access", "privilege_escalation"],
    },
    "xxe": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["file_read", "ssrf", "internal_access"],
        "technique": "T1190",
        "chains_to": ["credential_access", "lateral_movement"],
    },
    # Network vulns
    "buffer_overflow": {
        "tactic": TacticPhase.EXECUTION,
        "provides": ["rce", "code_execution", "memory_control"],
        "technique": "T1203",
        "chains_to": ["persistence", "privilege_escalation"],
    },
    "weak_ssh": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["shell_access", "file_read", "file_write"],
        "technique": "T1021",
        "chains_to": ["privilege_escalation", "lateral_movement", "persistence"],
    },
    "default_credentials": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["authenticated_access", "admin_panel"],
        "technique": "T1078",
        "chains_to": ["execution", "privilege_escalation", "data_exfil"],
    },
    # Cloud vulns
    "public_s3": {
        "tactic": TacticPhase.COLLECTION,
        "provides": ["data_read", "potential_data_write", "credential_dump"],
        "technique": "T1530",
        "chains_to": ["data_exfil", "credential_access"],
    },
    "iam_excessive": {
        "tactic": TacticPhase.PRIVILEGE_ESCALATION,
        "provides": ["cloud_admin", "resource_creation", "data_access"],
        "technique": "T1078.004",
        "chains_to": ["lateral_movement", "persistence", "impact"],
    },
    # Secrets
    "hardcoded_secret": {
        "tactic": TacticPhase.CREDENTIAL_ACCESS,
        "provides": ["api_access", "service_auth", "potential_admin"],
        "technique": "T1552",
        "chains_to": ["initial_access", "lateral_movement", "privilege_escalation"],
    },
    # Auth vulns
    "cors_misconfig": {
        "tactic": TacticPhase.CREDENTIAL_ACCESS,
        "provides": ["cross_origin_data", "session_theft"],
        "technique": "T1557",
        "chains_to": ["account_takeover"],
    },
    "open_redirect": {
        "tactic": TacticPhase.INITIAL_ACCESS,
        "provides": ["phishing_vector", "oauth_token_theft"],
        "technique": "T1566",
        "chains_to": ["credential_access", "account_takeover"],
    },
}

# ── Chain Patterns (Expert Pentester Knowledge) ──
# These are real-world attack chains that experienced pentesters know

KNOWN_CHAIN_PATTERNS = [
    {
        "name": "Web Shell → Domain Admin",
        "pattern": ["sqli|ssti|command_injection", "file_write", "reverse_shell",
                     "privilege_escalation", "credential_dump", "lateral_movement", "domain_admin"],
        "impact": "critical",
        "difficulty": "medium",
        "time_hours": 4,
    },
    {
        "name": "SSRF → Cloud Takeover",
        "pattern": ["ssrf", "cloud_metadata", "iam_credentials", "cloud_admin", "data_exfil"],
        "impact": "critical",
        "difficulty": "easy",
        "time_hours": 1,
    },
    {
        "name": "SQLi → Data Breach",
        "pattern": ["sqli", "db_read", "credential_dump", "privilege_escalation", "data_exfil"],
        "impact": "critical",
        "difficulty": "easy",
        "time_hours": 2,
    },
    {
        "name": "Git Secret → Lateral Movement",
        "pattern": ["hardcoded_secret", "api_access", "internal_access", "lateral_movement"],
        "impact": "high",
        "difficulty": "easy",
        "time_hours": 1,
    },
    {
        "name": "XSS → Account Takeover → Admin",
        "pattern": ["xss", "session_hijack", "admin_panel", "rce"],
        "impact": "critical",
        "difficulty": "medium",
        "time_hours": 3,
    },
    {
        "name": "Path Traversal → Credential Harvest → Pivot",
        "pattern": ["path_traversal", "config_read", "credential_dump", "lateral_movement"],
        "impact": "high",
        "difficulty": "medium",
        "time_hours": 2,
    },
    {
        "name": "Public S3 → Secrets → Full Compromise",
        "pattern": ["public_s3", "credential_dump", "cloud_admin", "data_exfil"],
        "impact": "critical",
        "difficulty": "trivial",
        "time_hours": 0.5,
    },
]


class AttackChainEngine:
    """
    Automatically discovers and chains vulnerabilities into attack paths.
    This is the expert pentester's brain — it connects dots that scanners miss.
    """

    def __init__(self):
        self.nodes: list[AttackNode] = []
        self.chains: list[AttackChain] = []
        self.capability_graph: dict[str, list[str]] = defaultdict(list)  # capability → nodes that provide it

    def ingest_findings(self, scan_results: dict) -> None:
        """Convert scan findings into attack graph nodes."""
        vulns = scan_results.get("vulnerabilities", [])
        secrets = scan_results.get("secrets", [])
        scan_results.get("assets", [])

        for i, vuln in enumerate(vulns):
            vuln_type = vuln.get("vuln_type", vuln.get("type", "unknown"))
            mapping = VULN_CAPABILITY_MAP.get(vuln_type, {})

            node = AttackNode(
                node_id=f"vuln-{i}",
                host=vuln.get("host", vuln.get("asset", "")),
                port=vuln.get("port", 0),
                vulnerability=vuln.get("cve", vuln.get("cve_id", f"HEAVEN-{vuln_type.upper()}")),
                technique=mapping.get("technique", ""),
                tactic=mapping.get("tactic", TacticPhase.RECON),
                description=vuln.get("title", vuln.get("description", "")),
                confidence=vuln.get("confidence", vuln.get("validation_confidence", 0.5)),
                provides=mapping.get("provides", []),
                evidence={"source": "vulnerability_scan"},
            )
            self.nodes.append(node)

            for cap in node.provides:
                self.capability_graph[cap].append(node.node_id)

        for i, secret in enumerate(secrets):
            node = AttackNode(
                node_id=f"secret-{i}",
                host=secret.get("file", ""),
                vulnerability=f"HEAVEN-SECRET-{secret.get('type', 'unknown').upper()}",
                tactic=TacticPhase.CREDENTIAL_ACCESS,
                description=f"Hardcoded {secret.get('type', 'secret')} in {secret.get('file', 'unknown')}",
                confidence=0.9,
                provides=["api_access", "service_auth", "credential_dump"],
                evidence={"source": "secret_scan", "entropy": secret.get("entropy", 0)},
            )
            self.nodes.append(node)

        logger.info(f"Attack graph: {len(self.nodes)} nodes, {len(self.capability_graph)} capabilities")

    def discover_chains(self) -> list[AttackChain]:
        """Discover all viable attack chains from the vulnerability graph."""
        self.chains = []

        if not self.nodes:
            return []

        # Strategy 1: Match against known attack patterns
        for pattern in KNOWN_CHAIN_PATTERNS:
            matched_chains = self._match_pattern(pattern)
            self.chains.extend(matched_chains)

        # Strategy 2: Graph traversal — find all paths from external entry to high-value targets
        entry_nodes = [n for n in self.nodes
                       if n.tactic in (TacticPhase.INITIAL_ACCESS, TacticPhase.RECON)]
        crown_nodes = [n for n in self.nodes
                       if any(c in n.provides for c in ["rce", "cloud_admin", "domain_admin", "data_exfil"])]

        for entry in entry_nodes:
            for crown in crown_nodes:
                if entry.node_id == crown.node_id:
                    continue
                path = self._find_path(entry, crown)
                if path and len(path) >= 2:
                    chain = AttackChain(
                        chain_id=hashlib.md5(
                            f"{entry.node_id}-{crown.node_id}".encode()
                        ).hexdigest()[:8],
                        name=f"{entry.description[:30]} → {crown.description[:30]}",
                        nodes=path,
                        total_confidence=min(n.confidence for n in path),
                        max_impact="critical" if any("rce" in n.provides or "cloud_admin" in n.provides for n in path) else "high",
                        entry_point=f"{entry.host}:{entry.port}",
                        crown_jewel=crown.description,
                        mitre_tactics=[TacticPhase(n.tactic).name for n in path],
                    )
                    self.chains.append(chain)

        # Deduplicate and sort by impact
        seen = set()
        unique_chains = []
        for c in self.chains:
            key = tuple(n.node_id for n in c.nodes)
            if key not in seen:
                seen.add(key)
                unique_chains.append(c)

        self.chains = sorted(unique_chains, key=lambda c: c.total_confidence, reverse=True)
        logger.info(f"Discovered {len(self.chains)} attack chains")
        return self.chains

    def _match_pattern(self, pattern: dict) -> list[AttackChain]:
        """Match a known attack pattern against discovered vulnerabilities."""
        chains = []
        first_step = pattern["pattern"][0]

        # Find nodes matching the first step
        first_step_types = first_step.split("|")
        matching_entries = [
            n for n in self.nodes
            if any(t in n.vulnerability.lower() or t in str(n.provides) for t in first_step_types)
        ]

        for entry in matching_entries:
            chain_nodes = [entry]
            # Try to link remaining steps via capabilities
            for step in pattern["pattern"][1:]:
                linked = [n for n in self.nodes
                          if n not in chain_nodes and step in str(n.provides)]
                if linked:
                    chain_nodes.append(linked[0])

            if len(chain_nodes) >= 2:
                chains.append(AttackChain(
                    chain_id=hashlib.md5(
                        f"{pattern['name']}-{entry.node_id}".encode()
                    ).hexdigest()[:8],
                    name=f"{pattern['name']} via {entry.host}",
                    nodes=chain_nodes,
                    total_confidence=min(n.confidence for n in chain_nodes),
                    max_impact=pattern["impact"],
                    entry_point=f"{entry.host}:{entry.port}",
                    difficulty=pattern["difficulty"],
                    estimated_time_hours=pattern["time_hours"],
                    mitre_tactics=[TacticPhase(n.tactic).name for n in chain_nodes],
                ))

        return chains

    def _find_path(self, start: AttackNode, end: AttackNode, max_depth: int = 6) -> list[AttackNode]:
        """BFS to find shortest path between two nodes via capabilities."""
        queue = [(start, [start])]
        visited = {start.node_id}

        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue

            if current.node_id == end.node_id:
                return path

            # Find nodes reachable via capabilities this node provides
            for capability in current.provides:
                for node in self.nodes:
                    if node.node_id in visited:
                        continue
                    # Can reach this node if it needs a capability we provide
                    vuln_type = node.vulnerability.lower()
                    mapping = VULN_CAPABILITY_MAP.get(vuln_type, {})
                    if capability in mapping.get("provides", []) or capability in str(node.provides):
                        visited.add(node.node_id)
                        queue.append((node, path + [node]))

        return []

    def generate_mermaid(self) -> str:
        """Generate Mermaid diagram of the top attack chains."""
        if not self.chains:
            return "graph TD\n    A[No attack chains discovered]"

        lines = ["graph TD"]
        node_styles = []

        for chain in self.chains[:3]:  # Top 3 chains
            for i, node in enumerate(chain.nodes):
                safe_id = node.node_id.replace("-", "_")
                label = f"{node.host}\\n{node.vulnerability}"
                lines.append(f'    {safe_id}["{label}"]')

                if i > 0:
                    prev_id = chain.nodes[i - 1].node_id.replace("-", "_")
                    edge_label = node.provides[0] if node.provides else ""
                    lines.append(f"    {prev_id} -->|{edge_label}| {safe_id}")

                # Style by tactic
                if node.tactic <= TacticPhase.INITIAL_ACCESS:
                    node_styles.append(f"    style {safe_id} fill:#ff0040,stroke:#ff0040,color:#fff")
                elif node.tactic <= TacticPhase.EXECUTION:
                    node_styles.append(f"    style {safe_id} fill:#ff6600,stroke:#ff6600,color:#fff")
                else:
                    node_styles.append(f"    style {safe_id} fill:#1a1a2e,stroke:#00f0ff,color:#00f0ff")

        lines.extend(node_styles)
        return "\n".join(lines)

    def summary(self) -> dict:
        """Return a structured summary of all discovered attack chains."""
        return {
            "total_nodes": len(self.nodes),
            "total_chains": len(self.chains),
            "critical_chains": sum(1 for c in self.chains if c.max_impact == "critical"),
            "chains": [
                {
                    "id": c.chain_id,
                    "name": c.name,
                    "impact": c.max_impact,
                    "confidence": round(c.total_confidence, 2),
                    "steps": len(c.nodes),
                    "entry": c.entry_point,
                    "crown_jewel": c.crown_jewel,
                    "difficulty": c.difficulty,
                    "est_hours": c.estimated_time_hours,
                    "mitre": c.mitre_tactics,
                }
                for c in self.chains[:20]
            ],
            "mermaid": self.generate_mermaid(),
        }
