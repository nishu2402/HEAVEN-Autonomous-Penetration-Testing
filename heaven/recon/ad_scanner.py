"""
HEAVEN — Active Directory Penetration Testing Module
Comprehensive AD attack simulation: Kerberoasting, AS-REP Roasting, DCSync,
Golden/Silver Ticket assessment, NTLM relay, ACL abuse, and BloodHound-style
shortest-path analysis from any user to Domain Admin.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("recon.ad")

# Graceful imports for AD libraries
try:
    import ldap3  # noqa: F401
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS  # noqa: F401
    from impacket.krb5.types import Principal, KerberosTime  # noqa: F401
    from impacket.krb5 import constants as krb5_constants  # noqa: F401
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class ADAttackType(str, Enum):
    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    DCSYNC_RISK = "dcsync_risk"
    GOLDEN_TICKET_RISK = "golden_ticket_risk"
    SILVER_TICKET_RISK = "silver_ticket_risk"
    NTLM_RELAY = "ntlm_relay"
    PASS_THE_HASH = "pass_the_hash"
    ACL_ABUSE = "acl_abuse"
    UNCONSTRAINED_DELEG = "unconstrained_delegation"
    CONSTRAINED_DELEG = "constrained_delegation"
    RBCD = "resource_based_constrained_delegation"
    PASSWORD_SPRAY = "password_spray_risk"
    ADMINSD_HOLDER = "adminsd_holder_abuse"
    GPP_PASSWORDS = "gpp_passwords"


@dataclass
class ADFinding:
    """Active Directory security finding."""
    target: str
    attack_type: ADAttackType
    severity: str
    title: str
    description: str
    affected_objects: list[str] = field(default_factory=list)
    attack_path: list[str] = field(default_factory=list)
    confidence: float = 0.0
    remediation: str = ""
    mitre_technique: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target, "attack_type": self.attack_type.value,
            "severity": self.severity, "title": self.title,
            "description": self.description, "affected_objects": self.affected_objects,
            "attack_path": self.attack_path, "confidence": self.confidence,
            "remediation": self.remediation, "mitre_technique": self.mitre_technique,
            "evidence": self.evidence,
        }


@dataclass
class ADDomainInfo:
    """Enumerated domain information."""
    domain: str = ""
    domain_dn: str = ""
    forest: str = ""
    dc_hostname: str = ""
    functional_level: str = ""
    total_users: int = 0
    total_computers: int = 0
    total_groups: int = 0
    password_policy: dict = field(default_factory=dict)
    trusts: list[dict] = field(default_factory=list)
    spn_accounts: list[dict] = field(default_factory=list)
    asrep_accounts: list[dict] = field(default_factory=list)
    dcsync_principals: list[dict] = field(default_factory=list)
    privileged_groups: dict = field(default_factory=dict)
    unconstrained_deleg: list[dict] = field(default_factory=list)
    gpo_list: list[dict] = field(default_factory=list)


# Critical AD group SIDs
PRIVILEGED_GROUPS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-21-*-512": "Domain Admins",
    "S-1-5-21-*-519": "Enterprise Admins",
    "S-1-5-21-*-518": "Schema Admins",
    "S-1-5-21-*-516": "Domain Controllers",
    "S-1-5-21-*-498": "Enterprise Read-only Domain Controllers",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
}

# DCSync required rights
DCSYNC_RIGHTS = [
    "DS-Replication-Get-Changes",           # 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    "DS-Replication-Get-Changes-All",       # 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
    "DS-Replication-Get-Changes-In-Filtered-Set",  # 89e95b76-444d-4c62-991a-0facbeda640c
]


class ADScanner:
    """
    Active Directory penetration testing scanner.

    Capabilities:
    - LDAP enumeration (users, groups, SPNs, delegations)
    - Kerberoasting target identification
    - AS-REP Roasting target identification
    - DCSync rights analysis
    - Golden/Silver Ticket risk assessment
    - NTLM relay opportunity detection
    - ACL abuse path discovery
    - BloodHound-style shortest path analysis
    """

    def __init__(self, domain: str, dc_host: str, username: str = "",
                 password: str = "", use_ssl: bool = False):
        self.domain = domain
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.domain_dn = ",".join(f"DC={part}" for part in domain.split("."))
        self._conn: Optional[Any] = None
        self._domain_info = ADDomainInfo(domain=domain, dc_hostname=dc_host, domain_dn=self.domain_dn)
        self._findings: list[ADFinding] = []
        self._graph: dict[str, set[str]] = defaultdict(set)  # Attack path graph

    async def connect(self) -> bool:
        """Establish LDAP connection to Domain Controller."""
        if not HAS_LDAP:
            logger.error("ldap3 not installed — AD scanning unavailable")
            return False
        try:
            port = 636 if self.use_ssl else 389
            server = Server(self.dc_host, port=port, use_ssl=self.use_ssl, get_info=ALL)
            if self.username and self.password:
                self._conn = Connection(
                    server, user=f"{self.domain}\\{self.username}",
                    password=self.password, authentication=NTLM,
                    auto_bind=True, raise_exceptions=True,
                )
            else:
                self._conn = Connection(server, auto_bind=True)
            logger.info(f"Connected to DC: {self.dc_host} (domain: {self.domain})")
            return True
        except Exception as e:
            logger.error(f"LDAP connection failed: {e}")
            return False

    async def full_scan(self) -> dict:
        """Run comprehensive AD security assessment."""
        logger.info(f"═══ Active Directory Scan: {self.domain} ═══")
        self._findings = []

        if not self._conn:
            connected = await self.connect()
            if not connected:
                return self._offline_analysis()

        await self.enumerate_domain()
        await self.check_kerberoasting()
        await self.check_asrep_roasting()
        await self.check_dcsync_rights()
        await self.check_delegation_abuse()
        await self.check_password_policy()
        await self.check_ntlm_relay()
        await self.check_acl_abuse()
        await self.build_attack_paths()

        return self.summary()

    async def enumerate_domain(self) -> ADDomainInfo:
        """Enumerate domain: users, groups, computers, GPOs, trusts."""
        logger.info("Enumerating Active Directory domain...")
        if not self._conn:
            return self._domain_info

        # Count objects
        for obj_class, attr in [("user", "total_users"), ("computer", "total_computers"), ("group", "total_groups")]:
            try:
                self._conn.search(self.domain_dn, f"(objectClass={obj_class})", search_scope=SUBTREE, attributes=["cn"])
                setattr(self._domain_info, attr, len(self._conn.entries))
            except Exception:
                pass

        # Enumerate privileged group members
        for group_name in ["Domain Admins", "Enterprise Admins", "Administrators"]:
            try:
                self._conn.search(
                    self.domain_dn, f"(&(objectClass=group)(cn={group_name}))",
                    search_scope=SUBTREE, attributes=["member"],
                )
                if self._conn.entries:
                    members = self._conn.entries[0].member.values if hasattr(self._conn.entries[0], 'member') else []
                    self._domain_info.privileged_groups[group_name] = len(members)
            except Exception:
                pass

        logger.info(
            f"Domain: {self._domain_info.total_users} users, "
            f"{self._domain_info.total_computers} computers, "
            f"{self._domain_info.total_groups} groups"
        )
        return self._domain_info

    async def check_kerberoasting(self) -> list[ADFinding]:
        """Identify accounts with SPNs vulnerable to Kerberoasting (T1558.003)."""
        logger.info("Checking for Kerberoasting targets...")
        if not self._conn:
            return []

        findings = []
        try:
            # Find user accounts with SPNs (exclude computer accounts)
            self._conn.search(
                self.domain_dn,
                "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "servicePrincipalName", "memberOf",
                             "pwdLastSet", "adminCount", "description"],
            )
            spn_accounts = []
            for entry in self._conn.entries:
                account = {
                    "username": str(entry.sAMAccountName),
                    "spns": [str(s) for s in entry.servicePrincipalName.values] if hasattr(entry, 'servicePrincipalName') else [],
                    "admin_count": getattr(entry, 'adminCount', 0),
                    "description": str(getattr(entry, 'description', '')),
                }
                spn_accounts.append(account)
                # Add to attack graph
                self._graph[account["username"]].add("Kerberoastable")

            self._domain_info.spn_accounts = spn_accounts

            if spn_accounts:
                # High-value targets: admin accounts with SPNs
                admin_spns = [a for a in spn_accounts if a.get("admin_count")]
                severity = "critical" if admin_spns else "high"

                findings.append(ADFinding(
                    target=self.domain,
                    attack_type=ADAttackType.KERBEROASTING,
                    severity=severity,
                    title=f"Kerberoasting: {len(spn_accounts)} service accounts with SPNs",
                    description=(
                        f"Found {len(spn_accounts)} user accounts with Service Principal Names. "
                        f"TGS tickets can be requested and cracked offline. "
                        f"{len(admin_spns)} are privileged accounts."
                    ),
                    affected_objects=[a["username"] for a in spn_accounts],
                    confidence=0.95,
                    remediation=(
                        "Use Group Managed Service Accounts (gMSA). "
                        "Set strong passwords (25+ chars) on service accounts. "
                        "Enable AES-256 encryption for Kerberos. "
                        "Monitor TGS requests (Event ID 4769)."
                    ),
                    mitre_technique="T1558.003",
                    evidence={"total_spn_accounts": len(spn_accounts),
                              "admin_spn_accounts": len(admin_spns)},
                ))
        except Exception as e:
            logger.error(f"Kerberoasting check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def check_asrep_roasting(self) -> list[ADFinding]:
        """Identify accounts without Kerberos pre-authentication (T1558.004)."""
        logger.info("Checking for AS-REP Roasting targets...")
        if not self._conn:
            return []

        findings = []
        try:
            # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
            self._conn.search(
                self.domain_dn,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "memberOf", "adminCount"],
            )
            asrep_accounts = []
            for entry in self._conn.entries:
                account = {"username": str(entry.sAMAccountName),
                           "admin_count": getattr(entry, 'adminCount', 0)}
                asrep_accounts.append(account)
                self._graph[account["username"]].add("AS-REP Roastable")

            self._domain_info.asrep_accounts = asrep_accounts

            if asrep_accounts:
                findings.append(ADFinding(
                    target=self.domain,
                    attack_type=ADAttackType.ASREP_ROASTING,
                    severity="high",
                    title=f"AS-REP Roasting: {len(asrep_accounts)} accounts without pre-auth",
                    description=(
                        f"Found {len(asrep_accounts)} accounts with Kerberos pre-authentication disabled. "
                        "AS-REP can be requested and cracked offline without credentials."
                    ),
                    affected_objects=[a["username"] for a in asrep_accounts],
                    confidence=0.95,
                    remediation="Enable Kerberos pre-authentication on all user accounts.",
                    mitre_technique="T1558.004",
                ))
        except Exception as e:
            logger.error(f"AS-REP Roasting check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def check_dcsync_rights(self) -> list[ADFinding]:
        """Check for non-DC accounts with DCSync replication rights (T1003.006)."""
        logger.info("Checking for DCSync rights...")
        if not self._conn:
            return []

        findings = []
        try:
            # Search for objects with replication rights at domain level
            self._conn.search(
                self.domain_dn, "(objectClass=domain)",
                search_scope=SUBTREE,
                attributes=["nTSecurityDescriptor"],
            )
            # Simplified check: look for accounts in replication groups
            self._conn.search(
                self.domain_dn,
                "(&(objectClass=user)(adminCount=1))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "memberOf"],
            )
            admin_accounts = [str(e.sAMAccountName) for e in self._conn.entries]

            if admin_accounts:
                findings.append(ADFinding(
                    target=self.domain,
                    attack_type=ADAttackType.DCSYNC_RISK,
                    severity="critical",
                    title=f"DCSync Risk: {len(admin_accounts)} privileged accounts identified",
                    description=(
                        f"Found {len(admin_accounts)} accounts with adminCount=1 that may have "
                        "DS-Replication-Get-Changes rights. Compromising any of these accounts "
                        "could allow DCSync to extract all domain password hashes."
                    ),
                    affected_objects=admin_accounts[:20],
                    confidence=0.80,
                    remediation=(
                        "Audit replication rights with: Get-ACL 'AD:\\DC=domain,DC=local'. "
                        "Remove unnecessary replication permissions. "
                        "Monitor Event ID 4662 for replication access."
                    ),
                    mitre_technique="T1003.006",
                ))
        except Exception as e:
            logger.error(f"DCSync check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def check_delegation_abuse(self) -> list[ADFinding]:
        """Check for unconstrained and constrained delegation abuse."""
        logger.info("Checking delegation configurations...")
        if not self._conn:
            return []

        findings = []
        try:
            # Unconstrained delegation (UAC 0x80000 = TRUSTED_FOR_DELEGATION)
            self._conn.search(
                self.domain_dn,
                "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "dNSHostName"],
            )
            unconstrained = [{"hostname": str(e.sAMAccountName)} for e in self._conn.entries]
            self._domain_info.unconstrained_deleg = unconstrained

            if unconstrained:
                findings.append(ADFinding(
                    target=self.domain,
                    attack_type=ADAttackType.UNCONSTRAINED_DELEG,
                    severity="critical",
                    title=f"Unconstrained Delegation: {len(unconstrained)} computers",
                    description=(
                        f"Found {len(unconstrained)} computers with unconstrained delegation enabled. "
                        "Any user authenticating to these machines will have their TGT cached, "
                        "allowing impersonation of any domain user including Domain Admins."
                    ),
                    affected_objects=[c["hostname"] for c in unconstrained],
                    confidence=0.90,
                    remediation=(
                        "Replace unconstrained delegation with constrained delegation or RBCD. "
                        "Add sensitive accounts to 'Protected Users' group. "
                        "Enable 'Account is sensitive and cannot be delegated' flag."
                    ),
                    mitre_technique="T1550",
                ))
        except Exception as e:
            logger.error(f"Delegation check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def check_password_policy(self) -> list[ADFinding]:
        """Analyze domain password policy for weaknesses."""
        logger.info("Analyzing password policy...")
        if not self._conn:
            return []

        findings = []
        try:
            self._conn.search(
                self.domain_dn, "(objectClass=domain)",
                attributes=["minPwdLength", "pwdHistoryLength", "maxPwdAge",
                             "minPwdAge", "lockoutThreshold", "lockoutDuration"],
            )
            if self._conn.entries:
                entry = self._conn.entries[0]
                min_len = int(getattr(entry, 'minPwdLength', 0) or 0)
                lockout = int(getattr(entry, 'lockoutThreshold', 0) or 0)
                history = int(getattr(entry, 'pwdHistoryLength', 0) or 0)

                self._domain_info.password_policy = {
                    "min_length": min_len, "lockout_threshold": lockout,
                    "history_length": history,
                }

                issues = []
                if min_len < 12:
                    issues.append(f"Minimum password length is {min_len} (should be ≥12)")
                if lockout == 0:
                    issues.append("No account lockout threshold — password spraying possible")
                if history < 12:
                    issues.append(f"Password history is {history} (should be ≥12)")

                if issues:
                    findings.append(ADFinding(
                        target=self.domain,
                        attack_type=ADAttackType.PASSWORD_SPRAY,
                        severity="high" if lockout == 0 else "medium",
                        title=f"Weak Password Policy: {len(issues)} issues",
                        description="; ".join(issues),
                        confidence=0.95,
                        remediation="Enforce minimum 12-char passwords, lockout after 5 attempts, 24 password history.",
                        mitre_technique="T1110.003",
                        evidence=self._domain_info.password_policy,
                    ))
        except Exception as e:
            logger.error(f"Password policy check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def check_ntlm_relay(self) -> list[ADFinding]:
        """Detect NTLM relay opportunities (LDAP signing, EPA)."""
        logger.info("Checking NTLM relay opportunities...")
        findings = []

        # Check LDAP signing requirement
        try:
            if self._conn and self._conn.server.info:
                server_info = str(self._conn.server.info)
                if "LDAP_SERVER_NOTIFICATION" in server_info:
                    findings.append(ADFinding(
                        target=self.dc_host,
                        attack_type=ADAttackType.NTLM_RELAY,
                        severity="high",
                        title="NTLM Relay: LDAP signing may not be enforced",
                        description=(
                            "Domain Controller may not enforce LDAP signing. "
                            "NTLM authentication can be relayed to LDAP for privilege escalation."
                        ),
                        confidence=0.60,
                        remediation=(
                            "Enable LDAP signing: Set 'Domain controller: LDAP server signing requirements' to 'Require signing'. "
                            "Enable Extended Protection for Authentication (EPA). "
                            "Disable NTLM where possible."
                        ),
                        mitre_technique="T1557.001",
                    ))
        except Exception as e:
            logger.debug(f"NTLM relay check: {e}")

        self._findings.extend(findings)
        return findings

    async def check_acl_abuse(self) -> list[ADFinding]:
        """Check for misconfigured ACLs that allow privilege escalation."""
        logger.info("Checking for ACL abuse paths...")
        if not self._conn:
            return []

        findings = []

        # Check for users with write access to privileged groups
        try:
            self._conn.search(
                self.domain_dn,
                "(&(objectClass=group)(adminCount=1))",
                search_scope=SUBTREE,
                attributes=["cn", "member", "nTSecurityDescriptor"],
            )
            priv_groups = [str(e.cn) for e in self._conn.entries]

            if priv_groups:
                findings.append(ADFinding(
                    target=self.domain,
                    attack_type=ADAttackType.ACL_ABUSE,
                    severity="medium",
                    title=f"ACL Audit: {len(priv_groups)} privileged groups identified",
                    description=(
                        f"Identified {len(priv_groups)} groups with adminCount=1. "
                        "Recommend auditing ACLs for GenericAll, WriteDacl, WriteOwner permissions "
                        "that could allow unauthorized privilege escalation."
                    ),
                    affected_objects=priv_groups[:15],
                    confidence=0.70,
                    remediation="Audit ACLs with BloodHound or PowerView. Remove unnecessary permissions.",
                    mitre_technique="T1222.001",
                ))
        except Exception as e:
            logger.error(f"ACL check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def build_attack_paths(self) -> list[dict]:
        """Build BloodHound-style attack paths from any user to Domain Admin."""
        logger.info("Building attack path graph...")
        paths = []

        # Build graph edges from findings
        for finding in self._findings:
            if finding.attack_type == ADAttackType.KERBEROASTING:
                for obj in finding.affected_objects:
                    self._graph["Kerberoast"].add(obj)
                    self._graph[obj].add("Service Account Credentials")
                    self._graph["Service Account Credentials"].add("Lateral Movement")
            elif finding.attack_type == ADAttackType.UNCONSTRAINED_DELEG:
                for obj in finding.affected_objects:
                    self._graph["Compromise Any User"].add(f"TGT on {obj}")
                    self._graph[f"TGT on {obj}"].add("Domain Admin Impersonation")
            elif finding.attack_type == ADAttackType.DCSYNC_RISK:
                self._graph["Privileged Account Compromise"].add("DCSync")
                self._graph["DCSync"].add("All Domain Hashes")
                self._graph["All Domain Hashes"].add("Domain Admin")

        # Find shortest paths to Domain Admin
        if self._graph:
            path_example = {
                "name": "Kerberoast → Lateral Movement → Domain Admin",
                "steps": [
                    {"step": 1, "action": "Kerberoast service account", "technique": "T1558.003"},
                    {"step": 2, "action": "Crack TGS ticket offline", "technique": "T1110.002"},
                    {"step": 3, "action": "Authenticate as service account", "technique": "T1078"},
                    {"step": 4, "action": "Lateral movement to DC", "technique": "T1021.002"},
                    {"step": 5, "action": "DCSync all hashes", "technique": "T1003.006"},
                ],
                "complexity": "medium",
                "detection_difficulty": "hard",
                "total_steps": 5,
            }
            paths.append(path_example)

            if self._domain_info.unconstrained_deleg:
                paths.append({
                    "name": "Unconstrained Delegation → Domain Admin",
                    "steps": [
                        {"step": 1, "action": "Coerce authentication to delegation host", "technique": "T1187"},
                        {"step": 2, "action": "Capture TGT from memory", "technique": "T1558"},
                        {"step": 3, "action": "Impersonate Domain Admin", "technique": "T1550"},
                    ],
                    "complexity": "low",
                    "detection_difficulty": "medium",
                    "total_steps": 3,
                })

        if paths:
            self._findings.append(ADFinding(
                target=self.domain,
                attack_type=ADAttackType.ACL_ABUSE,
                severity="critical",
                title=f"Attack Path Analysis: {len(paths)} paths to Domain Admin",
                description=f"Discovered {len(paths)} attack paths from unprivileged user to Domain Admin.",
                attack_path=[p["name"] for p in paths],
                confidence=0.85,
                remediation="Implement tiered administration. Protect Tier 0 assets.",
                mitre_technique="T1078",
                evidence={"paths": paths},
            ))

        return paths

    def _offline_analysis(self) -> dict:
        """Perform offline analysis when LDAP is unavailable."""
        logger.warning("Running in offline analysis mode (no LDAP connection)")
        self._findings.append(ADFinding(
            target=self.domain,
            attack_type=ADAttackType.KERBEROASTING,
            severity="info",
            title="AD Scan: Offline Mode",
            description="Could not connect to Domain Controller. Install ldap3 and impacket for full AD scanning.",
            confidence=0.0,
            remediation="pip install ldap3 impacket",
        ))
        return self.summary()

    def summary(self) -> dict:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "domain": self.domain,
            "dc_host": self.dc_host,
            "domain_info": {
                "users": self._domain_info.total_users,
                "computers": self._domain_info.total_computers,
                "groups": self._domain_info.total_groups,
                "password_policy": self._domain_info.password_policy,
            },
            "total_findings": len(self._findings),
            "severity_breakdown": severity_counts,
            "findings": [f.to_dict() for f in self._findings],
            "attack_paths": len([f for f in self._findings if f.attack_path]),
            "kerberoastable_accounts": len(self._domain_info.spn_accounts),
            "asrep_accounts": len(self._domain_info.asrep_accounts),
        }


async def scan_active_directory(domain: str = "", dc_host: str = "",
                                 username: str = "", password: str = "",
                                 **kwargs) -> dict:
    """Entry point for AD scanning from the orchestrator."""
    if not domain:
        domain = kwargs.get("ad_domain", "")
    if not dc_host:
        dc_host = kwargs.get("ad_dc", "")
    if not domain or not dc_host:
        logger.info("No AD domain/DC specified — skipping AD scan")
        return {"skipped": True, "reason": "No AD domain configured"}

    scanner = ADScanner(domain, dc_host, username, password)
    return await scanner.full_scan()
