"""HEAVEN — MITRE ATT&CK technique catalog for post-exploitation.

The web-vuln side of HEAVEN already maps findings to ATT&CK via
:mod:`heaven.mitre.attack_mapper` (keyed by CWE / vuln_type). Post-exploitation
findings are different: they describe *what an operator can do once inside a
host* — abuse a SUID binary, read an AWS credential file, reuse an SSH key — so
they need their own technique subset, keyed symbolically rather than by CWE.

This module is deliberately dependency-free and reuses the canonical
:class:`~heaven.mitre.attack_mapper.Tactic` enum so the two mappers speak the
same tactic taxonomy. Every post-ex finding gets a ``mitre`` block via
:func:`tag`, which flows straight into the Navigator layer and the kill-chain
report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from heaven.mitre.attack_mapper import TACTIC_NAMES, Tactic


@dataclass(frozen=True)
class PostExTechnique:
    """One ATT&CK (sub-)technique relevant to post-exploitation."""
    id: str                 # e.g. "T1548.001"
    name: str
    tactic: Tactic
    description: str = ""

    @property
    def tactic_name(self) -> str:
        return TACTIC_NAMES.get(self.tactic, "")

    @property
    def url(self) -> str:
        # T1548.001 → https://attack.mitre.org/techniques/T1548/001/
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic_name,
            "tactic_id": self.tactic.value,
            "url": self.url,
        }


# ── Symbolic constants (referenced by enum_engine / loot / lateral) ──────────
# Privilege escalation
T_SUID = "T1548.001"            # Setuid and Setgid
T_SUDO = "T1548.003"            # Sudo and Sudo Caching
T_KERNEL_EXPLOIT = "T1068"     # Exploitation for Privilege Escalation
T_ESCAPE_TO_HOST = "T1611"     # Escape to Host (docker/lxd → host root)
T_CRON = "T1053.003"           # Scheduled Task/Job: Cron
T_FILE_PERMS = "T1222.002"     # File and Directory Permissions Modification (Linux)
T_PATH_HIJACK = "T1574.007"    # Path Interception by PATH Environment Variable
T_CAPABILITIES = "T1548"       # Abuse Elevation Control Mechanism (file capabilities)

# Privilege escalation — Windows
T_UAC_BYPASS = "T1548.002"     # Abuse Elevation Control Mechanism: Bypass UAC
T_WINDOWS_SERVICE = "T1543.003"  # Create or Modify System Process: Windows Service
T_UNQUOTED_PATH = "T1574.009"  # Path Interception by Unquoted Path
T_SERVICE_PERMS = "T1574.010"  # Services File Permissions Weakness
T_TOKEN_IMPERSONATION = "T1134.001"  # nosec B105 -- ATT&CK id (Token Impersonation/Theft)

# Credential access
T_VALID_ACCOUNTS = "T1078"     # Valid Accounts
T_CREDS_IN_FILES = "T1552.001"  # Unsecured Credentials: Credentials In Files
T_CREDS_IN_REGISTRY = "T1552.002"  # Unsecured Credentials: Credentials in Registry
T_BASH_HISTORY = "T1552.003"   # Bash History
T_PRIVATE_KEYS = "T1552.004"   # Private Keys
T_CLOUD_METADATA = "T1552.005"  # Cloud Instance Metadata API
T_PASSWORD_STORES = "T1555"    # Credentials from Password Stores  # nosec B105
T_KUBECONFIG = "T1552.007"     # Container API (kubeconfig / service-account token)

# Discovery
T_SYSTEM_INFO = "T1082"        # System Information Discovery
T_FILE_DISCOVERY = "T1083"     # File and Directory Discovery
T_ACCOUNT_DISCOVERY = "T1087.001"  # Account Discovery: Local Account
T_NET_CONFIG = "T1016"         # System Network Configuration Discovery
T_NET_CONNECTIONS = "T1049"    # System Network Connections Discovery
T_PROCESS_DISCOVERY = "T1057"  # Process Discovery
T_SOFTWARE_DISCOVERY = "T1518"  # Software Discovery

# Collection
T_LOCAL_DATA = "T1005"         # Data from Local System

# Lateral movement
T_SSH = "T1021.004"            # Remote Services: SSH
T_SMB = "T1021.002"            # Remote Services: SMB/Windows Admin Shares
T_PASS_THE_HASH = "T1550.002"  # Use Alternate Authentication Material: Pass the Hash  # nosec B105

# Persistence *opportunities* (HEAVEN identifies, never installs)
T_SSH_AUTHKEYS = "T1098.004"   # Account Manipulation: SSH Authorized Keys
T_SYSTEMD = "T1543.002"        # Create or Modify System Process: systemd Service
T_CREATE_ACCOUNT = "T1136.001"  # Create Account: Local Account


# ── The catalog ─────────────────────────────────────────────────────────────
_T = PostExTechnique
POSTEX_TECHNIQUES: dict[str, PostExTechnique] = {t.id: t for t in (
    _T(T_SUID, "Setuid and Setgid", Tactic.PRIV_ESCALATION,
       "SUID/SGID binary can be abused to run code as its owner."),
    _T(T_SUDO, "Sudo and Sudo Caching", Tactic.PRIV_ESCALATION,
       "Sudo rule allows privileged command execution."),
    _T(T_KERNEL_EXPLOIT, "Exploitation for Privilege Escalation", Tactic.PRIV_ESCALATION,
       "Kernel/service version is vulnerable to a local privesc exploit."),
    _T(T_ESCAPE_TO_HOST, "Escape to Host", Tactic.PRIV_ESCALATION,
       "docker/lxd group membership or a mounted socket yields host root."),
    _T(T_CRON, "Scheduled Task/Job: Cron", Tactic.PRIV_ESCALATION,
       "Writable script or wildcard in a privileged cron job."),
    _T(T_FILE_PERMS, "File and Directory Permissions Modification", Tactic.PRIV_ESCALATION,
       "World-writable sensitive file (e.g. /etc/passwd) enables escalation."),
    _T(T_PATH_HIJACK, "Path Interception by PATH Environment Variable", Tactic.PRIV_ESCALATION,
       "Writable directory earlier in a privileged PATH allows binary planting."),
    _T(T_CAPABILITIES, "Abuse Elevation Control Mechanism", Tactic.PRIV_ESCALATION,
       "File capability (e.g. cap_setuid+ep) grants elevated privileges."),
    _T(T_UAC_BYPASS, "Abuse Elevation Control Mechanism: Bypass UAC", Tactic.PRIV_ESCALATION,
       "AlwaysInstallElevated or a disabled UAC allows SYSTEM-level install/exec."),
    _T(T_WINDOWS_SERVICE, "Create or Modify System Process: Windows Service", Tactic.PRIV_ESCALATION,
       "A modifiable service (binary/config) runs as SYSTEM on restart."),
    _T(T_UNQUOTED_PATH, "Path Interception by Unquoted Path", Tactic.PRIV_ESCALATION,
       "Unquoted service path with a space lets an earlier binary run as the service."),
    _T(T_SERVICE_PERMS, "Services File Permissions Weakness", Tactic.PRIV_ESCALATION,
       "The service executable sits in a user-writable directory → SYSTEM code exec."),
    _T(T_TOKEN_IMPERSONATION, "Access Token Manipulation: Token Impersonation/Theft",
       Tactic.PRIV_ESCALATION,
       "SeImpersonate/SeAssignPrimaryToken enables a 'Potato' token-theft escalation."),

    _T(T_VALID_ACCOUNTS, "Valid Accounts", Tactic.CREDENTIAL_ACCESS,
       "Recovered credentials authenticate as a legitimate account."),
    _T(T_CREDS_IN_FILES, "Unsecured Credentials: Credentials In Files", Tactic.CREDENTIAL_ACCESS,
       "Plaintext secret found in a config, .env, or history file."),
    _T(T_BASH_HISTORY, "Unsecured Credentials: Bash History", Tactic.CREDENTIAL_ACCESS,
       "Secret leaked on a shell history line."),
    _T(T_PRIVATE_KEYS, "Unsecured Credentials: Private Keys", Tactic.CREDENTIAL_ACCESS,
       "Readable SSH/TLS private key material."),
    _T(T_CLOUD_METADATA, "Unsecured Credentials: Cloud Instance Metadata API", Tactic.CREDENTIAL_ACCESS,
       "Cloud metadata endpoint reachable; may yield instance-role credentials."),
    _T(T_PASSWORD_STORES, "Credentials from Password Stores", Tactic.CREDENTIAL_ACCESS,
       "Credential store / keyring readable by the current user."),
    _T(T_CREDS_IN_REGISTRY, "Unsecured Credentials: Credentials in Registry", Tactic.CREDENTIAL_ACCESS,
       "Plaintext credential stored in the Windows registry (e.g. Winlogon autologon)."),
    _T(T_KUBECONFIG, "Unsecured Credentials: Container API", Tactic.CREDENTIAL_ACCESS,
       "kubeconfig or service-account token grants cluster access."),

    _T(T_SYSTEM_INFO, "System Information Discovery", Tactic.DISCOVERY,
       "OS, kernel, and hardware facts enumerated."),
    _T(T_FILE_DISCOVERY, "File and Directory Discovery", Tactic.DISCOVERY,
       "Sensitive files and directories enumerated."),
    _T(T_ACCOUNT_DISCOVERY, "Account Discovery: Local Account", Tactic.DISCOVERY,
       "Local user accounts enumerated."),
    _T(T_NET_CONFIG, "System Network Configuration Discovery", Tactic.DISCOVERY,
       "Interfaces, routes, and DNS enumerated for pivoting."),
    _T(T_NET_CONNECTIONS, "System Network Connections Discovery", Tactic.DISCOVERY,
       "Listening/established sockets enumerated (internal services)."),
    _T(T_PROCESS_DISCOVERY, "Process Discovery", Tactic.DISCOVERY,
       "Running processes enumerated."),
    _T(T_SOFTWARE_DISCOVERY, "Software Discovery", Tactic.DISCOVERY,
       "Installed packages / versions enumerated."),

    _T(T_LOCAL_DATA, "Data from Local System", Tactic.COLLECTION,
       "Sensitive local data collected from the host."),

    _T(T_SSH, "Remote Services: SSH", Tactic.LATERAL_MOVEMENT,
       "SSH credential/key accepted on another host."),
    _T(T_SMB, "Remote Services: SMB/Windows Admin Shares", Tactic.LATERAL_MOVEMENT,
       "SMB login accepted on another host."),
    _T(T_PASS_THE_HASH, "Use Alternate Authentication Material: Pass the Hash", Tactic.LATERAL_MOVEMENT,
       "NT hash accepted without the plaintext password."),

    _T(T_SSH_AUTHKEYS, "Account Manipulation: SSH Authorized Keys", Tactic.PERSISTENCE,
       "Writable authorized_keys allows persistent SSH access (opportunity)."),
    _T(T_SYSTEMD, "Create or Modify System Process: systemd Service", Tactic.PERSISTENCE,
       "Writable systemd unit allows persistence (opportunity)."),
    _T(T_CREATE_ACCOUNT, "Create Account: Local Account", Tactic.PERSISTENCE,
       "Privileges permit creating a local account (opportunity)."),
)}


def technique(tid: str) -> Optional[PostExTechnique]:
    """Return the catalogued technique for ``tid`` (base id falls back)."""
    t = POSTEX_TECHNIQUES.get(tid)
    if t is None and "." in tid:
        t = POSTEX_TECHNIQUES.get(tid.split(".", 1)[0])
    return t


def describe(tid: str) -> dict[str, str]:
    """Return a technique dict for ``tid``; a minimal stub if uncatalogued."""
    t = technique(tid)
    if t is not None:
        return t.to_dict()
    return {
        "id": tid, "name": tid, "tactic": "", "tactic_id": "",
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }


def tag(finding: dict[str, Any], *technique_ids: str) -> dict[str, Any]:
    """Attach an ATT&CK ``mitre`` block to ``finding`` (mutates + returns it).

    Adds a ``mitre`` dict of ``{techniques: [...], tactics: [sorted names]}`` and
    surfaces the primary technique/tactic on the finding's ``evidence`` so the
    engagement DB and reports carry them without a schema change.
    """
    techs = [describe(tid) for tid in technique_ids if tid]
    if not techs:
        return finding
    tactics = sorted({t["tactic"] for t in techs if t["tactic"]})
    finding["mitre"] = {"techniques": techs, "tactics": tactics}
    ev = finding.setdefault("evidence", {})
    if isinstance(ev, dict):
        ev.setdefault("mitre_techniques", [t["id"] for t in techs])
        ev.setdefault("mitre_tactics", tactics)
    return finding


__all__ = [
    "PostExTechnique", "POSTEX_TECHNIQUES", "technique", "describe", "tag",
    # symbolic ids
    "T_SUID", "T_SUDO", "T_KERNEL_EXPLOIT", "T_ESCAPE_TO_HOST", "T_CRON",
    "T_FILE_PERMS", "T_PATH_HIJACK", "T_CAPABILITIES",
    "T_UAC_BYPASS", "T_WINDOWS_SERVICE", "T_UNQUOTED_PATH", "T_SERVICE_PERMS",
    "T_TOKEN_IMPERSONATION", "T_CREDS_IN_REGISTRY", "T_VALID_ACCOUNTS",
    "T_CREDS_IN_FILES", "T_BASH_HISTORY", "T_PRIVATE_KEYS", "T_CLOUD_METADATA",
    "T_PASSWORD_STORES", "T_KUBECONFIG", "T_SYSTEM_INFO", "T_FILE_DISCOVERY",
    "T_ACCOUNT_DISCOVERY", "T_NET_CONFIG", "T_NET_CONNECTIONS",
    "T_PROCESS_DISCOVERY", "T_SOFTWARE_DISCOVERY", "T_LOCAL_DATA", "T_SSH",
    "T_SMB", "T_PASS_THE_HASH", "T_SSH_AUTHKEYS", "T_SYSTEMD", "T_CREATE_ACCOUNT",
]
