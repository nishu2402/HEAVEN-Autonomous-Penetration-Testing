"""Active Directory depth + false-positive guards for the security-descriptor
detectors: DCSync (replication rights on the domain head), ACL takeover edges
onto privileged groups, constrained / resource-based delegation, and the
attack-path builder.

Two things are proven for each detector: the TRUE positive fires on a real
misconfiguration, and the benign/default case stays silent. The false positive
these guard against is the historical one the user hit elsewhere: a scanner that
reports a critical "path to Domain Admin" (or a DCSync right) that nobody could
actually reach, because it was inferred from a default attribute rather than a
confirmed grant.
"""
from __future__ import annotations

import asyncio

import pytest

from heaven.recon import ad_acl
from heaven.recon.ad_acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_WRITE_PROP,
    ADS_RIGHT_GENERIC_ALL,
    ADS_RIGHT_WRITE_DAC,
    ATTR_MEMBER_GUID,
    REPL_GET_CHANGES,
    Ace,
    ace_dangerous_group_rights,
    ace_grants_replication,
    sid_is_default_privileged,
)
from heaven.recon.ad_scanner import ADAttackType, ADScanner

aiohttp = pytest.importorskip("aiohttp")  # ad_scanner imports it lazily elsewhere


# ── pure decision logic (no bytes, no DC) ─────────────────────────────────────

def test_default_privileged_sids_are_excluded():
    # The principals that hold replication / control rights by default must be
    # treated as expected, or every domain is a false positive.
    assert sid_is_default_privileged("S-1-5-9")              # Enterprise DCs
    assert sid_is_default_privileged("S-1-5-18")             # SYSTEM
    assert sid_is_default_privileged("S-1-5-32-544")         # BUILTIN\Administrators
    assert sid_is_default_privileged("S-1-5-21-1-2-3-512")   # Domain Admins
    assert sid_is_default_privileged("S-1-5-21-1-2-3-519")   # Enterprise Admins
    # Built-in operator groups appear in every privileged group's DEFAULT DACL, so
    # they MUST be excluded or every domain floods with phantom edges (found live).
    assert sid_is_default_privileged("S-1-5-32-548")         # Account Operators
    assert sid_is_default_privileged("S-1-5-32-549")         # Server Operators
    assert sid_is_default_privileged("S-1-5-32-550")         # Print Operators
    assert sid_is_default_privileged("S-1-5-32-551")         # Backup Operators
    # A normal user RID is NOT default-privileged.
    assert not sid_is_default_privileged("S-1-5-21-1-2-3-1104")
    assert not sid_is_default_privileged("S-1-5-11")         # Authenticated Users
    assert not sid_is_default_privileged("S-1-5-32-545")     # BUILTIN\Users (low priv)


def test_ace_grants_replication_discriminates():
    low = "S-1-5-21-1-2-3-1104"
    # Control-access ACE carrying the Get-Changes GUID → replication.
    assert ace_grants_replication(
        Ace(low, ADS_RIGHT_DS_CONTROL_ACCESS, REPL_GET_CHANGES))
    # GenericAll → replication (superset).
    assert ace_grants_replication(Ace(low, ADS_RIGHT_GENERIC_ALL, None))
    # Plain control-access with no ObjectType = all extended rights → replication.
    assert ace_grants_replication(Ace(low, ADS_RIGHT_DS_CONTROL_ACCESS, None))
    # Control-access for a DIFFERENT extended right (not replication) → no.
    assert not ace_grants_replication(
        Ace(low, ADS_RIGHT_DS_CONTROL_ACCESS,
            "00299570-246d-11d0-a768-00aa006e0529"))  # Reset-Password
    # A mere property write is not replication.
    assert not ace_grants_replication(Ace(low, ADS_RIGHT_DS_WRITE_PROP, None))


def test_ace_dangerous_group_rights_discriminates():
    low = "S-1-5-21-1-2-3-1104"
    assert ace_dangerous_group_rights(
        Ace(low, ADS_RIGHT_GENERIC_ALL, None)) == ["GenericAll"]
    assert "WriteDacl" in ace_dangerous_group_rights(
        Ace(low, ADS_RIGHT_WRITE_DAC, None))
    # Write to the member attribute (add-self-to-group) is dangerous.
    assert ace_dangerous_group_rights(
        Ace(low, ADS_RIGHT_DS_WRITE_PROP, ATTR_MEMBER_GUID)) == ["WriteProperty(member)"]
    # Write to some OTHER property is not a takeover of the group.
    assert ace_dangerous_group_rights(
        Ace(low, ADS_RIGHT_DS_WRITE_PROP,
            "bf967950-0de6-11d0-a285-00aa003049e2")) == []  # description attr


# ── parse_dacl round-trip against real impacket-built SD bytes ────────────────

def _guid_to_le_bytes(guid: str) -> bytes:
    import struct
    f = guid.split("-")
    d1 = struct.pack("<I", int(f[0], 16))
    d2 = struct.pack("<H", int(f[1], 16))
    d3 = struct.pack("<H", int(f[2], 16))
    rest = bytes.fromhex(f[3] + f[4])
    return d1 + d2 + d3 + rest


def _build_sd(sid_str: str, mask: int, object_guid: str | None) -> bytes:
    """Build a self-relative SD with one ACCESS_ALLOWED(-OBJECT) ACE, so the test
    exercises the real impacket byte layout parse_dacl must read off the wire."""
    ldaptypes = pytest.importorskip("impacket.ldap.ldaptypes")
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    owner = ldaptypes.LDAP_SID()
    owner.fromCanonical("S-1-5-32-544")
    sd["OwnerSid"] = owner
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    dacl = ldaptypes.ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = []
    ace = ldaptypes.ACE()
    sid = ldaptypes.LDAP_SID()
    sid.fromCanonical(sid_str)
    if object_guid:
        ace["AceType"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        body = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        body["Mask"] = ldaptypes.ACCESS_MASK()
        body["Mask"]["Mask"] = mask
        body["Flags"] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        body["ObjectType"] = _guid_to_le_bytes(object_guid)
        body["InheritedObjectType"] = b""
        body["Sid"] = sid
    else:
        ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        body = ldaptypes.ACCESS_ALLOWED_ACE()
        body["Mask"] = ldaptypes.ACCESS_MASK()
        body["Mask"]["Mask"] = mask
        body["Sid"] = sid
    ace["AceFlags"] = 0
    ace["Ace"] = body
    dacl.aces.append(ace)
    sd["Dacl"] = dacl
    return sd.getData()


def test_parse_dacl_round_trips_replication_object_ace():
    raw = _build_sd("S-1-5-21-1-2-3-1104", ADS_RIGHT_DS_CONTROL_ACCESS,
                    REPL_GET_CHANGES)
    aces = ad_acl.parse_dacl(raw)
    assert aces is not None and len(aces) == 1
    got = aces[0]
    assert got.sid == "S-1-5-21-1-2-3-1104"
    assert got.mask & ADS_RIGHT_DS_CONTROL_ACCESS
    assert (got.object_guid or "").lower() == REPL_GET_CHANGES
    assert ace_grants_replication(got)


def test_parse_dacl_none_when_unparseable():
    assert ad_acl.parse_dacl(None) is None
    assert ad_acl.parse_dacl(b"") is None
    assert ad_acl.parse_dacl(b"not-a-descriptor") is None


# ── a filter-routing fake Connection (returns distinct entries per search) ────

class _Attr:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

    @property
    def values(self):
        return self.value if isinstance(self.value, list) else [self.value]


class _Entry:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, _Attr(v))


class _RoutingConn:
    """Return entries whose configured substring matches the search filter, so a
    single check's several searches can each get their own result set."""

    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or []
        self.entries: list = []
        self.filters: list[str] = []

    def search(self, base, search_filter, **kw):
        self.filters.append(search_filter)
        for sub, entries in self.routes:
            if sub in search_filter:
                self.entries = entries
                return
        self.entries = self.default


def _mk_scanner(conn) -> ADScanner:
    s = ADScanner(domain="lab.local", dc_host="dc01")
    s.domain_dn = "DC=lab,DC=local"
    s._conn = conn
    return s


# ── DCSync: confirmed from a non-default replication grant ────────────────────

def test_dcsync_confirms_nondefault_replication_grant(monkeypatch):
    low = "S-1-5-21-1-2-3-1104"
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace(low, ADS_RIGHT_DS_CONTROL_ACCESS, REPL_GET_CHANGES)])
    conn = _RoutingConn(
        routes=[("objectClass=domain", [_Entry(nTSecurityDescriptor=b"\x01sd")]),
                ("objectSid", [_Entry(sAMAccountName="eviluser")])])
    s = _mk_scanner(conn)
    asyncio.run(s.check_dcsync_rights())
    dc = [f for f in s._findings if f.attack_type == ADAttackType.DCSYNC_RISK]
    assert dc and dc[0].severity == "critical"
    assert dc[0].evidence.get("confirmed") is True
    # The confirmed grant is reported, resolved to a readable name.
    assert any("eviluser" in o or low in o for o in dc[0].affected_objects)


def test_dcsync_default_principal_is_not_a_finding(monkeypatch):
    # Replication granted ONLY to Domain Admins (RID 512) is the default state and
    # must not be reported as an exposure; it degrades to the adminCount pointer.
    da = "S-1-5-21-1-2-3-512"
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace(da, ADS_RIGHT_GENERIC_ALL, None)])
    conn = _RoutingConn(
        routes=[("objectClass=domain", [_Entry(nTSecurityDescriptor=b"\x01sd")]),
                ("adminCount=1", [_Entry(sAMAccountName="Administrator")])])
    s = _mk_scanner(conn)
    asyncio.run(s.check_dcsync_rights())
    dc = [f for f in s._findings if f.attack_type == ADAttackType.DCSYNC_RISK]
    assert dc, "the adminCount pointer should still surface for the ACL review"
    assert dc[0].severity != "critical"
    assert not dc[0].evidence.get("confirmed")


# ── ACL abuse: takeover edge onto a privileged group ──────────────────────────

def test_acl_abuse_confirms_tier0_takeover_edge(monkeypatch):
    low = "S-1-5-21-1-2-3-1104"
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace(low, ADS_RIGHT_GENERIC_ALL, None)])
    conn = _RoutingConn(
        routes=[("objectClass=group", [_Entry(cn="Domain Admins",
                                               nTSecurityDescriptor=b"\x01sd")]),
                ("objectSid", [_Entry(sAMAccountName="lowpriv")])])
    s = _mk_scanner(conn)
    asyncio.run(s.check_acl_abuse())
    acl = [f for f in s._findings if f.attack_type == ADAttackType.ACL_ABUSE]
    assert acl and acl[0].severity == "critical"   # Tier-0 group
    assert acl[0].evidence.get("confirmed") is True
    assert any("Domain Admins" in o for o in acl[0].affected_objects)


def test_acl_abuse_benign_group_is_only_a_pointer(monkeypatch):
    # Group SD grants control only to Domain Admins (default) → no takeover edge,
    # so the finding stays the medium adminCount pointer, never a critical.
    da = "S-1-5-21-1-2-3-512"
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace(da, ADS_RIGHT_GENERIC_ALL, None)])
    conn = _RoutingConn(
        routes=[("objectClass=group", [_Entry(cn="Domain Admins",
                                               nTSecurityDescriptor=b"\x01sd")])])
    s = _mk_scanner(conn)
    asyncio.run(s.check_acl_abuse())
    acl = [f for f in s._findings if f.attack_type == ADAttackType.ACL_ABUSE]
    assert acl and acl[0].severity == "medium"
    assert not acl[0].evidence.get("confirmed")


# ── Delegation: constrained (protocol transition) and RBCD ────────────────────

def test_constrained_delegation_protocol_transition_is_high():
    conn = _RoutingConn(routes=[
        ("msDS-AllowedToDelegateTo=*",
         [_Entry(sAMAccountName="web01$",
                 **{"msDS-AllowedToDelegateTo": ["HOST/dc01", "CIFS/dc01"],
                    "userAccountControl": 0x1001000})])],  # 0x1000000 = T2A4D
        default=[])
    s = _mk_scanner(conn)
    asyncio.run(s.check_delegation_abuse())
    cd = [f for f in s._findings if f.attack_type == ADAttackType.CONSTRAINED_DELEG]
    assert cd and cd[0].severity == "high"
    assert cd[0].evidence.get("protocol_transition") is True
    assert "HOST/dc01" in cd[0].affected_objects


def test_rbcd_grant_to_nondefault_principal(monkeypatch):
    low = "S-1-5-21-1-2-3-1104"
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace(low, ADS_RIGHT_GENERIC_ALL, None)])
    conn = _RoutingConn(routes=[
        ("msDS-AllowedToActOnBehalfOfOtherIdentity=*",
         [_Entry(sAMAccountName="srv02$",
                 **{"msDS-AllowedToActOnBehalfOfOtherIdentity": b"\x01sd"})]),
        ("objectSid", [_Entry(sAMAccountName="attacker$")])],
        default=[])
    s = _mk_scanner(conn)
    asyncio.run(s.check_delegation_abuse())
    rbcd = [f for f in s._findings if f.attack_type == ADAttackType.RBCD]
    assert rbcd and rbcd[0].severity == "high"
    assert "srv02$" in rbcd[0].title


def test_rbcd_default_principal_is_silent(monkeypatch):
    # RBCD that names only a default-privileged principal is not an exposure.
    monkeypatch.setattr(ad_acl, "parse_dacl",
                        lambda _b: [Ace("S-1-5-18", ADS_RIGHT_GENERIC_ALL, None)])
    conn = _RoutingConn(routes=[
        ("msDS-AllowedToActOnBehalfOfOtherIdentity=*",
         [_Entry(sAMAccountName="srv02$",
                 **{"msDS-AllowedToActOnBehalfOfOtherIdentity": b"\x01sd"})])],
        default=[])
    s = _mk_scanner(conn)
    asyncio.run(s.check_delegation_abuse())
    assert not [f for f in s._findings if f.attack_type == ADAttackType.RBCD]


# ── attack-path builder: the fabricated-critical FP fix ───────────────────────

def test_attack_path_not_fabricated_from_nonprivileged_kerberoast():
    # A single non-privileged service account with an SPN must NOT produce a
    # critical "path to Domain Admin" (the historical fabricated-path FP).
    s = ADScanner(domain="lab.local", dc_host="dc01")
    s._domain_info.spn_accounts = [{"username": "svc_web", "privileged": False}]
    asyncio.run(s.build_attack_paths())
    paths = [f for f in s._findings
             if "path" in f.title.lower() and "Domain Admin" in f.title]
    assert paths == [], f"must not fabricate a DA path; got {[p.title for p in paths]}"


def test_attack_path_from_privileged_kerberoast_is_real():
    s = ADScanner(domain="lab.local", dc_host="dc01")
    s._domain_info.spn_accounts = [{"username": "svc_adm", "privileged": True}]
    res = asyncio.run(s.build_attack_paths())
    assert any("privileged service account" in p["name"] for p in res)
    paths = [f for f in s._findings if f.attack_type == ADAttackType.ACL_ABUSE
             and "confirmed path" in f.title]
    assert paths and paths[0].severity == "critical"


def test_attack_path_from_unconstrained_delegation_is_real():
    s = ADScanner(domain="lab.local", dc_host="dc01")
    s._domain_info.unconstrained_deleg = [{"hostname": "WEBSRV$"}]
    res = asyncio.run(s.build_attack_paths())
    assert any("Unconstrained Delegation" in p["name"] for p in res)


def test_attack_path_silent_when_no_evidence():
    s = ADScanner(domain="lab.local", dc_host="dc01")
    res = asyncio.run(s.build_attack_paths())
    assert res == []
    assert not [f for f in s._findings if "path" in f.title.lower()]


# ── kerberoasting severity no longer escalates off an ldap3 truthiness bug ────

def test_kerberoasting_severity_requires_real_admincount():
    from heaven.recon.ad_scanner import _attr_int

    class _AC:
        # Mimic an ldap3 Attribute whose value is absent (truthy wrapper, 0 value).
        value = None

        def __bool__(self):
            return True

    class _E:
        adminCount = _AC()

    # The wrapper is truthy, but _attr_int reads the (absent) value → 0, so the
    # account is NOT treated as privileged (the fix for the severity FP).
    assert _attr_int(_E(), "adminCount") == 0


def test_kerberoasting_excludes_krbtgt_and_rates_nonpriv_high():
    # Found live: krbtgt carries SPNs AND adminCount=1, so including it inflated
    # the roast list and wrongly escalated the finding to critical. The query must
    # exclude krbtgt, critical system objects and disabled accounts, and a plain
    # service account must be rated high, not critical.
    conn = _RoutingConn(routes=[
        ("servicePrincipalName=*",
         [_Entry(sAMAccountName="svc_sql",
                 servicePrincipalName=["MSSQLSvc/dc1.heaven.local:1433"])])])
    s = _mk_scanner(conn)
    asyncio.run(s.check_kerberoasting())
    kq = next(f for f in conn.filters if "servicePrincipalName=*" in f)
    assert "sAMAccountName=krbtgt" in kq
    assert "isCriticalSystemObject=TRUE" in kq
    assert "1.2.840.113556.1.4.803:=2" in kq  # ACCOUNTDISABLE excluded
    kerb = [f for f in s._findings if f.attack_type == ADAttackType.KERBEROASTING]
    assert kerb and kerb[0].severity == "high"
    assert "svc_sql" in kerb[0].affected_objects
