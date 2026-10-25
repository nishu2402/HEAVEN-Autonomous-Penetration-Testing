"""HEAVEN: Active Directory security-descriptor (DACL) parsing for DCSync and
object-takeover ACL detection.

``ad_scanner`` reads an object's ``nTSecurityDescriptor`` to decide two things no
LDAP attribute states directly:

* DCSync: which principals hold the DS-Replication-Get-Changes[-All] extended
  rights on the domain head (the ground truth for a DCSync grant; the
  ``adminCount`` attribute is NOT that, which is why it stays a pointer).
* ACL abuse: which principals hold GenericAll / WriteDacl / WriteOwner /
  GenericWrite / write-to-``member`` over a privileged group (a BloodHound-style
  takeover edge).

Both reduce to the same job: parse the DACL and read each ACCESS_ALLOWED (plain or
object) ACE as ``(sid, mask, object_guid)``. The parse returns ``None`` when the
descriptor cannot be read (impacket's ldaptypes unavailable, or malformed bytes)
so the caller downgrades to an honest "could not confirm" pointer instead of
guessing. A right granted to a principal that holds it BY DEFAULT (a Domain
Controller, Domain/Enterprise Admins, BUILTIN\\Administrators, SYSTEM, Enterprise
Domain Controllers, Self, Creator Owner) is normal and is never reported; that
exclusion is what keeps the detector from firing on every domain.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from heaven.utils.logger import get_logger

logger = get_logger(__name__)

# ── Access-mask / ACE constants (from the DACL) ──────────────────────────────
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100   # "control access", an extended right
ADS_RIGHT_DS_WRITE_PROP = 0x00000020       # write a specific property
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
_ACE_OBJECT_TYPE_PRESENT = 0x01

# Replication extended-right GUIDs that together permit DCSync.
REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
_REPL_GUIDS = frozenset({REPL_GET_CHANGES, REPL_GET_CHANGES_ALL,
                         REPL_GET_CHANGES_FILTERED})

# The ``member`` attribute GUID: write to it = add any principal (incl. self) to
# the group, a direct takeover of a privileged group.
ATTR_MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# SIDs/RIDs that hold privileged rights BY DEFAULT. A grant to any of these is the
# normal state of a domain and must never be reported as an exposure. This MUST
# include the built-in operator groups: a real DC's default DACL on every
# privileged group grants Account/Server/Print/Backup Operators write-equivalent
# rights, so omitting them floods every domain with phantom takeover edges (found
# live against a real Samba DC). The dangerous case is a NON-built-in, low-priv
# principal (a normal user, Authenticated Users, Everyone, a custom group).
_DEFAULT_PRIVILEGED_EXACT = frozenset({
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-10",      # Principal Self
    "S-1-5-18",      # Local System
    "S-1-3-0",       # Creator Owner
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-548",  # BUILTIN\Account Operators
    "S-1-5-32-549",  # BUILTIN\Server Operators
    "S-1-5-32-550",  # BUILTIN\Print Operators
    "S-1-5-32-551",  # BUILTIN\Backup Operators
    "S-1-5-32-552",  # BUILTIN\Replicator
})

# Well-known SID -> readable name, for findings (these have no directory object
# with a sAMAccountName to resolve). Note which are NOT default-privileged
# (Everyone / Anonymous / Authenticated Users / BUILTIN\Users): a grant to them is
# a genuine exposure, we just render it readably.
WELL_KNOWN_SID_NAMES = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-18": "SYSTEM",
    "S-1-5-10": "Self",
    "S-1-3-0": "Creator Owner",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicator",
}


def well_known_name(sid: str) -> Optional[str]:
    """Readable name for a well-known SID, or ``None`` if not well known."""
    return WELL_KNOWN_SID_NAMES.get(sid)
# Domain-relative RIDs (the SID ends with "-<rid>").
_DEFAULT_PRIVILEGED_RIDS = frozenset({
    "500",  # Administrator
    "502",  # krbtgt
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "521",  # Read-only Domain Controllers
    "498",  # Enterprise Read-only Domain Controllers
})

# Human labels for the dangerous write-equivalent rights, keyed by mask bit.
_WRITE_RIGHT_LABELS = (
    (ADS_RIGHT_GENERIC_ALL, "GenericAll"),
    (ADS_RIGHT_GENERIC_WRITE, "GenericWrite"),
    (ADS_RIGHT_WRITE_DAC, "WriteDacl"),
    (ADS_RIGHT_WRITE_OWNER, "WriteOwner"),
)


@dataclass
class Ace:
    """One ACCESS_ALLOWED ACE: the trustee SID, its access mask, and the
    ObjectType GUID when the ACE is an object ACE (``None`` otherwise, which means
    the right applies to every object / all extended rights)."""
    sid: str
    mask: int
    object_guid: Optional[str]


def _guid_le_bytes_to_str(b: bytes) -> str:
    """Format a little-endian 16-byte GUID as its canonical string."""
    if len(b) != 16:
        return b.hex()
    d1, d2, d3 = struct.unpack("<IHH", b[:8])
    return (f"{d1:08x}-{d2:04x}-{d3:04x}-"
            f"{b[8]:02x}{b[9]:02x}-"
            f"{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}")


def _ace_object_guid(ace_body) -> Optional[str]:
    """ObjectType GUID string of an object ACE, or ``None`` when the ACE carries
    no ObjectType (right applies to all objects / all extended rights)."""
    try:
        flags = int(ace_body["Flags"])
        if not (flags & _ACE_OBJECT_TYPE_PRESENT):
            return None
        raw = ace_body["ObjectType"]
        if not raw:
            return None
        return _guid_le_bytes_to_str(bytes(raw))
    except Exception:
        return None


def parse_dacl(sd_bytes: Optional[bytes]) -> Optional[list[Ace]]:
    """Parse an ``nTSecurityDescriptor`` and return its ACCESS_ALLOWED ACEs.

    Returns ``None`` when the descriptor cannot be parsed (impacket unavailable or
    malformed bytes) so the caller stays honest about not having confirmed rights.
    An empty list means it parsed but held no allow ACEs.
    """
    if not sd_bytes:
        return None
    try:
        from impacket.ldap import ldaptypes
    except Exception:
        logger.debug("impacket ldaptypes unavailable; cannot parse DACL")
        return None
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        logger.debug("failed to parse nTSecurityDescriptor", exc_info=True)
        return None
    # impacket's SR_SECURITY_DESCRIPTOR is a Structure with NO __getattr__, so its
    # fields are dict-accessed; getattr(sd, "Dacl") would silently be None.
    try:
        dacl = sd["Dacl"]
    except Exception:
        return None
    if dacl is None:
        return None
    aces: list[Ace] = []
    for ace in dacl.aces:
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE_TYPE,
                                  ACCESS_ALLOWED_OBJECT_ACE_TYPE):
            continue
        body = ace["Ace"]
        try:
            sid = body["Sid"].formatCanonical()
        except Exception:
            logger.debug("could not format ACE SID", exc_info=True)
            continue
        try:
            mask = int(body["Mask"]["Mask"])
        except Exception:
            logger.debug("could not read ACE mask", exc_info=True)
            continue
        guid = (_ace_object_guid(body)
                if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE_TYPE else None)
        aces.append(Ace(sid=sid, mask=mask, object_guid=guid))
    return aces


def sid_is_default_privileged(sid: str) -> bool:
    """True when the SID is a principal that holds privileged rights by default,
    so a grant to it is the normal state of a domain rather than an exposure."""
    if sid in _DEFAULT_PRIVILEGED_EXACT:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return sid.startswith("S-1-5-21-") and rid in _DEFAULT_PRIVILEGED_RIDS


def ace_grants_replication(ace: Ace) -> bool:
    """True when the ACE confers the DS-Replication-Get-Changes[-All] rights that
    together permit DCSync: GenericAll, a control-access ACE for a replication
    GUID, or a plain / all-objects control-access ACE (= all extended rights)."""
    if ace.mask & ADS_RIGHT_GENERIC_ALL:
        return True
    if ace.mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        # Object ACE: only the specific replication rights (or "all extended
        # rights" when no ObjectType is present) count. Plain allow ACE with the
        # control-access bit = all extended rights.
        return ace.object_guid is None or ace.object_guid.lower() in _REPL_GUIDS
    return False


def ace_dangerous_group_rights(ace: Ace) -> list[str]:
    """Names of the takeover-grade rights this ACE confers over a group object:
    GenericAll / GenericWrite / WriteDacl / WriteOwner (full control of the ACL or
    object), or a write to the ``member`` property (add anyone to the group)."""
    rights: list[str] = []
    for bit, label in _WRITE_RIGHT_LABELS:
        if ace.mask & bit:
            rights.append(label)
    if ace.mask & ADS_RIGHT_DS_WRITE_PROP:
        # A property write is dangerous on a group only when it targets ``member``
        # (or the whole object when no specific property is named).
        if ace.object_guid is None or ace.object_guid.lower() == ATTR_MEMBER_GUID:
            rights.append("WriteProperty(member)")
    return rights
