"""
HEAVEN — BloodHound-compatible AD data collector

Queries Active Directory via LDAP (using ldap3) and emits JSON files in
the BloodHound v4.x ingestor schema. Operator opens BloodHound, drops
the JSON files in, and gets the standard attack-path graph.

This is intentionally a *minimal* collector — not a SharpHound replacement.
It covers the four most operationally useful collections:
  users.json   — user accounts (name, SID, lastLogon, AdminCount)
  groups.json  — security groups + memberships
  computers.json — computer accounts
  domains.json — the domain object itself

What it does NOT collect (yet):
  - Sessions (requires SMB/wmiexec — needs impacket; future work)
  - Local admin enumeration via SAM-R
  - GPO / OU / Trust relationships

Auth + reuse:
  Reuses the credentials stored in heaven.config.ADConfig so the same
  AD scope the recon module already enumerates is what's collected.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger("postex.bloodhound")


@dataclass
class CollectionResult:
    domain: str
    success: bool
    counts: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    error: str = ""


class BloodHoundCollector:
    """Minimal BloodHound JSON collector via LDAP."""

    BH_VERSION = 4

    def __init__(self, authorized: bool = False):
        self.authorized = authorized

    def collect(self, domain: str, dc_host: str, username: str,
                password: str, use_ssl: bool = False,
                output_dir: Optional[Path] = None) -> CollectionResult:
        if not self.authorized:
            return CollectionResult(domain, False, error="aborted: collector not authorized")
        try:
            from ldap3 import Server, Connection, SUBTREE, ALL  # type: ignore[import-not-found]
        except ImportError:
            return CollectionResult(
                domain, False,
                error="ldap3 not installed — pip install ldap3",
            )

        output_dir = output_dir or Path(f"data/bloodhound/{domain}/{int(time.time())}")
        output_dir.mkdir(parents=True, exist_ok=True)

        server = Server(dc_host, use_ssl=use_ssl, get_info=ALL)
        bind_user = f"{username}@{domain}" if "@" not in username else username
        try:
            conn = Connection(server, user=bind_user, password=password,
                              auto_bind=True, raise_exceptions=False)
        except Exception as e:
            return CollectionResult(domain, False,
                                    error=f"LDAP bind failed: {e}")

        try:
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            collections: dict[str, tuple[str, list[str]]] = {
                "users":     ("(objectCategory=person)",
                              ["sAMAccountName", "objectSid", "lastLogonTimestamp",
                               "adminCount", "userAccountControl", "memberOf"]),
                "groups":    ("(objectCategory=group)",
                              ["sAMAccountName", "objectSid", "member", "description"]),
                "computers": ("(objectCategory=computer)",
                              ["dNSHostName", "operatingSystem", "objectSid", "memberOf"]),
            }

            counts: dict[str, int] = {}
            files: list[str] = []
            for kind, (ldap_filter, attrs) in collections.items():
                conn.search(base_dn, ldap_filter, attributes=attrs, search_scope=SUBTREE)
                docs = []
                for entry in conn.entries:
                    docs.append(_entry_to_bh_doc(entry, kind, domain))
                fname = output_dir / f"{kind}.json"
                fname.write_text(json.dumps({
                    "data": docs,
                    "meta": {"type": kind, "count": len(docs), "version": self.BH_VERSION},
                }, indent=2))
                counts[kind] = len(docs)
                files.append(str(fname))

            # Minimal domain object
            domain_doc = {
                "data": [{
                    "Properties": {"name": domain.upper(), "domain": domain.upper()},
                    "ObjectIdentifier": domain.upper(),
                    "Aces": [], "Trusts": [], "Links": [],
                }],
                "meta": {"type": "domains", "count": 1, "version": self.BH_VERSION},
            }
            dom_file = output_dir / "domains.json"
            dom_file.write_text(json.dumps(domain_doc, indent=2))
            counts["domains"] = 1
            files.append(str(dom_file))

            return CollectionResult(domain=domain, success=True,
                                    counts=counts, files=files)
        finally:
            try:
                conn.unbind()
            except Exception:
                pass


def _entry_to_bh_doc(entry: Any, kind: str, domain: str) -> dict[str, Any]:
    """Translate one ldap3 entry into a minimal BloodHound v4 object."""
    name = (getattr(entry, "sAMAccountName", None)
            or getattr(entry, "dNSHostName", None)
            or "<unknown>")
    name = str(name)
    sid = str(getattr(entry, "objectSid", ""))
    obj_id = sid or f"{name}@{domain.upper()}"
    member_of = [str(m) for m in (getattr(entry, "memberOf", []) or [])]
    members = [str(m) for m in (getattr(entry, "member", []) or [])]

    base = {
        "Properties": {
            "name": f"{name}@{domain.upper()}",
            "domain": domain.upper(),
            "objectid": obj_id,
        },
        "ObjectIdentifier": obj_id,
        "Aces": [],
    }
    if kind == "users":
        base["PrimaryGroupSID"] = ""
        base["Properties"]["enabled"] = True   # simplification
        base["Properties"]["admincount"] = bool(getattr(entry, "adminCount", 0))
        base["MemberOf"] = member_of
    elif kind == "groups":
        base["Members"] = members
    elif kind == "computers":
        base["Properties"]["operatingsystem"] = str(getattr(entry, "operatingSystem", ""))
        base["MemberOf"] = member_of
    return base
