"""HEAVEN — Active Directory Certificate Services (AD CS) misconfiguration audit.

AD CS is the dominant privilege-escalation surface in modern Active Directory
engagements: a single over-permissive certificate template lets any domain user
enrol a certificate that authenticates as a Domain Admin. This module enumerates
the Certificate Authorities and published templates over the SAME read-only LDAP
session the ``ad_scanner`` already establishes (the Configuration naming context
holds the PKI objects) and classifies each template against the well-known ESC
abuse categories:

    ESC1  Enrollee-supplies-subject + a client-authentication EKU, no manager
          approval and no enrolment-agent signature, enrollable by low-privileged
          principals. A domain user requests a cert with an arbitrary
          ``subjectAltName`` (e.g. a Domain Admin UPN) and authenticates as them.
    ESC2  "Any Purpose" EKU (or no EKU / SubCA), enrollable by low-priv principals.
          The issued certificate can be used for any purpose, including client
          authentication.
    ESC3  Certificate-Request-Agent EKU, enrollable by low-priv principals. Lets
          the holder enrol on behalf of any other principal.
    ESC4  A low-privileged principal holds write access (WriteDacl / WriteOwner /
          GenericAll / GenericWrite / full control) over the template object, so
          they can reconfigure it into an ESC1.
    ESC8  A CA exposes an NTLM-authenticated web-enrolment endpoint
          (``/certsrv/``). Combined with an authentication-coercion vector this is
          a relay-to-domain-takeover path (see coercion_probe.py).

Everything here is READ-ONLY: LDAP searches and a single HTTP HEAD/GET to the CA
web-enrolment URL. It never requests, enrols or forges a certificate. When the
security descriptor cannot be parsed (impacket's ldaptypes unavailable, or the
attribute is not returned) a template whose *configuration* is abusable is still
reported, but as a lower-confidence "potential" finding because the enrolment
rights could not be confirmed — the tool never claims an exploit it did not
verify.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from heaven.utils.logger import get_logger

logger = get_logger(__name__)

# ── Extended Key Usage / Application Policy OIDs ─────────────────────────────────
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"  # a.k.a. Enrollment Agent
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

# Any of these EKUs makes a certificate usable to authenticate to Active Directory.
_AUTH_EKUS = frozenset({EKU_CLIENT_AUTH, EKU_PKINIT_CLIENT, EKU_SMARTCARD_LOGON})

# ── msPKI-Certificate-Name-Flag bits ────────────────────────────────────────────
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# ── msPKI-Enrollment-Flag bits ──────────────────────────────────────────────────
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002  # manager approval required

# ── Low-privileged well-known SIDs / RIDs (enrollable-by-anyone signal) ─────────
# Exact SIDs (identity independent of the domain).
_LOW_PRIV_EXACT_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-7",       # Anonymous
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
})
# Domain-relative RIDs that denote broad groups (the SID ends with "-<rid>").
_LOW_PRIV_DOMAIN_RIDS = frozenset({"513", "514", "515", "545"})
# Domain Users, Domain Guests, Domain Computers, Users.

# ── Active Directory access-mask / ACE constants (from the SD DACL) ─────────────
# Rights that let a principal reconfigure the template object (→ ESC4).
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100  # "control access" — extended right
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000

_WRITE_MASK = (
    ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_WRITE_DAC | ADS_RIGHT_WRITE_OWNER
    | ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_GENERIC_WRITE
)

# Certificate-Enrollment / Certificate-AutoEnrollment extended-right GUIDs.
_ENROLL_RIGHT_GUIDS = {
    "0e10c968-78fb-11d2-90d4-00c04f79dc55",  # Certificate-Enrollment
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2",  # Certificate-AutoEnrollment
}

ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05


@dataclass
class ADCSFinding:
    """An AD CS misconfiguration finding, shaped like every other HEAVEN finding."""
    target: str
    vuln_type: str
    severity: str
    title: str
    description: str
    confidence: float = 0.0
    remediation: str = ""
    mitre_technique: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target, "vuln_type": self.vuln_type,
            "severity": self.severity, "title": self.title,
            "description": self.description, "confidence": self.confidence,
            "remediation": self.remediation, "mitre_technique": self.mitre_technique,
            "evidence": self.evidence,
        }


# ── Pure classification helpers (unit-testable without LDAP/impacket) ───────────

def _has_authentication_eku(ekus: list[str]) -> bool:
    """True when the template's EKUs allow AD client authentication — or when it
    has NO EKU restriction at all (an unrestricted / SubCA template, usable for
    anything including authentication)."""
    if not ekus:
        return True
    e = set(ekus)
    return bool(e & _AUTH_EKUS) or EKU_ANY_PURPOSE in e


def _is_any_purpose(ekus: list[str]) -> bool:
    """True for an "Any Purpose" template or one with no EKU restriction (SubCA)."""
    return (not ekus) or (EKU_ANY_PURPOSE in set(ekus))


def classify_template(template: dict) -> list[dict]:
    """Classify one certificate template against the ESC abuse categories.

    ``template`` is a normalized dict:
        name (str), enabled (bool), enrollee_supplies_subject (bool),
        requires_manager_approval (bool), authorized_signatures (int),
        ekus (list[str]), low_priv_can_enroll (bool | None),
        low_priv_can_write (bool | None), ca (str)

    ``low_priv_can_enroll`` / ``low_priv_can_write`` may be None when the security
    descriptor could not be parsed — the result is then downgraded to "potential"
    (a real configuration weakness, unconfirmed enrolment rights). Returns a list
    of ``{esc, severity, confirmed}`` descriptors (possibly empty).
    """
    out: list[dict] = []
    if not template.get("enabled", True):
        return out  # a disabled/unpublished template is not enrollable

    ess = bool(template.get("enrollee_supplies_subject"))
    approval = bool(template.get("requires_manager_approval"))
    ra_sigs = int(template.get("authorized_signatures") or 0)
    ekus = list(template.get("ekus") or [])
    can_enroll = template.get("low_priv_can_enroll")
    can_write = template.get("low_priv_can_write")

    # A template is only escalatable if it can be enrolled without manager sign-off
    # and without an enrolment-agent signature.
    unrestricted_enroll = (not approval) and (ra_sigs == 0)

    # ESC1 — enrollee supplies subject + authentication EKU.
    if unrestricted_enroll and ess and _has_authentication_eku(ekus):
        confirmed = can_enroll is True
        out.append({"esc": "ESC1", "severity": "critical" if confirmed else "high",
                    "confirmed": confirmed})

    # ESC2 — Any-Purpose / no-EKU (SubCA-like) template.
    if unrestricted_enroll and _is_any_purpose(ekus) and not ess:
        confirmed = can_enroll is True
        out.append({"esc": "ESC2", "severity": "critical" if confirmed else "high",
                    "confirmed": confirmed})

    # ESC3 — Certificate Request Agent (Enrollment Agent) EKU.
    if unrestricted_enroll and EKU_CERT_REQUEST_AGENT in set(ekus):
        confirmed = can_enroll is True
        out.append({"esc": "ESC3", "severity": "critical" if confirmed else "high",
                    "confirmed": confirmed})

    # ESC4 — a low-priv principal can rewrite the template's configuration.
    if can_write is True:
        out.append({"esc": "ESC4", "severity": "high", "confirmed": True})

    return out


# ── Security-descriptor parsing (impacket, optional) ────────────────────────────

def _parse_enroll_and_write(sd_bytes: bytes) -> tuple[Optional[bool], Optional[bool]]:
    """Parse an nTSecurityDescriptor and return
    ``(low_priv_can_enroll, low_priv_can_write)``.

    Returns ``(None, None)`` when the descriptor cannot be parsed (impacket
    unavailable or malformed bytes) so the caller downgrades to "potential".
    """
    if not sd_bytes:
        return None, None
    try:
        from impacket.ldap import ldaptypes
    except Exception:  # impacket ldaptypes not available — cannot confirm rights
        logger.debug("impacket ldaptypes unavailable; enrolment rights unresolved")
        return None, None
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        logger.debug("failed to parse nTSecurityDescriptor", exc_info=True)
        return None, None

    can_enroll = False
    can_write = False
    dacl = getattr(sd, "Dacl", None)
    if dacl is None:
        return None, None
    for ace in dacl.aces:
        ace_type = ace["AceType"]
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE):
            continue
        body = ace["Ace"]
        try:
            sid = body["Sid"].formatCanonical()
        except Exception:
            logger.debug("could not format ACE SID", exc_info=True)
            continue
        if not _sid_is_low_priv(sid):
            continue
        mask = int(body["Mask"]["Mask"])

        # Write-equivalent rights → ESC4.
        if mask & _WRITE_MASK:
            can_write = True

        # Enrolment right: GenericAll, or a control-access ACE whose ObjectType is
        # (a) the enrolment extended-right GUID, or (b) absent (= all extended
        # rights).
        if mask & ADS_RIGHT_GENERIC_ALL:
            can_enroll = True
        elif mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                guid = _ace_object_guid(body)
                if guid is None or guid.lower() in _ENROLL_RIGHT_GUIDS:
                    can_enroll = True
            else:
                can_enroll = True  # plain control-access = all extended rights
    return can_enroll, can_write


def _ace_object_guid(ace_body: Any) -> Optional[str]:
    """Return the ObjectType GUID string of an object ACE, or None when the ACE
    carries no ObjectType (which means the right applies to all objects)."""
    try:
        # impacket sets ObjectType only when the ACE flags mark it present.
        flags = int(ace_body["Flags"])
        if not (flags & 0x01):  # ACE_OBJECT_TYPE_PRESENT
            return None
        raw = ace_body["ObjectType"]
        if not raw:
            return None
        return _guid_le_bytes_to_str(bytes(raw))
    except Exception:
        return None


def _guid_le_bytes_to_str(b: bytes) -> str:
    """Format a little-endian 16-byte GUID as its canonical string."""
    if len(b) != 16:
        return b.hex()
    import struct
    d1, d2, d3 = struct.unpack("<IHH", b[:8])
    return (f"{d1:08x}-{d2:04x}-{d3:04x}-"
            f"{b[8]:02x}{b[9]:02x}-"
            f"{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}")


def _sid_is_low_priv(sid: str) -> bool:
    """True when a SID denotes a broad, low-privileged principal (any domain user
    / authenticated user / everyone / computers)."""
    if sid in _LOW_PRIV_EXACT_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return sid.startswith("S-1-5-21-") and rid in _LOW_PRIV_DOMAIN_RIDS


# ── LDAP enumeration ────────────────────────────────────────────────────────────

def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_template(entry: Any) -> dict:
    """Turn an ldap3 pKICertificateTemplate entry into the classifier's dict."""
    def g(attr: str) -> Any:
        try:
            v = getattr(entry, attr)
            return v.value if hasattr(v, "value") else v
        except Exception:
            return None

    def glist(attr: str) -> list[str]:
        try:
            v = getattr(entry, attr)
            vals = v.values if hasattr(v, "values") else v
            if vals is None:
                return []
            if isinstance(vals, (list, tuple)):
                return [str(x) for x in vals]
            return [str(vals)]
        except Exception:
            return []

    name = g("cn") or g("name") or "<unknown>"
    name_flag = _to_int(g("msPKI-Certificate-Name-Flag"))
    enroll_flag = _to_int(g("msPKI-Enrollment-Flag"))
    ra_sigs = _to_int(g("msPKI-RA-Signature"))
    ekus = glist("pKIExtendedKeyUsage") or glist("msPKI-Certificate-Application-Policy")

    sd_bytes = g("nTSecurityDescriptor")
    if isinstance(sd_bytes, str):
        sd_bytes = sd_bytes.encode("latin-1", "ignore")
    can_enroll, can_write = _parse_enroll_and_write(sd_bytes or b"")

    return {
        "name": str(name),
        "enabled": True,  # only *published* templates reach us (see enumerate)
        "enrollee_supplies_subject": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
        "requires_manager_approval": bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS),
        "authorized_signatures": ra_sigs,
        "ekus": ekus,
        "low_priv_can_enroll": can_enroll,
        "low_priv_can_write": can_write,
    }


_ESC_META = {
    "ESC1": ("adcs_esc1", "T1649 · Steal or Forge Authentication Certificates",
             "Enrollee-supplies-subject template with a client-authentication EKU"),
    "ESC2": ("adcs_esc2", "T1649 · Steal or Forge Authentication Certificates",
             "Any-Purpose / SubCA certificate template enrollable by low-priv users"),
    "ESC3": ("adcs_esc3", "T1649 · Steal or Forge Authentication Certificates",
             "Enrolment-Agent template enrollable by low-priv users"),
    "ESC4": ("adcs_esc4", "T1649 · Steal or Forge Authentication Certificates",
             "Certificate template object writable by low-priv users"),
    "ESC8": ("adcs_esc8", "T1649 · Steal or Forge Authentication Certificates",
             "CA web-enrolment endpoint accepts NTLM (relay target)"),
}

_ESC_REMEDIATION = {
    "ESC1": ("Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from the template, require "
             "manager approval or an enrolment-agent signature, and restrict the "
             "template's enrolment ACL to the principals that genuinely need it."),
    "ESC2": ("Replace the Any-Purpose EKU with the minimum required EKUs, require "
             "manager approval, and restrict enrolment rights."),
    "ESC3": ("Restrict who may enrol the Certificate Request Agent template and "
             "enable the enrolment-agent restrictions on the CA."),
    "ESC4": ("Tighten the template's DACL so low-privileged principals cannot "
             "write to it; audit for WriteDacl/WriteOwner/GenericAll grants."),
    "ESC8": ("Disable HTTP web enrolment or enforce Extended Protection for "
             "Authentication (EPA) and require HTTPS + channel binding; disable "
             "NTLM on the CA and remove the coercion surface."),
}


def enumerate_adcs(conn: Any, config_nc: str,
                   web_reachable_cas: Optional[dict[str, list[str]]] = None) -> list[dict]:
    """Enumerate AD CS CAs + templates over an existing ldap3 ``conn`` and return
    a list of finding dicts. ``config_nc`` is the Configuration naming context DN
    (``CN=Configuration,DC=...``). ``web_reachable_cas`` optionally maps a CA
    dNSHostName to the reachable ``/certsrv`` URL(s) for ESC8.
    """
    findings: list[ADCSFinding] = []
    if conn is None or not config_nc:
        return []

    pki_base = f"CN=Public Key Services,CN=Services,{config_nc}"
    ca_base = f"CN=Enrollment Services,{pki_base}"
    tmpl_base = f"CN=Certificate Templates,{pki_base}"

    # 1. Enumerate the CAs and the templates each one has *published* (only a
    #    published template is actually enrollable).
    published: set[str] = set()
    cas: list[dict] = []
    try:
        conn.search(ca_base, "(objectClass=pKIEnrollmentService)",
                    attributes=["cn", "dNSHostName", "certificateTemplates"])
        for entry in getattr(conn, "entries", []):
            ca_name = _safe_val(entry, "cn")
            dns = _safe_val(entry, "dNSHostName")
            templates = _safe_list(entry, "certificateTemplates")
            published.update(t.lower() for t in templates)
            cas.append({"name": ca_name, "dns": dns, "templates": templates})
    except Exception:
        logger.debug("AD CS CA enumeration failed (no PKI container?)", exc_info=True)
        return []

    if not cas:
        return []

    logger.info("AD CS: %d certificate authority(ies) discovered", len(cas))
    for ca in cas:
        target = ca["dns"] or ca["name"] or "AD CS"
        findings.append(ADCSFinding(
            target=str(target), vuln_type="adcs_ca_discovered", severity="info",
            title=f"AD CS Certificate Authority: {ca['name']}",
            description=(f"Enterprise CA '{ca['name']}' on {ca['dns'] or 'unknown host'} "
                         f"publishes {len(ca['templates'])} certificate template(s)."),
            confidence=0.99, mitre_technique="T1649",
            evidence={"ca_name": ca["name"], "dns_host": ca["dns"],
                      "published_templates": ca["templates"]},
        ))

        # 2. ESC8 — web enrolment relay surface.
        urls = (web_reachable_cas or {}).get(ca["dns"] or "", [])
        if urls:
            findings.append(ADCSFinding(
                target=str(ca["dns"] or target), vuln_type="adcs_esc8", severity="high",
                title=f"AD CS web enrolment exposed (ESC8) on {ca['name']}",
                description=("The CA exposes an HTTP(S) web-enrolment endpoint that "
                             "accepts NTLM authentication. Combined with an "
                             "authentication-coercion vector, an attacker can relay a "
                             "Domain Controller's machine authentication to this "
                             "endpoint and obtain a certificate that authenticates as "
                             "the DC (domain takeover)."),
                confidence=0.8, mitre_technique="T1649",
                remediation=_ESC_REMEDIATION["ESC8"],
                evidence={"ca_name": ca["name"], "endpoints": urls, "esc": "ESC8"},
            ))

    # 3. Enumerate + classify the templates.
    try:
        conn.search(tmpl_base, "(objectClass=pKICertificateTemplate)",
                    attributes=["cn", "name", "msPKI-Certificate-Name-Flag",
                                "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                                "pKIExtendedKeyUsage",
                                "msPKI-Certificate-Application-Policy",
                                "nTSecurityDescriptor"])
        entries = list(getattr(conn, "entries", []))
    except Exception:
        logger.debug("AD CS template enumeration failed", exc_info=True)
        entries = []

    for entry in entries:
        tmpl = _normalize_template(entry)
        # Only assess templates that are actually published by a CA.
        if published and tmpl["name"].lower() not in published:
            continue
        for hit in classify_template(tmpl):
            findings.append(_finding_for_esc(tmpl, hit))

    return [f.to_dict() for f in findings]


def _finding_for_esc(tmpl: dict, hit: dict) -> ADCSFinding:
    esc = hit["esc"]
    vuln_type, mitre, blurb = _ESC_META[esc]
    confirmed = hit["confirmed"]
    name = tmpl["name"]
    status = "confirmed" if confirmed else "potential (enrolment rights unconfirmed)"
    return ADCSFinding(
        target=f"template:{name}", vuln_type=vuln_type, severity=hit["severity"],
        title=f"AD CS {esc}: certificate template '{name}' is escalatable",
        description=(f"{blurb}. {('A low-privileged principal can enrol this template' if confirmed else 'The template configuration is abusable, but enrolment rights could not be confirmed from the security descriptor')}. "
                     f"An attacker who can enrol obtains a certificate that "
                     f"authenticates as a chosen principal, enabling privilege "
                     f"escalation up to Domain Admin ({status})."),
        confidence=0.9 if confirmed else 0.55,
        mitre_technique=mitre, remediation=_ESC_REMEDIATION[esc],
        evidence={"esc": esc, "template": name,
                  "enrollee_supplies_subject": tmpl["enrollee_supplies_subject"],
                  "requires_manager_approval": tmpl["requires_manager_approval"],
                  "authorized_signatures": tmpl["authorized_signatures"],
                  "ekus": tmpl["ekus"],
                  "low_priv_can_enroll": tmpl["low_priv_can_enroll"],
                  "low_priv_can_write": tmpl["low_priv_can_write"],
                  "confirmed": confirmed},
    )


def _safe_val(entry: Any, attr: str) -> str:
    try:
        v = getattr(entry, attr)
        v = v.value if hasattr(v, "value") else v
        return "" if v is None else str(v)
    except Exception:
        return ""


def _safe_list(entry: Any, attr: str) -> list[str]:
    try:
        v = getattr(entry, attr)
        vals = v.values if hasattr(v, "values") else v
        if vals is None:
            return []
        if isinstance(vals, (list, tuple)):
            return [str(x) for x in vals]
        return [str(vals)]
    except Exception:
        return []
