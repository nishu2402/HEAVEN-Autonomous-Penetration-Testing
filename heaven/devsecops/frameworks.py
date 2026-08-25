"""HEAVEN — OT / IoT security-framework taxonomy.

Consumer-IoT and industrial-OT findings do **not** belong under the web OWASP
Top 10 (2021) — a Modbus PLC reachable from the corporate LAN is not "A01
Broken Access Control". This module maps those findings to the frameworks the
industry actually uses for each domain:

  • Consumer / building IoT      → OWASP IoT Top 10 (2018)  (I1–I10)
  • Operational technology / ICS → IEC 62443-3-3 Foundational Requirements
    (FR1–FR7), cross-referenced to MITRE ATT&CK for ICS techniques.

``classify_iot_ot(finding)`` derives the framework tags for one IoT/OT finding
from its protocol + title (never fabricated — every mapping is grounded in the
published framework). The report layer renders two dynamic coverage matrices
from these tags, exactly the way the web OWASP matrix is built, so an IoT/OT
engagement is scored against the *right* standard.

Kept dependency-free (stdlib only) so both the recon scanners and the report
generators can import it without an import cycle.
"""

from __future__ import annotations

import re
from typing import Any

# ── Canonical framework lists (rendered in full as a coverage matrix) ────────

# OWASP IoT Top 10 (2018). https://owasp.org/www-project-internet-of-things/
OWASP_IOT_2018: list[tuple[str, str]] = [
    ("I1", "Weak, Guessable, or Hardcoded Passwords"),
    ("I2", "Insecure Network Services"),
    ("I3", "Insecure Ecosystem Interfaces"),
    ("I4", "Lack of Secure Update Mechanism"),
    ("I5", "Use of Insecure or Outdated Components"),
    ("I6", "Insufficient Privacy Protection"),
    ("I7", "Insecure Data Transfer and Storage"),
    ("I8", "Lack of Device Management"),
    ("I9", "Insecure Default Settings"),
    ("I10", "Lack of Physical Hardening"),
]

# IEC 62443-3-3 Foundational Requirements — the OT/ICS equivalent of a "top N".
# A read-only external scan primarily exercises FR1 (authentication) and FR5
# (network segmentation / restricted data flow); the full list is shown so the
# matrix is an honest coverage statement, not a cherry-picked subset.
IEC_62443_FR: list[tuple[str, str]] = [
    ("FR1", "Identification & Authentication Control"),
    ("FR2", "Use Control"),
    ("FR3", "System Integrity"),
    ("FR4", "Data Confidentiality"),
    ("FR5", "Restricted Data Flow"),
    ("FR6", "Timely Response to Events"),
    ("FR7", "Resource Availability"),
]

OWASP_IOT_REFERENCE = "https://owasp.org/www-project-internet-of-things/"
IEC_62443_REFERENCE = "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards"
ATTACK_ICS_REFERENCE = "https://attack.mitre.org/matrices/ics/"

# ── Web OWASP Top 10 (2025) — the single source of truth ─────────────────────
#
# The 2025 edition (https://owasp.org/Top10/2025/) is a re-ranking of 2021 with
# two structural changes every consumer of this data must respect:
#   • SSRF (A10:2021) is no longer a standalone risk — it folds into A01.
#   • "Vulnerable & Outdated Components" (A06:2021) broadened into
#     A03:2025 "Software Supply Chain Failures".
#   • A10:2025 "Mishandling of Exceptional Conditions" is brand-new (CWE-209/
#     703/755/248/390 …): verbose errors, unhandled exceptions, fail-open logic.
# Keeping the canon + the 2021→2025 crosswalk here (dependency-free) means the
# report, the coverage self-grade, the methodology page and the UI all speak one
# vocabulary, and any legacy finding stored with a 2021 tag upgrades on read.
OWASP_2025: list[tuple[str, str]] = [
    ("A01:2025", "Broken Access Control"),
    ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"),
    ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"),
    ("A06:2025", "Insecure Design"),
    ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"),
    ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
]
OWASP_2025_REFERENCE = "https://owasp.org/Top10/2025/"

# 2021 → 2025 ordinal remap (a permutation with two merges). Keyed on the bare
# ``Ann`` id; the year is handled separately in ``owasp_2025_id``.
_OWASP_2021_TO_2025_ID: dict[str, str] = {
    "A01": "A01",  # Broken Access Control (now also absorbs SSRF)
    "A02": "A04",  # Cryptographic Failures  #2 → #4
    "A03": "A05",  # Injection               #3 → #5
    "A04": "A06",  # Insecure Design         #4 → #6
    "A05": "A02",  # Security Misconfiguration #5 → #2
    "A06": "A03",  # Vulnerable & Outdated Components → Software Supply Chain
    "A07": "A07",  # (Identification &) Authentication Failures
    "A08": "A08",  # Software or Data Integrity Failures
    "A09": "A09",  # Security Logging & Alerting Failures
    "A10": "A01",  # SSRF → merged into Broken Access Control
}
_OWASP_2025_NAMES: dict[str, str] = {cid.split(":")[0]: name for cid, name in OWASP_2025}
_OWASP_ID_RE = re.compile(r"A(\d{2})[:_](20\d{2})")


def owasp_2025_id(value: str) -> str:
    """The canonical 2025 control id for any OWASP-Top-10 string (``A04:2025``).

    Accepts every shape seen in the wild — ``A05:2021``, ``A05_2021``,
    ``A03:2021-Injection``, ``A02:2025 Security Misconfiguration`` — and returns
    the correctly-remapped 2025 id, or ``""`` when the string carries no
    recognisable web-OWASP id. 2021 ids are crosswalked; 2025 ids pass through;
    an unknown edition is accepted only if the ordinal is a valid 2025 id.
    """
    m = _OWASP_ID_RE.search(str(value or ""))
    if not m:
        return ""
    aid, year = f"A{m.group(1)}", m.group(2)
    if year == "2021":
        aid = _OWASP_2021_TO_2025_ID.get(aid, "")
    if aid not in _OWASP_2025_NAMES:
        return ""
    return f"{aid}:2025"


def normalize_owasp(value: str) -> str:
    """Any OWASP-Top-10 string → the canonical 2025 label
    (``A04:2025 Cryptographic Failures``), or ``""`` if unrecognised.

    This is the upgrade path for legacy findings: a value stored years ago as
    ``A02:2021 Cryptographic Failures`` renders today as its 2025 equivalent, so
    the report / coverage / UI never show a stale edition for old data.
    """
    cid = owasp_2025_id(value)
    if not cid:
        return ""
    return f"{cid} {_OWASP_2025_NAMES[cid.split(':')[0]]}"

# Industrial-protocol tokens. A finding whose protocol/title matches one of
# these is OT/ICS; everything else in the IoT/OT scanners is consumer IoT.
_ICS_PROTOCOLS: tuple[str, ...] = (
    "modbus", "s7comm", "s7 ", "siemens s7", "dnp3", "iec 60870", "iec104",
    "iec-104", "opc-ua", "opcua", "ethernet/ip", "enip", "bacnet", "profinet",
    "cip ", "codesys", "omron fins", "melsec", "hart-ip",
)


def _hay(finding: dict) -> tuple[str, str]:
    proto = str(finding.get("protocol") or "").lower()
    title = str(finding.get("title") or "").lower()
    return proto, title


def is_ics(finding: dict) -> bool:
    """True when a finding belongs to an industrial-control protocol."""
    proto, title = _hay(finding)
    hay = f"{proto} {title}"
    return any(tok in hay for tok in _ICS_PROTOCOLS)


def _classify_ot(proto: str, title: str) -> dict[str, str]:
    # Open ICS port whose protocol handshake did not confirm — exposure only.
    if "did not confirm" in title or ("default port" in title and "open" in title):
        return {
            "device_class": "ot",
            "vuln_type": "ics_port_open_unconfirmed",
            "iec62443": "FR5 Restricted Data Flow",
            "mitre_technique": "T0846 · Remote System Discovery",
        }
    # Modbus is read/write and unauthenticated → an attacker can issue commands.
    if "modbus" in proto or "modbus" in title:
        return {
            "device_class": "ot",
            "vuln_type": "ics_modbus_exposed",
            "iec62443": "FR1 Identification & Authentication Control",
            "mitre_technique": "T0855 · Unauthorized Command Message",
        }
    # Every other confirmed ICS service reachable without authentication.
    return {
        "device_class": "ot",
        "vuln_type": "ics_exposed_service",
        "iec62443": "FR1 Identification & Authentication Control",
        "mitre_technique": "T0846 · Remote System Discovery",
    }


def _classify_iot(proto: str, title: str) -> dict[str, str]:
    if "default credential" in title or "accepts default" in title:
        vt, iid, name = ("iot_default_credentials", "I1",
                         "Weak, Guessable, or Hardcoded Passwords")
        mitre = "T1078.001 — Valid Accounts: Default Accounts"
    elif "web panel" in title or "management panel" in title or "mgmt" in title:
        vt, iid, name = ("iot_exposed_mgmt_interface", "I3",
                         "Insecure Ecosystem Interfaces")
        mitre = "T1133 — External Remote Services"
    elif "snmp" in proto or "community" in title:
        vt, iid, name = ("iot_default_snmp_community", "I9",
                         "Insecure Default Settings")
        mitre = "T1602 — Data from Configuration Repository"
    elif "coap" in proto or "cleartext" in title or "unencrypted" in title:
        vt, iid, name = ("iot_cleartext_protocol", "I7",
                         "Insecure Data Transfer and Storage")
        mitre = "T1040 — Network Sniffing"
    else:  # MQTT / RTSP / UPnP-SSDP and other exposed device services
        vt, iid, name = ("iot_insecure_network_service", "I2",
                         "Insecure Network Services")
        mitre = "T1046 — Network Service Discovery"
    return {
        "device_class": "iot",
        "vuln_type": vt,
        "owasp_iot": f"{iid}:2018 {name}",
        "mitre_technique": mitre,
    }


def classify_iot_ot(finding: dict) -> dict[str, str]:
    """Framework tags for one IoT/OT finding (protocol + title driven).

    Returns a dict carrying ``device_class`` (``iot``/``ot``), a stable
    ``vuln_type`` slug, a ``mitre_technique``, and exactly one of ``owasp_iot``
    (consumer IoT) or ``iec62443`` (industrial OT).
    """
    proto, title = _hay(finding)
    if is_ics(finding):
        return _classify_ot(proto, title)
    return _classify_iot(proto, title)


def tag_iot_ot_finding(finding: dict) -> dict[str, Any]:
    """Return a copy of ``finding`` with its framework tags merged in.

    ``vuln_type`` is only set when the finding doesn't already carry one; the
    framework fields are always added (they're new). Used by the IoT and OT
    scan entry points so every finding they emit is scored against the right
    standard downstream.
    """
    out = dict(finding)
    tags = classify_iot_ot(out)
    if not out.get("vuln_type"):
        out["vuln_type"] = tags.get("vuln_type", "")
    for key in ("device_class", "owasp_iot", "iec62443"):
        if tags.get(key):
            out[key] = tags[key]
    # Don't clobber a scanner-supplied technique.
    if tags.get("mitre_technique") and not out.get("mitre_technique"):
        out["mitre_technique"] = tags["mitre_technique"]
    return out


def has_iot_ot_tag(finding: dict) -> bool:
    """True when a finding already carries an IoT/OT framework tag — used by the
    web-OWASP layer to exclude it from the (2021) matrix."""
    return bool(finding.get("owasp_iot") or finding.get("iec62443"))


def iot_category_id(finding: dict) -> str:
    """The OWASP IoT Top 10 id for a finding (e.g. ``I2``), or '' if none."""
    m = re.match(r"\s*(I\d{1,2}):2018", str(finding.get("owasp_iot") or ""))
    return m.group(1) if m else ""


def ot_category_id(finding: dict) -> str:
    """The IEC 62443 foundational-requirement id for a finding (e.g. ``FR1``)."""
    m = re.match(r"\s*(FR\d)", str(finding.get("iec62443") or ""))
    return m.group(1) if m else ""


def framework_label(finding: dict) -> str:
    """The single best framework label to show on a finding detail view —
    the OT/ICS or IoT category when present, otherwise ''."""
    return str(finding.get("iec62443") or finding.get("owasp_iot") or "")
