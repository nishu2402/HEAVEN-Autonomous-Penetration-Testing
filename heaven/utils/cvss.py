"""
HEAVEN CVSS base-score calculator (dual version: v4.0 and v3.1).

CVSS v4.0 is the current standard (https://www.first.org/cvss/v4.0/), so HEAVEN
scores and surfaces it as the primary number, alongside CVSS v3.1 for continuity
and for the large body of published CVEs that still carry only a v3.1 vector.

Two scorers back this:

  * v3.1 is a faithful in-house implementation of the specification's base-score
    formula (https://www.first.org/cvss/v3.1/specification-document, section 7.1).
  * v4.0 has no closed-form formula (it is a published MacroVector lookup), so we
    delegate to the reference-grade ``cvss`` library rather than re-deriving the
    table. When the library is unavailable or a vector is malformed the v4.0
    scorer returns 0.0 and callers fall back to a severity label as before.

Both turn a CVSS vector string (for example the ones OSV / GHSA / NVD advisories
carry) into a numeric base score and a severity label, so findings get a real,
non-fabricated score instead of a hand-picked severity constant.

This is a deterministic standard, not a model or a heuristic. Two different
vulnerability classes get genuinely different scores; the same class scores the
same (a CVSS base score is a property of the weakness, not the individual URL).
The two versions score the same weakness differently by design (FIRST states
v4.0 is not meant to reproduce v3.1), so HEAVEN keeps both and never forces one
to match the other.
"""
from __future__ import annotations

import contextlib
import math
import os
from typing import Any, Optional

# ── Metric coefficients (CVSS v3.1 spec, section 7.4) ──

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is scope-dependent: (unchanged, changed).
_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(value: float) -> float:
    """CVSS spec Roundup: round *up* to one decimal, avoiding float drift."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Split a CVSS vector into its ``METRIC: value`` components (upper-cased)."""
    out: dict[str, str] = {}
    for part in (vector or "").strip().split("/"):
        if ":" in part:
            key, _, val = part.partition(":")
            out[key.strip().upper()] = val.strip().upper()
    return out


def cvss_version_of(vector: str) -> str:
    """Return the CVSS version a vector string declares: ``"4.0"``, ``"3.1"``,
    ``"3.0"``, ``"2.0"``, or ``""`` when it carries no ``CVSS:x.y`` prefix.

    Used to label a score honestly (a v4.0 vector is shown as v4.0, a v3.1 as
    v3.1) rather than assuming a single version everywhere.
    """
    v = (vector or "").strip().upper()
    if v.startswith("CVSS:4.0"):
        return "4.0"
    if v.startswith("CVSS:3.1"):
        return "3.1"
    if v.startswith("CVSS:3.0"):
        return "3.0"
    if v.startswith("CVSS:2.0") or (v and not v.startswith("CVSS:")):
        # A bare "AV:N/AC:L/..." string with no prefix is the legacy v2 / v3
        # shorthand; treat an explicit CVSS:2.0 as v2 and leave the rest blank.
        return "2.0" if v.startswith("CVSS:2.0") else ""
    return ""


def _v4_base_score(vector: str) -> float:
    """CVSS v4.0 base score via the reference ``cvss`` library.

    CVSS v4.0 is scored from a published MacroVector lookup table (there is no
    formula), so we defer to the vetted reference implementation rather than
    re-deriving the table. Returns ``0.0`` when the library is unavailable or the
    vector is unparseable, so callers fall back to a severity label as before.
    """
    try:
        from cvss import CVSS4  # type: ignore[import-untyped]
    except Exception:  # noqa: BLE001 - lib optional; degrade to label fallback
        return 0.0
    try:
        return float(CVSS4(vector).base_score)
    except Exception:  # noqa: BLE001 - malformed vector must never break a scan
        return 0.0


def base_score_from_vector(vector: str) -> float:
    """Return the CVSS base score (0.0–10.0) for a vector string.

    Routes CVSS:4.0 vectors to the v4.0 scorer and everything else through the
    in-house v3.x formula. Returns ``0.0`` when the vector is missing the base
    metrics needed to score (so callers can fall back to a severity label).
    """
    if (vector or "").strip().upper().startswith("CVSS:4"):
        return _v4_base_score(vector.strip())
    m = parse_vector(vector)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in m for k in required):
        return 0.0

    scope_changed = m["S"] == "C"
    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = _PR[m["PR"]][1 if scope_changed else 0]
        ui = _UI[m["UI"]]
        conf = _CIA[m["C"]]
        integ = _CIA[m["I"]]
        avail = _CIA[m["A"]]
    except KeyError:
        return 0.0

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> str:
    """Map a CVSS base score to the standard qualitative severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# Representative score for a qualitative label, when only a label is available
# (some OSV/GHSA records carry ``database_specific.severity`` but no vector).
_LABEL_SCORE = {
    "critical": 9.5, "high": 8.0, "moderate": 5.5, "medium": 5.5,
    "low": 3.1, "none": 0.0, "info": 0.0,
}


def score_from_label(label: str) -> float:
    """Best-effort numeric score for a qualitative severity label."""
    return _LABEL_SCORE.get((label or "").strip().lower(), 0.0)


def _finding_float(finding: dict, keys: tuple[str, ...]) -> Optional[float]:
    """First in-range (0,10] float found under ``keys`` on the finding/evidence."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    for src in (finding, ev):
        for k in keys:
            try:
                v = float(src.get(k))  # type: ignore[union-attr,arg-type]
            except (TypeError, ValueError, AttributeError):
                continue
            if 0.0 < v <= 10.0:
                return v
    return None


def objective_base_score(finding: dict[str, Any]) -> float:
    """Genuinely per-finding CVSS base score from *real* data — 0.0 if none.

    This is the one authoritative resolver shared by the report, the UI/store
    and the ML feature extractor so a finding's CVSS is the same everywhere and
    is never a flat per-severity constant. Precedence, most authoritative first:

      1. a real published base score carried on the finding (CVE / NVD / OSV);
      2. the KB "typical" base score curated for the finding's class;
      3. the base score computed from the class's curated CVSS vector;
      4. the base score computed from the finding's own CVSS vector.

    Because each vulnerability class carries its own curated vector, two
    different classes yield different scores (SQLi ≠ XSS ≠ missing-header),
    while the qualitative-label fallback (a flat constant) is deliberately *not*
    used here — callers that need a last-resort number can add it themselves.
    """
    # 1. a real, published base score (CVE / NVD / OSV ground truth).
    v = _finding_float(finding, ("cvss_base", "cvss_base_score", "cvss_score", "cvss"))
    if v is not None:
        return v

    vt = str(finding.get("vuln_type") or finding.get("type") or "")

    # 2. the KB "typical" base score curated for this class (per-class, varied).
    v = _finding_float(finding, ("typical_cvss",))
    if v is None:
        try:
            from heaven.devsecops.vuln_kb import lookup as _lookup
            tv = (_lookup(vt) or {}).get("typical_cvss")
            v = float(tv) if tv else None
            if v is not None and not (0.0 < v <= 10.0):
                v = None
        except Exception:  # noqa: BLE001 - KB optional; fall through to vectors
            v = None
    if v is not None:
        return v

    # 3. compute from the class's curated vector (never a generic severity one).
    with contextlib.suppress(Exception):  # KB optional
        from heaven.devsecops.vuln_kb import cvss_vector_for as _vec_for
        s = base_score_from_vector(_vec_for(vt))
        if s > 0:
            return s

    # 4. compute from the finding's own vector (may itself be a severity fallback).
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    vec = str(finding.get("cvss_vector") or ev.get("cvss_vector") or "")
    s = base_score_from_vector(vec)
    return s if s > 0 else 0.0


# ──────────────────────────────────────────────────────────────────────────
# Contextual (Temporal + Environmental) scoring — genuinely per-finding.
#
# The *base* score above is a property of the weakness class (CVSS's own
# definition), so two findings of the same class share it. CVSS also defines
# Temporal and Environmental metric groups whose whole purpose is to adjust the
# base for a *specific* finding on a *specific* asset — this is the number
# Tenable/Qualys/Rapid7 surface as their per-asset score. HEAVEN already
# collects the exact real signals those metrics require:
#
#   • Exploit Code Maturity (E)  ← EPSS probability / public-exploit / CISA KEV
#   • Report Confidence   (RC)   ← the detector's own confidence in the finding
#   • Security Requirements (CR/IR/AR) ← the asset's criticality tag
#   • Modified Attack Vector (MAV)     ← whether the target is internet-facing
#
# so the contextual score is standards-based and non-fabricated: it varies
# because the *evidence* varies, not because of any random jitter. When a
# finding carries no such signals it degrades exactly to its base score.
# ──────────────────────────────────────────────────────────────────────────

# CVSS v3.1 Security-Requirement weights (spec §7.4): Low 0.5 / Medium 1.0 /
# High 1.5. HEAVEN's asset-criticality tags map onto them (crown_jewel == High,
# the spec's ceiling).
_SR_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "crown_jewel": 1.5}


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _num(src: Any, key: str) -> Optional[float]:
    try:
        return float(src.get(key))  # type: ignore[union-attr]
    except (TypeError, ValueError, AttributeError):
        return None


def _finding_and_evidence_num(finding: dict, keys: tuple[str, ...]) -> Optional[float]:
    """First numeric value found under ``keys`` on the finding or its evidence."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    for src in (finding, ev):
        for k in keys:
            v = _num(src, k)
            if v is not None:
                return v
    return None


def _finding_flag(finding: dict, keys: tuple[str, ...]) -> bool:
    """True when any truthy value exists under ``keys`` on finding/evidence."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    for src in (finding, ev):
        for k in keys:
            v = src.get(k) if isinstance(src, dict) else None
            if isinstance(v, str):
                if v.strip().lower() in {"true", "1", "yes", "y", "available"}:
                    return True
            elif v:
                return True
    return False


def _report_confidence_coeff(finding: dict) -> float:
    """CVSS Report-Confidence coefficient from the detector's confidence.

    Interpolated continuously inside the spec band [Unknown 0.92 … Confirmed
    1.00]. A finding with no (or zero) recorded confidence is treated as
    "Not Defined" (1.0) so it is never penalised for missing data.
    """
    c = _finding_and_evidence_num(finding, ("confidence",))
    if c is None or c <= 0.0:
        return 1.0
    return round(0.92 + 0.08 * _clamp(c, 0.0, 1.0), 4)


def _exploit_maturity_coeff(finding: dict) -> float:
    """CVSS Exploit-Code-Maturity coefficient from real threat intel.

    CISA-KEV (actively exploited) → 1.0 (High); a public exploit → ≥0.97
    (Functional); otherwise interpolated from the EPSS probability inside the
    spec band [Unproven 0.91 … High 1.0]. With no exploit intel at all the
    metric is "Not Defined" (1.0).
    """
    if _finding_flag(finding, ("in_kev", "kev", "cisa_kev")):
        return 1.0
    epss = _finding_and_evidence_num(finding, ("epss", "epss_score"))
    has_exploit = _finding_flag(finding, ("exploit_available", "exploit_db", "metasploit"))
    if epss is None and not has_exploit:
        return 1.0
    coeff = 0.91
    if epss is not None:
        coeff = max(coeff, 0.91 + 0.09 * _clamp(epss, 0.0, 1.0))
    if has_exploit:
        coeff = max(coeff, 0.97)
    return round(min(coeff, 1.0), 4)


def _finding_criticality(finding: dict) -> str:
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    for src in (finding, ev):
        if isinstance(src, dict):
            c = src.get("criticality") or src.get("asset_criticality")
            if c:
                return str(c)
    return "medium"


def _anchor_vector(finding: dict) -> Optional[str]:
    """The CVSS base vector to anchor the environmental recompute on.

    Prefer the finding's own (published) vector; otherwise the curated class
    vector from the KB. Returns ``None`` when neither scores.
    """
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    own = str(finding.get("cvss_vector") or ev.get("cvss_vector") or "")
    if own and base_score_from_vector(own) > 0:
        return own
    vt = str(finding.get("vuln_type") or finding.get("type") or "")
    with contextlib.suppress(Exception):  # KB optional
        from heaven.devsecops.vuln_kb import cvss_vector_for as _vec_for
        v = _vec_for(vt)
        if v and base_score_from_vector(v) > 0:
            return v
    return None


def _mav_override(exposure: Optional[str]) -> Optional[str]:
    """Modified Attack Vector from network exposure.

    An internal / private-network-only target is not reachable from the
    internet, so a Network-vector weakness is genuinely harder to reach →
    downgrade Modified Attack Vector to Adjacent. Internet-facing keeps Network.
    """
    if (exposure or "").strip().lower() in ("internal", "private", "lan", "rfc1918"):
        return "A"
    return None


def _environmental_modified_base(
    vector: str, sr: float, mav_override: Optional[str] = None,
) -> Optional[float]:
    """CVSS v3.1 Environmental *modified base* (before temporal), spec §7.3.

    Uses the base metrics as the modified metrics (except an optional MAV
    override) and applies the Security-Requirement weight ``sr`` to C/I/A.
    Returns ``None`` when the vector lacks the required base metrics.
    """
    m = parse_vector(vector)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in m for k in required):
        return None
    scope_changed = m["S"] == "C"
    try:
        mav = _AV[mav_override or m["AV"]]
        mac = _AC[m["AC"]]
        mpr = _PR[m["PR"]][1 if scope_changed else 0]
        mui = _UI[m["UI"]]
        mc, mi, ma = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    isc_mod = min(1 - (1 - mc * sr) * (1 - mi * sr) * (1 - ma * sr), 0.915)
    if isc_mod <= 0:
        return 0.0
    if scope_changed:
        m_impact = 7.52 * (isc_mod - 0.029) - 3.25 * (isc_mod * 0.9731 - 0.02) ** 13
    else:
        m_impact = 6.42 * isc_mod
    if m_impact <= 0:
        return 0.0

    m_exploit = 8.22 * mav * mac * mpr * mui
    raw = m_impact + m_exploit
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def _own_vector(finding: dict[str, Any]) -> str:
    """The finding's own (published) CVSS vector, from the finding or evidence."""
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(finding.get("cvss_vector") or ev.get("cvss_vector") or "")


def _v4_contextual(
    vector: str,
    finding: dict[str, Any],
    criticality: Optional[str],
    exposure: Optional[str],
) -> float:
    """CVSS v4.0 contextual score via the reference library's Threat +
    Environmental metrics, driven by the same real per-finding signals HEAVEN
    already collects. Returns 0.0 when the library is unavailable or the vector
    will not score, so the caller degrades to the base score.

    v4.0 dropped Report Confidence, so the detector's confidence has no v4.0
    metric to map onto; the adjustment uses Exploit Maturity (E), the asset's
    Security Requirements (CR/IR/AR), and network exposure (Modified Attack
    Vector) only.
    """
    try:
        from cvss import CVSS4  # type: ignore[import-untyped]
    except Exception:  # noqa: BLE001 - lib optional; degrade to base
        return 0.0
    parts = [vector.strip().rstrip("/")]

    # Exploit Maturity: KEV / public exploit -> Attacked; EPSS present -> POC.
    if _finding_flag(finding, ("in_kev", "kev", "cisa_kev")) or _finding_flag(
        finding, ("exploit_available", "exploit_db", "metasploit")
    ):
        parts.append("E:A")
    elif _finding_and_evidence_num(finding, ("epss", "epss_score")) is not None:
        parts.append("E:P")

    # Security Requirements from the asset's criticality tag.
    crit = (criticality or _finding_criticality(finding) or "medium").strip().lower()
    sr = {"crown_jewel": "H", "high": "H", "medium": "M", "low": "L"}.get(crit)
    if sr and sr != "M":  # M is the spec default; only add when it changes scoring
        parts.append(f"CR:{sr}/IR:{sr}/AR:{sr}")

    # Modified Attack Vector: an internal-only target is not internet-reachable.
    if _mav_override(exposure) == "A":
        parts.append("MAV:A")

    try:
        return float(CVSS4("/".join(parts)).base_score)
    except Exception:  # noqa: BLE001 - malformed must never break a scan
        return 0.0


def contextual_score(
    finding: dict[str, Any],
    *,
    criticality: Optional[str] = None,
    exposure: Optional[str] = None,
) -> float:
    """Genuinely per-finding CVSS **contextual** score (0.0–10.0), 1 d.p.

    Starts from the finding's real base score (:func:`objective_base_score`) and
    adjusts it with the CVSS Temporal + Environmental metric groups, driven by
    real per-finding signals: Exploit Code Maturity (EPSS / public-exploit /
    KEV), Report Confidence (the detector's confidence), and the asset's
    Security Requirements (criticality) + Modified Attack Vector (exposure).

    Because those signals vary from finding to finding, the returned number is
    genuinely dynamic — two findings of the *same class* differ when their
    evidence differs. When a finding carries none of these signals the score
    degrades exactly to its base score (never a fabricated jitter). Returns
    ``0.0`` only when the base itself is unscoreable.
    """
    base = objective_base_score(finding)
    if base <= 0:
        return 0.0

    # A finding whose own authoritative vector is v4.0 (a CVE with a published
    # v4.0 score) is adjusted with v4.0's own Threat + Environmental metrics via
    # the reference library, so its contextual number stays on the same standard
    # as its base. Everything else uses the in-house v3.1 environmental recompute.
    own = _own_vector(finding)
    if cvss_version_of(own) == "4.0":
        s = _v4_contextual(own, finding, criticality, exposure)
        return min(round(s, 1), 10.0) if s > 0 else base

    e = _exploit_maturity_coeff(finding)
    rc = _report_confidence_coeff(finding)
    rl = 1.0  # Remediation Level: "Not Defined" — no reliable per-finding signal.

    # Environmental adjustment, expressed as a ratio derived from a faithful
    # CVSS v3.1 environmental recompute on the finding's anchor vector, so the
    # number stays pinned to the finding's real base score.
    crit = criticality or _finding_criticality(finding)
    sr = _SR_WEIGHT.get((crit or "medium").strip().lower(), 1.0)
    mav = _mav_override(exposure)
    ratio = 1.0
    if sr != 1.0 or mav is not None:
        vec = _anchor_vector(finding)
        if vec:
            plain = base_score_from_vector(vec)
            env = _environmental_modified_base(vec, sr, mav)
            if plain and plain > 0 and env is not None and env > 0:
                ratio = env / plain

    modified_base = min(10.0, base * ratio)
    score = _roundup(modified_base * e * rl * rc)
    return min(round(score, 1), 10.0)


# ──────────────────────────────────────────────────────────────────────────
# Severity ⇄ score reconciliation.
#
# A finding carries two views of its risk that a reader sees side by side: the
# qualitative *severity* the detector assigned, and the numeric *CVSS base
# score* resolved for its class. When these disagree — e.g. a "Low" badge next
# to a CVSS of 8.1 — the report looks broken. This reconciler keeps the two in
# the same qualitative band, honestly and in one place, so no surface can drift.
# ──────────────────────────────────────────────────────────────────────────

# Ordered most-severe-last so a numeric comparison expresses "more severe".
_SEV_RANK = {"info": 0, "none": 0, "low": 1, "medium": 2, "moderate": 2,
             "high": 3, "critical": 4}

# The representative in-band score used when an *unconfirmed* detection's class
# base over-states it: the top of the qualitative band, so the number is pulled
# down to match the badge without under-claiming inside that band.
_BAND_CEILING = {"critical": 9.9, "high": 8.9, "medium": 6.9, "low": 3.9,
                 "info": 0.0, "none": 0.0}

# Words a detector uses when it is flagging a *weak, unconfirmed* signal rather
# than a proven vulnerability. Such a finding must NOT inherit the confirmed
# weakness class's high base score (an "indicator" is not the real thing).
_UNCONFIRMED_MARKERS = (
    "indicator", "possible", "potential", "suspected", "unconfirmed",
    "heuristic", "likely", "presumed", "maybe",
)


def is_unconfirmed_finding(finding: dict[str, Any]) -> bool:
    """True when the detector itself signals this is a weak / unconfirmed
    detection — a heuristic 'indicator / possible / potential' finding, or an
    explicit low confidence with no authoritative CVE backing it. These must not
    be scored as if the confirmed weakness class were proven present."""
    hay = " ".join(str(finding.get(k) or "") for k in ("vuln_type", "type", "title")).lower()
    if any(m in hay for m in _UNCONFIRMED_MARKERS):
        return True
    conf = _finding_and_evidence_num(finding, ("confidence",))
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    has_cve = bool(finding.get("cve") or finding.get("cve_id") or ev.get("cve"))
    return conf is not None and 0.0 < conf < 0.5 and not has_cve


def _has_published_score(finding: dict[str, Any]) -> bool:
    """Whether the finding carries a real, published base score (CVE / NVD /
    OSV) — the authoritative number that should drive the severity band."""
    return _finding_float(
        finding, ("cvss_base", "cvss_base_score", "cvss_score", "cvss")
    ) is not None


def cvss_badge_version() -> str:
    """Which CVSS version drives the severity badge.

    Default ``"3.1"`` — HEAVEN's calibrated band. FIRST's v4.0 rescoring runs hot
    at the low end for some low-impact classes (a bare verbose-error page can band
    Medium under v4.0 where v3.1 bands Low), so the badge stays on the calibrated
    v3.1 score by default and v4.0 is shown alongside as a labelled companion.

    Set ``HEAVEN_CVSS_BADGE_VERSION=4.0`` to badge on the raw CVSS v4.0 score
    instead. This is a deliberate, single-switch operator choice — the whole
    product then bands on v4.0, and those low-impact classes will read hotter by
    the standard's design. Any value other than 4 / 4.0 is treated as 3.1.
    """
    return "4.0" if (os.environ.get("HEAVEN_CVSS_BADGE_VERSION") or "").strip() in ("4", "4.0") else "3.1"


def badge_base_score(finding: dict[str, Any]) -> float:
    """The base score that drives the severity badge, honouring the badge-version
    toggle. Default: the calibrated objective (v3.1-anchored) base. When the
    operator has opted into v4.0 badging AND the finding carries a real v4.0 base,
    that raw v4.0 score drives the band instead. Falls back to the objective base
    whenever no v4.0 score is available, so a mixed corpus never loses its badge.
    """
    if cvss_badge_version() == "4.0":
        v4 = _finding_float(finding, ("cvss4_base", "cvss4_base_score"))
        if v4 is not None and v4 > 0:
            return v4
    return objective_base_score(finding)


def reconcile_severity(finding: dict[str, Any]) -> dict[str, Any]:
    """Keep a finding's qualitative ``severity`` and its resolved CVSS base score
    in the *same* band, so a report never shows "CVSS 8.1 / Low". Mutates and
    returns the finding. Two honest directions, never a fabricated number:

      • a **published** base score (CVE / NVD / OSV) is authoritative → the
        severity label is aligned to it (a real Critical is never buried behind a
        hand-set Low, and a label is never inflated above the published score);

      • an **unconfirmed / low-confidence** detection whose class base
        over-states it → the *effective* base is capped down to the detector's
        (lower) severity band, because an "indicator" does not warrant the
        confirmed class's score. The badge stays as the detector intended and the
        CVSS / Contextual columns now agree with it.

    A confirmed finding whose class base is *more* severe than a hand-set label
    has its label raised to match (the class genuinely warrants it); a
    confirmed finding is never silently *downgraded* off a KB estimate alone.

    The band-driving score is resolved through :func:`badge_base_score`, so the
    default calibrated v3.1 badge and the opt-in v4.0 badge share this one path.
    """
    base = badge_base_score(finding)
    if base <= 0:
        return finding
    label = str(finding.get("severity") or "").strip().lower()
    score_band = severity_from_score(base)

    # Unconfirmed / weak signal: cap the class base to the label's band so the
    # numbers match the deliberately-low badge (anti-over-claim).
    if is_unconfirmed_finding(finding):
        ceiling = _BAND_CEILING.get(label)
        if ceiling is not None and base > ceiling:
            finding["cvss_base"] = ceiling
            ev = finding.get("evidence")
            if isinstance(ev, dict):
                ev["cvss_base"] = ceiling
            finding["typical_cvss"] = ceiling
        return finding

    # Published, authoritative score (incl. a real per-CVE score backfilled from
    # the bundled DB) → the label follows the standard number, up or down.
    if _has_published_score(finding):
        if label != score_band:
            # A finding proven present by active exploitation is ground truth: a
            # published base score may only RAISE its label, never demote it. A
            # real exploit-to-root outranks a stale/pre-v3 CVSS — e.g. the Samba
            # usermap RCE (CVE-2007-2447) whose only published score is the CVSS
            # v2 6.0 (Medium) must not file a captured root shell as Medium.
            demote = _SEV_RANK.get(score_band, 0) < _SEV_RANK.get(label, 0)
            if not (demote and _is_actively_validated(finding)):
                finding["severity"] = score_band
        return finding

    # KB-estimate base on a confirmed finding. A finding still carrying a CVE id
    # but no resolvable published score might be a real Critical we can't score
    # offline — so only *raise* it, never demote off an estimate. A finding with
    # NO CVE is a class / posture finding whose curated class base *is* its
    # authoritative severity, so align it in both directions.
    if label not in _SEV_RANK:
        return finding
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    has_cve = bool(finding.get("cve") or finding.get("cve_id") or ev.get("cve"))
    if has_cve:
        if _SEV_RANK[score_band] > _SEV_RANK[label]:
            finding["severity"] = score_band
    elif label != score_band:
        finding["severity"] = score_band
    return finding


# ── Confirmation status: Confirmed vs Potential ─────────────────────────────
#
# A professional penetration test separates what was *proven present* from what
# is only *inferred*. HEAVEN carries this as a computed status (never a stored
# column — resolved on read everywhere, one rule):
#
#   • Confirmed — established by direct observation or active validation: a
#     missing security header actually seen in a live response, an open cleartext
#     port, a payload that executed, an anonymous login that succeeded, a
#     validator that returned "confirmed", or an authoritative version read from
#     a dependency manifest (SCA).
#   • Potential — inferred, not validated: a CVE mapped from a network service
#     *version banner* (the backport problem — vendors patch without bumping the
#     banner, so an unauthenticated banner match cannot confirm the flaw is
#     present), or any heuristic "indicator / possible / potential" signal.
#
# Potential findings document real attack surface and stay fully in the report —
# they are never suppressed — but they must NOT inflate the confirmed-risk
# headline (Overall Risk / the Critical count). Severity is orthogonal: a finding
# can be "Critical (Potential)" — critical *if* present, not yet proven present.

# vuln_types that are inferred from a network *version banner* (or a zero-day
# heuristic) rather than actively exploited — Potential until validated. SCA /
# dependency matches (``vulnerable_dependency``, source ``osv``) are deliberately
# excluded: their version is read authoritatively from a manifest, so the
# vulnerable component genuinely *is* present (Confirmed-present).
_BANNER_INFERRED_TYPES = frozenset({
    "vulnerable_service", "potential_vulnerable_service",
    "known_vulnerable_version", "outdated_service", "zero_day_heuristic",
})

# Finding ``source`` prefixes that denote a network/banner-inferred CVE match
# (never active proof). ``osv`` (SCA) is intentionally absent.
_BANNER_INFERRED_SOURCES = ("inline_db", "nvd", "live", "circl", "cve_feed",
                            "heuristic")


def _is_actively_validated(finding: dict[str, Any]) -> bool:
    """True when a finding was *proven* — a probe executed, a payload fired, an
    access actually succeeded — rather than merely matched against a banner.

    ``version_confirmed`` does **not** count: it only means a version string fell
    within a CVE's affected range, which is precisely the unauthenticated
    inference this module treats as Potential.

    The active-exploitation engine sets ``confirmed: True`` and stores the live
    command output it captured in ``evidence.proof_output`` — it is the only
    producer of either, and a banner match never carries them, so recognising
    them here is honest ground truth, not a loosening. ``proof_output`` also
    survives the DB round-trip (the top-level ``confirmed`` flag does not), so a
    persisted RCE still reads as Confirmed on the findings list and report.
    """
    if _finding_flag(finding, ("validated", "exploited", "verified", "proven",
                               "confirmed")):
        return True
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    if ev.get("proof_output"):
        return True
    result = str(
        finding.get("validation") or ev.get("validation")
        or ev.get("validation_result") or ev.get("result") or ""
    ).strip().lower()
    return result in {"confirmed", "exploited", "verified", "proven"}


def is_confirmed_finding(finding: dict[str, Any]) -> bool:
    """Whether a finding was established by direct observation / active
    validation (**Confirmed**) rather than inferred from a network version banner
    or a heuristic indicator (**Potential**). See the module note above."""
    # Active validation always wins — even over an "indicator"-worded title.
    if _is_actively_validated(finding):
        return True
    # Heuristic / indicator / possible / low-confidence-no-CVE → not confirmed.
    if is_unconfirmed_finding(finding):
        return False
    vt = str(finding.get("vuln_type") or finding.get("type") or "").strip().lower()
    if vt in _BANNER_INFERRED_TYPES:
        return False
    # A CVE from a network-banner source with no active validation is inferred.
    ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    source = str(finding.get("source") or ev.get("source") or "").strip().lower()
    has_cve = bool(finding.get("cve") or finding.get("cve_id") or ev.get("cve"))
    if has_cve and any(source.startswith(s) for s in _BANNER_INFERRED_SOURCES):
        return False
    # Everything else is a directly-observed posture / config / exposure finding
    # (missing headers, weak TLS, cleartext protocol, anonymous access, SCA …).
    return True


def confirmation_status(finding: dict[str, Any]) -> str:
    """Canonical label — ``"Confirmed"`` or ``"Potential"`` — for a finding."""
    return "Confirmed" if is_confirmed_finding(finding) else "Potential"
