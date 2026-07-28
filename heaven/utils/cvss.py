"""
HEAVEN — CVSS base-score calculator (v3.1 in-house + v4.0 via the reference lib).

A faithful implementation of the CVSS v3.1 specification's base-score formula
(https://www.first.org/cvss/v3.1/specification-document, section 7.1), plus
CVSS v4.0 base scoring delegated to the reference-grade ``cvss`` library (v4.0
has no closed-form formula — it is a published MacroVector lookup, so we use the
vetted implementation rather than re-deriving the table). Used to turn a CVSS
vector string (e.g. the ones OSV / GHSA advisories carry) into a numeric base
score and a severity label, so findings get a real, non-fabricated score
instead of a hand-picked severity constant.

This is a deterministic standard — not a model, not a heuristic. Two *different*
vulnerability classes get genuinely different scores; the same class scores the
same (a CVSS base score is a property of the weakness, not the individual URL).
"""
from __future__ import annotations

import contextlib
import math
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
