"""
HEAVEN — CVSS v3.1 base-score calculator.

A faithful implementation of the CVSS v3.1 specification's base-score formula
(https://www.first.org/cvss/v3.1/specification-document, section 7.1). Used to
turn a CVSS vector string (e.g. the ones OSV / GHSA advisories carry) into a
numeric base score and a severity label, so dependency findings get a real,
non-fabricated score instead of a hand-picked guess.

This is a deterministic standard formula — not a model, not a heuristic.
"""
from __future__ import annotations

import math

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


def base_score_from_vector(vector: str) -> float:
    """Return the CVSS v3.1 base score (0.0–10.0) for a vector string.

    Returns ``0.0`` when the vector is missing the base metrics needed to score
    (so callers can fall back to a severity label instead).
    """
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
