"""
HEAVEN — Finding confidence calibration (single application point).

The project already ships a calibrator (:class:`heaven.ml.ai_brain.ConfidenceCalibrator`)
with a source-weighted, piecewise-linear curve trained by ``heaven train-priors``.
Until now nothing in the finding write path actually *called* it, so every
persisted finding carried its raw detector/suppressor confidence and the
calibrated probability was never computed. This module is the one place that
turns that raw number into a calibrated probability and stamps it on a finding.

Design goals
------------
* **Additive, never destructive.** :func:`stamp_calibration` writes
  ``evidence.calibrated_confidence`` and an audit ``evidence.calibration`` block.
  It never overwrites the adjudicated ``confidence`` that FP suppression /
  active confirmation set — so the careful zero-false-positive adjudication that
  already exists is untouched, and calibration is a second, honest read on the
  same finding.
* **Honest mapping.** The calibration ``source`` is derived from what the
  detector actually recorded (a fired exploit canary, a reproducible error, a
  bare banner match, a fuzzing anomaly, …). We never claim a stronger source
  than the evidence supports, so a banner-only match never calibrates like a
  validated proof.
* **Corroboration counts real signals only.** Independent oracles listed in
  ``evidence.signals`` raise confidence; re-running the *same* oracle does not.

This module has no heavy dependencies and never raises: a calibration failure
must never block persisting a finding.
"""

from __future__ import annotations

from typing import Any

from heaven.utils.logger import get_logger

logger = get_logger("vulnscan.calibration")


# ── source mapping ──────────────────────────────────────────────────────────
# Map a finding to one of the calibrator's known ``source_weights`` keys
# (data/models/priors_bootstrap.json). Each rule is checked in order; the first
# match wins, so the strongest applicable evidence sets the source.
_SIGNAL_SOURCE = (
    # (substring seen in evidence.signals / reasons, calibration source key)
    ("oob_callback", "validated_poc"),
    ("cloud_metadata", "validated_poc"),
    ("canary", "validated_poc"),
    ("union", "error_based"),
    ("error_only_on_payload", "error_based"),
    ("error_based", "error_based"),
    ("time_based", "time_based_blind"),
    ("time-based", "time_based_blind"),
    ("boolean", "boolean_inference"),
    ("advisory_version_match", "banner_version"),
    ("version_match", "banner_version"),
    ("default_cred", "default_cred"),
    ("fuzz", "fuzzing_anomaly"),
    ("anomaly", "fuzzing_anomaly"),
)


def _ev(finding: dict[str, Any]) -> dict[str, Any]:
    ev = finding.get("evidence")
    return ev if isinstance(ev, dict) else {}


def calibration_source(finding: dict[str, Any]) -> str:
    """Best calibration ``source`` key for a finding, honestly derived.

    Preference order: a proven finding is ``validated_poc``; otherwise the
    strongest signal named in ``evidence.signals`` / ``fp_check_reasons``;
    otherwise a version/banner CVE match is ``banner_version``; otherwise the
    conservative ``heuristic`` default.
    """
    from heaven.utils.cvss import is_confirmed_finding

    ev = _ev(finding)
    if finding.get("validated") or finding.get("proved") \
            or ev.get("validation_result") == "confirmed":
        return "validated_poc"
    if is_confirmed_finding(finding):
        return "validated_poc"

    blob = " ".join(str(s).lower() for s in (ev.get("signals") or []))
    blob += " " + " ".join(str(r).lower() for r in (finding.get("fp_check_reasons") or []))
    for needle, source in _SIGNAL_SOURCE:
        if needle in blob:
            return source

    # A CVE that came from a version/banner match (no live probe) is banner_version.
    if (finding.get("cve") or finding.get("cve_id") or ev.get("cve")):
        return "banner_version"
    return "heuristic"


def corroboration_count(finding: dict[str, Any]) -> int:
    """Number of *distinct* independent oracles recorded for a finding.

    Mirrors :func:`heaven.vulnscan.fp_suppress._independent_signal_count`: only
    genuinely independent confirmations in ``evidence.signals`` count, and a
    re-run of the same oracle (``*_reproduced`` / ``*_reproducible``) is folded
    into its family rather than counted twice. The count passed to the
    calibrator is one *less* than the family total, because the first signal is
    the finding itself and only additional independent signals corroborate it.
    """
    ev = _ev(finding)
    families: set[str] = set()
    for s in (ev.get("signals") or []):
        fam = (str(s).lower()
               .replace("_confirmed", "").replace("_reproduced", "")
               .replace("_reproducible", ""))
        if fam:
            families.add(fam)
    return max(0, len(families) - 1)


def calibrated_confidence(finding: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    """Return ``(calibrated_probability, audit)`` for a finding.

    ``audit`` records the inputs (raw confidence, source, corroboration) so the
    number is fully explainable in the UI / report. Never raises — on any error
    it returns the raw confidence unchanged with an ``error`` note, so a
    calibration problem can never block or distort persistence.
    """
    try:
        raw = float(finding.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        raw = 0.0
    audit: dict[str, Any] = {"raw": round(raw, 4)}
    try:
        from heaven.ml.ai_brain import ConfidenceCalibrator
        source = calibration_source(finding)
        corr = corroboration_count(finding)
        prob = ConfidenceCalibrator.calibrate(
            raw, source=source, corroborating_sources=corr,
        )
        audit.update(source=source, corroboration=corr, model="priors.v1")
        return prob, audit
    except Exception as exc:  # noqa: BLE001 — calibration must never block persistence
        logger.debug("calibration failed, using raw confidence: %s", exc)
        audit["error"] = type(exc).__name__
        return round(raw, 4), audit


def stamp_calibration(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach ``evidence.calibrated_confidence`` + ``evidence.calibration`` in place.

    Additive: the finding's adjudicated ``confidence`` is left exactly as it was.
    Returns the same finding for chaining. Safe to call more than once
    (idempotent for a given finding state).
    """
    prob, audit = calibrated_confidence(finding)
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    ev["calibrated_confidence"] = prob
    ev["calibration"] = audit
    finding["evidence"] = ev
    return finding
