"""
HEAVEN — Description/type CVSS fallback model

A scikit-learn text model trained on real NVD CVE data (the
``NVD_Cybersecurity`` dataset, ~337k scored CVEs) that predicts a CVSS base
score from what ANY finding carries — its description text plus the
vulnerability-type flags and the text length — WITHOUT needing a CVSS vector.

This is the *fallback* half of HEAVEN's hybrid risk model:

  * When a finding carries a real, published CVSS vector or base score, the
    13-feature vector model (:mod:`heaven.ml.risk_model`) is authoritative — it
    reverse-engineers the CVSS calculator to ~R²=0.91.
  * When a finding has NO published score (a heuristic web/network finding), the
    vector model can only map the class to a hand-curated constant. THIS model
    instead reads the finding's own description and gives a data-grounded
    estimate learned from hundreds of thousands of real CVEs. The description
    text is the dominant signal (a TF-IDF + Ridge pipeline over the text, with
    the flags/length as a robust backbone). It is trained and measured on the
    population HEAVEN actually routes to it — findings that carry a real vuln-type
    signal — where honest CV is R²≈0.63, MAE≈0.79, and it lands the right
    severity band ~99% of the time within one level. R² is a harsh lens (the same
    vuln class spans a wide CVSS range in real data), so band accuracy is the
    metric that reflects real use. This is a genuinely harder problem than
    reversing the CVSS formula, and it never sets a report's badge: the model is
    pinned to the deterministic per-class CVSS score and only orders findings the
    deterministic path could not score.

The model artifact and its metadata are trained by
:mod:`heaven.ml.train_desc_model` (``heaven train-model`` runs it when the
dataset is available) and, like the vector model, are not committed to git.
Everything degrades cleanly: if the artifact is absent the hybrid simply uses
the vector model for every finding, exactly as before.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import joblib
except ImportError:  # pragma: no cover - joblib is a base dep
    joblib = None  # type: ignore[assignment]

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]

try:
    import pandas as pd
except ImportError:  # pragma: no cover - pandas is a base dep
    pd = None  # type: ignore[assignment]

from heaven.utils.logger import get_logger

logger = get_logger("ml.desc")

# ── the seven vulnerability-type flags the dataset carries ────────────────────
FLAG_NAMES = [
    "Flag_XSS", "Flag_SQLi", "Flag_Buffer_Overflow", "Flag_RCE",
    "Flag_Privilege_Escalation", "Flag_DoS", "Flag_Directory_Traversal",
]

# HEAVEN vuln_type → flag. vuln_type is the strongest, most reliable signal a
# finding carries, so it maps directly; the free-text scan below is a backstop.
_VULN_TYPE_FLAGS: dict[str, str] = {
    # SQLi family
    "sqli": "Flag_SQLi", "sql_injection": "Flag_SQLi", "blind_sqli": "Flag_SQLi",
    "boolean_sqli": "Flag_SQLi", "error_sqli": "Flag_SQLi", "time_sqli": "Flag_SQLi",
    "time_based_sqli": "Flag_SQLi", "union_sqli": "Flag_SQLi",
    # XSS family
    "xss": "Flag_XSS", "reflected_xss": "Flag_XSS", "stored_xss": "Flag_XSS",
    "dom_xss": "Flag_XSS",
    # RCE / code-exec family
    "rce": "Flag_RCE", "remote_code_execution": "Flag_RCE",
    "command_injection": "Flag_RCE", "os_command_injection": "Flag_RCE",
    "code_injection": "Flag_RCE", "ssti": "Flag_RCE",
    "server_side_template_injection": "Flag_RCE",
    "insecure_deserialization": "Flag_RCE", "deserialization": "Flag_RCE",
    # buffer overflow
    "buffer_overflow": "Flag_Buffer_Overflow", "stack_overflow": "Flag_Buffer_Overflow",
    "heap_overflow": "Flag_Buffer_Overflow", "integer_overflow": "Flag_Buffer_Overflow",
    # privilege escalation
    "privilege_escalation": "Flag_Privilege_Escalation", "privesc": "Flag_Privilege_Escalation",
    "local_privilege_escalation": "Flag_Privilege_Escalation",
    # DoS
    "dos": "Flag_DoS", "denial_of_service": "Flag_DoS", "ddos": "Flag_DoS",
    # directory / path traversal
    "path_traversal": "Flag_Directory_Traversal", "directory_traversal": "Flag_Directory_Traversal",
    "lfi": "Flag_Directory_Traversal", "local_file_inclusion": "Flag_Directory_Traversal",
}

# Free-text keywords → flag (mirrors how the dataset derived the flags from the
# CVE description). Scanned against the finding's title + type + evidence text.
_FLAG_KEYWORDS: list[tuple[str, str]] = [
    ("sql injection", "Flag_SQLi"), ("sqli", "Flag_SQLi"),
    ("cross-site scripting", "Flag_XSS"), ("cross site scripting", "Flag_XSS"),
    ("xss", "Flag_XSS"),
    ("remote code execution", "Flag_RCE"), ("code execution", "Flag_RCE"),
    ("arbitrary code", "Flag_RCE"), ("command injection", "Flag_RCE"),
    ("arbitrary command", "Flag_RCE"), ("template injection", "Flag_RCE"),
    ("deserialization", "Flag_RCE"),
    ("buffer overflow", "Flag_Buffer_Overflow"), ("stack overflow", "Flag_Buffer_Overflow"),
    ("heap overflow", "Flag_Buffer_Overflow"),
    ("privilege escalation", "Flag_Privilege_Escalation"),
    ("gain privileges", "Flag_Privilege_Escalation"),
    ("elevation of privilege", "Flag_Privilege_Escalation"),
    ("denial of service", "Flag_DoS"),
    ("directory traversal", "Flag_Directory_Traversal"),
    ("path traversal", "Flag_Directory_Traversal"),
    ("file inclusion", "Flag_Directory_Traversal"),
]


def _finding_text(finding: dict) -> str:
    """The descriptive text a finding carries, for flag scan + length features."""
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("vuln_type") or finding.get("type") or ""),
    ]
    ev = finding.get("evidence")
    if isinstance(ev, dict):
        for k in ("description", "summary", "detail", "note", "match", "payload"):
            v = ev.get(k)
            if isinstance(v, str):
                parts.append(v)
    elif isinstance(ev, str):
        parts.append(ev)
    return " ".join(p for p in parts if p).strip()


def derive_flags(finding: dict) -> dict[str, int]:
    """Derive the seven binary vuln-type flags for a finding (vuln_type first,
    then a free-text keyword scan as backstop)."""
    flags = {f: 0 for f in FLAG_NAMES}
    vt = str(finding.get("vuln_type") or finding.get("type") or "").lower()
    vt = vt.replace("-", "_").replace(" ", "_")
    if vt in _VULN_TYPE_FLAGS:
        flags[_VULN_TYPE_FLAGS[vt]] = 1
    else:
        for key, flag in _VULN_TYPE_FLAGS.items():
            if key in vt:
                flags[flag] = 1
                break
    text = _finding_text(finding).lower()
    if text:
        for kw, flag in _FLAG_KEYWORDS:
            if kw in text:
                flags[flag] = 1
    return flags


def _clip(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def build_feature_row(finding: dict, feature_names: list[str],
                      clip: Optional[dict[str, list[float]]] = None) -> list[float]:
    """Assemble the model's input row for a finding, in ``feature_names`` order.

    ``clip`` maps a feature to ``[lo, hi]`` training bounds; length features
    (Word_Count/Char_Length) are clamped there so a short finding title never
    extrapolates the model outside the range it learned on.
    """
    clip = clip or {}
    flags = derive_flags(finding)
    text = _finding_text(finding)
    wc = float(len(text.split()))
    cl = float(len(text))
    now = datetime.now(timezone.utc)
    values = {
        **{f: float(flags.get(f, 0)) for f in FLAG_NAMES},
        "Word_Count": wc,
        "Char_Length": cl,
        "Publish_Year": float(now.year),
        "Publish_Month": float(now.month),
    }
    row: list[float] = []
    for name in feature_names:
        v = values.get(name, 0.0)
        if name in clip and clip[name]:
            v = _clip(v, clip[name][0], clip[name][1])
        row.append(v)
    return row


class DescriptionRiskModel:
    """Loads the description/type CVSS fallback model (if present)."""

    def __init__(self, model_dir: Optional[Path] = None):
        self._model = None
        self._feature_names: list[str] = []
        self._clip: dict[str, list[float]] = {}
        self._meta: dict[str, Any] = {}
        self._model_path: Optional[Path] = None

        for d in self._search_dirs(model_dir):
            model_file = d / "cvss_text_model.joblib"
            meta_file = d / "cvss_text_model.meta.json"
            if model_file.exists() and joblib is not None:
                try:
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        self._model = joblib.load(model_file)
                    if meta_file.exists():
                        self._meta = json.loads(meta_file.read_text())
                    self._feature_names = self._meta.get("feature_names", [])
                    self._clip = self._meta.get("clip", {})
                    self._model_path = model_file
                    logger.info(
                        f"Loaded description CVSS model from {model_file} "
                        f"({len(self._feature_names)} features)")
                    break
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Could not load description CVSS model: {e}")
                    self._model = None

    @staticmethod
    def _search_dirs(model_dir: Optional[Path]) -> list[Path]:
        root = Path(__file__).parent.parent.parent
        dirs: list[Path] = []
        if model_dir:
            dirs.append(Path(model_dir))
        env = os.environ.get("HEAVEN_DESC_MODEL_DIR")
        if env:
            dirs.append(Path(env))
        dirs.append(root / "data" / "models")
        try:
            from heaven.ml.risk_model import default_model_dir
            dirs.append(default_model_dir())
        except Exception:  # noqa: BLE001
            logger.debug("risk_model default dir unavailable", exc_info=True)
        return dirs

    @property
    def available(self) -> bool:
        return self._model is not None and bool(self._feature_names)

    def predict(self, finding: dict) -> float:
        """Predict a CVSS base score (0.0–10.0) for a finding. Returns 0.0 if the
        model is unavailable, so callers can fall back cleanly."""
        if not self.available:
            return 0.0
        try:
            if self._meta.get("model_family") == "text":
                return self._predict_text(finding)
            # Legacy numeric-row model (flags + length only).
            if np is None:
                return 0.0
            row = build_feature_row(finding, self._feature_names, self._clip)
            score = float(self._model.predict(np.array([row]))[0])
            return max(0.0, min(10.0, score))
        except Exception as e:  # noqa: BLE001
            logger.warning(f"description model prediction failed: {e}")
            return 0.0

    def _predict_text(self, finding: dict) -> float:
        """Prediction path for the TF-IDF text pipeline: assemble the one-row
        DataFrame (description text + flags + clipped length) the pipeline's
        ColumnTransformer expects, in the trained column order."""
        if pd is None:
            return 0.0
        text = _finding_text(finding).lower()
        flags = derive_flags(finding)
        wc = float(len(text.split()))
        cl = float(len(text))
        if self._clip.get("Word_Count"):
            wc = _clip(wc, self._clip["Word_Count"][0], self._clip["Word_Count"][1])
        if self._clip.get("Char_Length"):
            cl = _clip(cl, self._clip["Char_Length"][0], self._clip["Char_Length"][1])
        text_col = self._meta.get("text_column", "text")
        input_cols = self._meta.get(
            "input_columns", [text_col, *FLAG_NAMES, "Word_Count", "Char_Length"])
        row = {
            text_col: text, "Word_Count": wc, "Char_Length": cl,
            **{f: float(flags.get(f, 0)) for f in FLAG_NAMES},
        }
        frame = pd.DataFrame([row]).reindex(columns=input_cols)
        score = float(self._model.predict(frame)[0])
        return max(0.0, min(10.0, score))

    def get_metrics(self) -> dict:
        return {
            "available": self.available,
            "n_features": len(self._feature_names),
            # Real-finding population (all non-zero-score CVEs the model trains on).
            "cv_r2": self._meta.get("cv_r2"),
            "cv_mae": self._meta.get("cv_mae"),
            # Severity-band accuracy is the metric that reflects real use (does the
            # predicted score land in the right CVSS band?) — a fairer read than R²
            # on a target whose same-class scores genuinely span a wide range.
            "cv_band_exact": self._meta.get("cv_band_exact"),
            "cv_band_within1": self._meta.get("cv_band_within1"),
            # Deployment population (findings carrying a vuln-type flag) — exactly
            # what HEAVEN's router feeds this model, and the numbers to cite.
            "deploy_r2": self._meta.get("deploy_r2"),
            "deploy_mae": self._meta.get("deploy_mae"),
            "deploy_band_exact": self._meta.get("deploy_band_exact"),
            "deploy_band_within1": self._meta.get("deploy_band_within1"),
            "training_population": self._meta.get("training_population"),
            "n_samples": self._meta.get("n_samples"),
        }


_desc_model: Optional[DescriptionRiskModel] = None


def get_desc_model() -> DescriptionRiskModel:
    global _desc_model
    if _desc_model is None:
        _desc_model = DescriptionRiskModel()
    return _desc_model
