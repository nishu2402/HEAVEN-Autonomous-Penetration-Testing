"""
HEAVEN — NVD CVSS Risk Model

Loads the trained NVD ExtraTreesRegressor (13-feature CVSS-v3 predictor,
R²≈0.99; see data/models/NVD_model.MODEL_CARD.md) and predicts a CVSS base
score (0–10) for a finding. This is the model wired into the scan pipeline's
ML-scoring phase via ``score_vulnerabilities()``.

Cross-platform: Linux, macOS, Windows.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Any, Optional

try:
    import joblib
except ImportError:
    joblib = None  # type: ignore[assignment]

from heaven.ml.feature_engine import extract_features
from heaven.utils.logger import get_logger

logger = get_logger("ml.risk")
warnings.filterwarnings("ignore", category=UserWarning)

# The 48 MB NVD model is intentionally NOT shipped in the wheel or committed to
# git (it's gitignored), so `pip install` and `git clone` users don't have it
# until they fetch it with `heaven download-model`. The download lands in the
# user cache dir below, so the search path has to include it — otherwise the
# loader would only ever find a model in a source checkout.


def default_model_dir() -> Path:
    """User-writable cache dir where `heaven download-model` stores the model.

    Honours ``XDG_CACHE_HOME`` (Linux/macOS convention); falls back to
    ``~/.cache``. Always writable, so it works for pip installs where the
    package lives in read-only site-packages.
    """
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "heaven" / "models"


def model_search_paths() -> list[Path]:
    """Ordered candidate locations for NVD_model.pkl (first existing one wins).

    1. ``HEAVEN_MODEL_PATH`` — explicit operator override (file path).
    2. ``<repo>/data/models/NVD_model.pkl`` — canonical home in a source checkout.
    3. ``<repo>/NVD_model.pkl`` — legacy repo-root / Docker-image location.
    4. ``<cache>/heaven/models/NVD_model.pkl`` — where `download-model` writes,
       so pip-installed users get the real model.
    """
    root = Path(__file__).parent.parent.parent
    paths: list[Path] = []
    env = os.environ.get("HEAVEN_MODEL_PATH")
    if env:
        paths.append(Path(env))
    paths.append(root / "data" / "models" / "NVD_model.pkl")
    paths.append(root / "NVD_model.pkl")
    paths.append(default_model_dir() / "NVD_model.pkl")
    return paths


class HeavenRiskModel:
    """Loads the NVD CVSS ExtraTrees regressor and predicts a CVSS base score."""

    # NVD model feature names (13 features — matches NVD_model.pkl)
    NVD_FEATURE_NAMES = [
        "attack_vector",       # PHYSICAL=1, LOCAL=2, ADJACENT=3, NETWORK=4
        "attack_complexity",   # HIGH=1, LOW=2
        "privileges_required", # HIGH=1, LOW=2, NONE=3
        "user_interaction",    # REQUIRED=1, NONE=2
        "scope",               # UNCHANGED=1, CHANGED=2
        "conf_impact",         # NONE=1, LOW=2, HIGH=3
        "integ_impact",        # NONE=1, LOW=2, HIGH=3
        "avail_impact",        # NONE=1, LOW=2, HIGH=3
        "vuln_age_days",       # 0–3650 (raw days)
        "ref_count",           # number of CVE references
        "cpe_count",           # number of affected CPEs
        "epss_score_pct",      # EPSS probability × 100
        "in_kev",              # 0/1 — CISA KEV catalog
    ]

    def __init__(self, model_path: Optional[Path] = None):
        # model_path.parent is used only to locate an optional fallback regressor
        # (data/models/cvss_regressor.joblib from `heaven train-model`); the file
        # itself is never loaded directly.
        self.model_path = model_path or Path("models/risk_model_v2.joblib")
        self.version = "1.0.0"
        self._is_trained = False
        self._regressor = None
        self._feature_names: list[str] = []
        self._regression_mode = False

        import json as _json

        # Priority 1: the trained NVD CVSS model (13-feature ExtraTreesRegressor).
        # Its canonical home is data/models/ (next to NVD_model.MODEL_CARD.md);
        # the repo root is kept as a fallback so existing checkouts and the
        # Docker image — which ship the file at the root — keep working.
        _root = Path(__file__).parent.parent.parent
        nvd_feat_file = _root / "nvd_data" / "feature_names_nvd.json"
        nvd_model_file = next(
            (p for p in model_search_paths() if p.exists()),
            None,
        )
        if nvd_model_file is not None and joblib is not None:
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self._regressor = joblib.load(nvd_model_file)
                self._feature_names = (
                    _json.loads(nvd_feat_file.read_text())
                    if nvd_feat_file.exists()
                    else self.NVD_FEATURE_NAMES
                )
                self._regression_mode = True
                self._is_trained = True
                logger.info(f"Loaded NVD CVSS model from {nvd_model_file} "
                            f"({len(self._feature_names)} features)")
                return
            except Exception as e:
                logger.warning(f"Could not load NVD_model.pkl: {e}")

        # Priority 2: trained cvss_regressor.joblib (generated by train_model command)
        model_file = self.model_path.parent / "cvss_regressor.joblib"
        feat_file = self.model_path.parent / "feature_names.json"
        if model_file.exists() and joblib is not None:
            try:
                self._regressor = joblib.load(model_file)
                self._feature_names = _json.loads(feat_file.read_text()) if feat_file.exists() else []
                self._regression_mode = True
                self._is_trained = True
                logger.info(f"Loaded CVSS regressor from {model_file}")
            except Exception as e:
                logger.warning(f"Could not load regressor: {e}")
                self._regression_mode = False
        else:
            logger.warning(
                "No NVD CVSS model found — CVSS scores fall back to each finding's "
                "own base score. Fetch the trained model with `heaven download-model` "
                "(or train one with `heaven train-model`)."
            )
            self._regression_mode = False

    def predict_cvss_score(self, vuln_features: dict) -> float:
        """Predict CVSS base score from vulnerability features (0.0–10.0)."""
        if self._regression_mode and self._regressor is not None:
            try:
                import numpy as np
                feature_names = self._feature_names or self.NVD_FEATURE_NAMES
                n_expected = getattr(self._regressor, "n_features_in_", len(feature_names))
                if len(feature_names) == n_expected:
                    vec = np.array([[vuln_features.get(f, 0.0) for f in feature_names]])
                else:
                    # Feature count mismatch — pad/trim
                    raw = [vuln_features.get(f, 0.0) for f in feature_names[:n_expected]]
                    raw += [0.0] * max(0, n_expected - len(raw))
                    vec = np.array([raw[:n_expected]])
                score = float(self._regressor.predict(vec)[0])
                return max(0.0, min(10.0, score))
            except Exception as e:
                # Don't silently mask model failures — operators need to know
                # a finding's CVSS came from the fallback, not the model.
                logger.warning(f"CVSS regressor prediction failed, using fallback: {e}")
        return float(vuln_features.get("cvss_base_score", 5.0))

    def get_metrics(self) -> dict:
        """Return the loaded CVSS regressor's status (surfaced in scan output)."""
        return {
            "version": self.version,
            "regression_mode": self._regression_mode,
            "is_trained": self._is_trained,
            "n_features": len(self._feature_names),
        }


# Module-level singleton
_model: Optional[HeavenRiskModel] = None


def get_model() -> HeavenRiskModel:
    global _model
    if _model is None:
        _model = HeavenRiskModel()
    return _model


def _extract_nvd_features(finding: dict) -> dict:
    """
    Extract the 13-feature vector used by NVD_model.pkl from a finding dict.

    Accepts both short CVSS v3 vector codes (AV:N, AC:L …) and full English
    names (NETWORK, LOW …) stored as individual keys.
    """
    # Short-code → numeric mappings (as used in CVSS v3 vector strings)
    AV_SHORT  = {"N": 4, "A": 3, "L": 2, "P": 1}   # NETWORK, ADJACENT, LOCAL, PHYSICAL
    AC_SHORT  = {"L": 2, "H": 1}                     # LOW, HIGH
    PR_SHORT  = {"N": 3, "L": 2, "H": 1}             # NONE, LOW, HIGH
    UI_SHORT  = {"N": 2, "R": 1}                     # NONE, REQUIRED
    SC_SHORT  = {"C": 2, "U": 1}                     # CHANGED, UNCHANGED
    IMP_SHORT = {"H": 3, "L": 2, "N": 1}             # HIGH, LOW, NONE

    # Full-name → numeric mappings (for raw NVD API dict fields)
    AV_LONG  = {"NETWORK": 4, "ADJACENT_NETWORK": 3, "ADJACENT": 3, "LOCAL": 2, "PHYSICAL": 1}
    AC_LONG  = {"LOW": 2, "HIGH": 1}
    PR_LONG  = {"NONE": 3, "LOW": 2, "HIGH": 1}
    UI_LONG  = {"NONE": 2, "REQUIRED": 1}
    SC_LONG  = {"CHANGED": 2, "UNCHANGED": 1}
    IMP_LONG = {"HIGH": 3, "LOW": 2, "NONE": 1}

    # Defaults: NETWORK / LOW / NONE / NONE / UNCHANGED / NONE-NONE-NONE
    av_num, ac_num, pr_num, ui_num, sc_num = 4, 2, 3, 2, 1
    ci_num, ii_num, ai_num = 1, 1, 1

    cvss_vector = finding.get("cvss_vector", "")
    if cvss_vector:
        # Parse compact CVSS v3 vector string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        for segment in cvss_vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/"):
            if ":" not in segment:
                continue
            k, v = segment.split(":", 1)
            if k == "AV":
                av_num = AV_SHORT.get(v, AV_LONG.get(v, av_num))
            elif k == "AC":
                ac_num = AC_SHORT.get(v, AC_LONG.get(v, ac_num))
            elif k == "PR":
                pr_num = PR_SHORT.get(v, PR_LONG.get(v, pr_num))
            elif k == "UI":
                ui_num = UI_SHORT.get(v, UI_LONG.get(v, ui_num))
            elif k == "S":
                sc_num = SC_SHORT.get(v, SC_LONG.get(v, sc_num))
            elif k == "C":
                ci_num = IMP_SHORT.get(v, IMP_LONG.get(v, ci_num))
            elif k == "I":
                ii_num = IMP_SHORT.get(v, IMP_LONG.get(v, ii_num))
            elif k == "A":
                ai_num = IMP_SHORT.get(v, IMP_LONG.get(v, ai_num))
    else:
        # No CVSS vector — infer from severity / vuln_type
        sev   = (finding.get("severity") or "medium").lower()
        vtype = (finding.get("vuln_type") or "").lower().replace("-", "_")

        critical_types = {"rce", "command_injection", "sqli", "sql_injection", "blind_sqli",
                          "remote_code_execution", "os_command_injection", "docker_socket_exposed"}
        high_types     = {"ssrf", "xxe", "lfi", "path_traversal", "ssti", "idor",
                          "jwt_none_alg", "default_credentials", "subdomain_takeover",
                          "insecure_deserialization", "request_smuggling", "smb_exposed"}
        medium_types   = {"xss", "reflected_xss", "stored_xss", "csrf", "open_redirect",
                          "cors_misconfig", "jwt_weak_secret", "race_condition"}

        if sev == "critical" or any(t in vtype for t in critical_types):
            av_num, ac_num, pr_num, ui_num, sc_num = 4, 2, 3, 2, 2  # N/L/N/N/C
            ci_num, ii_num, ai_num = 3, 3, 3                         # H/H/H
        elif sev == "high" or any(t in vtype for t in high_types):
            av_num, ac_num, pr_num, ui_num, sc_num = 4, 2, 2, 1, 1  # N/L/L/R/U
            ci_num, ii_num, ai_num = 3, 2, 1                         # H/L/N
        elif sev == "medium" or any(t in vtype for t in medium_types):
            av_num, ac_num, pr_num, ui_num, sc_num = 4, 2, 3, 1, 2  # N/L/N/R/C
            ci_num, ii_num, ai_num = 2, 1, 1                         # L/N/N
        else:                                                          # low / info
            av_num, ac_num, pr_num, ui_num, sc_num = 2, 1, 1, 1, 1  # L/H/H/R/U
            ci_num, ii_num, ai_num = 1, 1, 1                         # N/N/N

    epss      = float(finding.get("epss_score", 0.0))
    in_kev    = 1.0 if finding.get("in_kev") else 0.0
    age_days  = float(min(finding.get("vuln_age_days", 30), 3650))
    ref_count = float(min(finding.get("ref_count", 5), 50))
    cpe_count = float(min(finding.get("cpe_count", 1), 20))

    return {
        "attack_vector":        float(av_num),
        "attack_complexity":    float(ac_num),
        "privileges_required":  float(pr_num),
        "user_interaction":     float(ui_num),
        "scope":                float(sc_num),
        "conf_impact":          float(ci_num),
        "integ_impact":         float(ii_num),
        "avail_impact":         float(ai_num),
        "vuln_age_days":        age_days,
        "ref_count":            ref_count,
        "cpe_count":            cpe_count,
        "epss_score_pct":       epss * 100.0,
        "in_kev":               in_kev,
    }


async def score_vulnerabilities(scan_id: str = "", findings: Optional[list[dict[Any, Any]]] = None, **kwargs) -> dict[str, Any]:
    """Score vulnerabilities with the NVD CVSS prediction model (called by orchestrator)."""
    logger.info("Running ML risk scoring with NVD CVSS model...")
    model = get_model()
    findings = findings or []
    scored_findings = []

    from heaven.ml.nvd_pipeline import NVDPipeline

    for f in findings:
        # Extract NVD-compatible 13-feature vector for the model
        nvd_features = _extract_nvd_features(f)
        predicted = model.predict_cvss_score(nvd_features)

        # Fall back to feature_engine if the NVD model wasn't loaded
        if predicted == 5.0 and not model._regression_mode:
            fe_features = extract_features(f)
            predicted = model.predict_cvss_score(fe_features.features)

        epss = f.get("epss_score", 0.0)
        in_kev = f.get("in_kev", False)
        f["predicted_cvss_score"] = round(predicted, 1)
        f["priority_score"] = NVDPipeline.compute_priority_score(predicted, epss, in_kev)
        f["risk_band"] = (
            "critical" if predicted >= 9.0 else
            "high"     if predicted >= 7.0 else
            "medium"   if predicted >= 4.0 else "low"
        )
        scored_findings.append(f)

    return {
        "scored": len(scored_findings),
        "model_version": model.version,
        "metrics": model.get_metrics(),
        "risk_scores": scored_findings,
    }
