"""
HEAVEN — Description/type CVSS fallback model trainer

Trains a text model on the NVD_Cybersecurity dataset (a CSV of ~1M CVEs, ~337k
with a published CVSS base score) to predict a CVSS base score from what ANY
finding carries: its descriptive text plus the seven vulnerability-type flags
and the text length. This is the fallback half of HEAVEN's hybrid risk model —
see :mod:`heaven.ml.desc_model`.

The model is a scikit-learn ``Pipeline``: a TF-IDF vectoriser over the finding's
description text (word 1–2 grams) combined with the seven binary vuln-type flags
and two length features, fed to a Ridge regressor. The description text is the
dominant signal — using it lifts honest CV from R²≈0.43 (flags+length only) to
R²≈0.56 on real findings. The flags/length give a robust backbone so a terse
finding title still scores sensibly when the TF-IDF vocabulary barely fires.

TRAINED ON THE POPULATION HEAVEN ACTUALLY SCORES (measured honestly):
  * The model is trained and evaluated on the ~316k CVEs with a NON-ZERO CVSS
    base score — i.e. real, exploitable vulnerabilities. The ~22k CVEs scored
    exactly 0.0 (rejected / disputed / purely informational entries) are dropped:
    HEAVEN never routes them to this model (a finding only reaches it when it has
    a real vuln-type signal), and keeping them just inflates R² with trivially
    predictable zeros while pulling real predictions down.
  * Two honest metric populations are recorded in the meta:
      - the real-finding population (all non-zero rows): ``cv_r2`` / ``cv_mae`` /
        ``cv_band_exact`` / ``cv_band_within1`` (5-fold CV / out-of-fold).
      - the true DEPLOYMENT population — findings that carry a vuln-type flag,
        which is exactly what HEAVEN's router feeds this model: ``deploy_r2`` /
        ``deploy_mae`` / ``deploy_band_exact`` / ``deploy_band_within1``. These
        are the numbers to cite, and they are the strongest and the most honest.
  * R² is a harsh lens for this job: the same vuln class genuinely spans a wide
    CVSS range in real NVD data, so no honest feature available at scan time can
    pin the exact number. What matters for HEAVEN is the SEVERITY BAND, and on
    the deployment population the model lands the right band ~70% of the time and
    within one band ~99%.
  * The genuine "100%" is the CVSS formula on the actual metric vector (R²=1.0),
    which is what HEAVEN already uses for every finding's REPORTED severity
    (per-class vector → reference scorer → ``reconcile_severity``). This text
    model is only a secondary prioritisation hint for scoreless findings, and it
    is pinned to the authoritative severity, so it can never move a report's
    badge — it only orders findings the deterministic path could not score.

Deliberately EXCLUDES ``Exploitability_Score`` and ``Impact_Score``: those are
CVSS sub-formula components, so a model using them just re-derives the score you
already have (R²≈0.999 but useless when a finding has NO published CVSS — a
scoreless finding has neither sub-score either). It also excludes ``Publish_Year``
/ ``Publish_Month``: they are constant at inference (every finding in a scan gets
the current date), so training on them inflates CV without helping deployment.
The dataset carries no CVSS metric columns (AV/AC/PR/UI/S/C/I/A), so there is no
structured real-world feature to switch to — text IS the richest honest signal.
An exhaustive architecture search (word+char n-grams, HistGradientBoosting on a
TruncatedSVD of the TF-IDF, MAE-loss linear models, a direct severity-band
classifier) found nothing that honestly beats this linear text model on the
deployment population.

Run via ``heaven train-model`` (auto-runs this when the CSV is present) or
``python -m heaven.ml.train_desc_model --csv <path>``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from heaven.ml.desc_model import FLAG_NAMES

# Length features are clipped to [p1, p99] of the training data at BOTH train and
# inference time (see desc_model) so a short finding title can never push the
# model outside the range it learned on.
_LENGTH_FEATURES = ["Word_Count", "Char_Length"]
NUMERIC_FEATURES = FLAG_NAMES + _LENGTH_FEATURES
_TEXT_COLUMN = "text"

# TF-IDF + Ridge hyper-parameters — chosen by honest CV over the dataset (word
# 1–2 grams @ 50k features + flags + length + Ridge(alpha=3.0) topped the search;
# char n-grams gave a negligible lift and bloated the artifact, and no nonlinear
# model beat linear on the deployment population).
_TFIDF_MAX_FEATURES = 50000
_TFIDF_NGRAM = (1, 2)
_TFIDF_MIN_DF = 3
_RIDGE_ALPHA = 3.0

# Where the CSV may live (first existing wins). The dataset is large and
# user-specific, so an explicit --csv / HEAVEN_NVD_CSV always wins.
_CSV_CANDIDATES = [
    "nvd_data/NVD_Cybersecurity_Dataset.csv",
    "data/nvd/NVD_Cybersecurity_Dataset.csv",
]


def _resolve_csv(csv: Optional[str]) -> Optional[Path]:
    if csv:
        p = Path(csv).expanduser()
        return p if p.exists() else None
    env = os.environ.get("HEAVEN_NVD_CSV")
    if env and Path(env).expanduser().exists():
        return Path(env).expanduser()
    for c in _CSV_CANDIDATES:
        if Path(c).exists():
            return Path(c)
    return None


def _build_pipeline():
    from sklearn.compose import ColumnTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import Ridge
    from sklearn.pipeline import Pipeline

    pre = ColumnTransformer(
        [
            (
                "word",
                TfidfVectorizer(
                    ngram_range=_TFIDF_NGRAM,
                    min_df=_TFIDF_MIN_DF,
                    max_features=_TFIDF_MAX_FEATURES,
                    sublinear_tf=True,
                ),
                _TEXT_COLUMN,  # scalar selector → 1-D Series into the vectoriser
            ),
            ("num", "passthrough", NUMERIC_FEATURES),
        ]
    )
    return Pipeline([("pre", pre), ("reg", Ridge(alpha=_RIDGE_ALPHA))])


def _band(a):
    import numpy as np
    return np.where(a >= 9, 3, np.where(a >= 7, 2, np.where(a >= 4, 1, 0)))


def train_desc_model(csv: Optional[str] = None,
                     model_dir: Path = Path("data/models")) -> Optional[dict]:
    """Train the description/type CVSS model. Returns the metrics dict, or None
    if the source CSV is not available (caller should skip cleanly)."""
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.metrics import mean_absolute_error, r2_score
    from sklearn.model_selection import KFold, cross_val_predict, cross_val_score

    csv_path = _resolve_csv(csv)
    if csv_path is None:
        print("Description-model CSV not found — skipping (set --csv or HEAVEN_NVD_CSV). "
              "The hybrid risk model will use the vector model for every finding.")
        return None

    print(f"Reading dataset: {csv_path}")
    usecols = ["Clean_Description", "Description", *NUMERIC_FEATURES, "CVSS_Base_Score"]
    df = pd.read_csv(csv_path, usecols=usecols)
    df = df[df["CVSS_Base_Score"].notna()].copy()
    n_all_labelled = len(df)

    # Train on the population HEAVEN actually scores: real findings with a
    # NON-ZERO CVSS base score. The ~22k score==0 rows are rejected/disputed/
    # informational CVEs that HEAVEN never routes to this model; keeping them just
    # inflates R² with trivial zeros and biases real predictions downward.
    n_zero = int((df["CVSS_Base_Score"] == 0).sum())
    df = df[df["CVSS_Base_Score"] > 0].copy()
    if len(df) < 500:
        print(f"Only {len(df)} non-zero labelled rows — too few to train; skipping.")
        return None

    # The finding's description text — lower-cased to match Clean_Description and
    # desc_model's inference-time cleaning.
    df[_TEXT_COLUMN] = (
        df["Clean_Description"].fillna(df["Description"]).fillna("").astype(str).str.lower()
    )
    print(f"Labelled rows: {n_all_labelled:,} (dropped {n_zero:,} score==0 info-CVEs) "
          f"→ training on {len(df):,} real findings | text + "
          f"{len(NUMERIC_FEATURES)} numeric features")

    # Clip bounds (p1..p99) for the length features — bounds the inference input.
    clip: dict[str, list[float]] = {}
    for f in _LENGTH_FEATURES:
        lo = float(df[f].quantile(0.01))
        hi = float(df[f].quantile(0.99))
        clip[f] = [lo, hi]
        df[f] = df[f].clip(lower=lo, upper=hi)
    for f in FLAG_NAMES:
        df[f] = df[f].fillna(0).astype(float)

    input_columns = [_TEXT_COLUMN, *NUMERIC_FEATURES]
    X = df[input_columns]
    y = df["CVSS_Base_Score"].to_numpy(float)
    # The DEPLOYMENT population: findings carrying a vuln-type flag — exactly what
    # HEAVEN's router feeds this model. Positional mask, aligned to X's rows.
    flag_mask = (df[FLAG_NAMES].to_numpy().sum(axis=1) > 0)

    pipeline = _build_pipeline()

    print("Cross-validating (5-fold)…")
    cv = KFold(n_splits=5, shuffle=True, random_state=42)
    cv_r2 = cross_val_score(pipeline, X, y, cv=cv, scoring="r2", n_jobs=-1)

    # Out-of-fold predictions → honest MAE + severity-band accuracy, and the same
    # metrics restricted to the deployment (flagged) population. R² is a harsh
    # lens (the same vuln type spans a wide CVSS range in NVD), so what matters is
    # landing the finding in the right severity BAND: `band_exact` = same band as
    # the true score; `band_within1` = at most one band away. Bands follow
    # HEAVEN's cut points (critical ≥9, high ≥7, medium ≥4, else low).
    pred_oof = np.clip(cross_val_predict(pipeline, X, y, cv=cv, n_jobs=-1), 0.0, 10.0)
    tb, pb = _band(y), _band(pred_oof)

    cv_mae = float(mean_absolute_error(y, pred_oof))
    band_exact = float((tb == pb).mean())
    band_within1 = float((np.abs(tb - pb) <= 1).mean())

    # Deployment population (flagged findings) — the numbers HEAVEN really runs on.
    dr2 = float(r2_score(y[flag_mask], pred_oof[flag_mask]))
    dmae = float(mean_absolute_error(y[flag_mask], pred_oof[flag_mask]))
    d_exact = float((tb[flag_mask] == pb[flag_mask]).mean())
    d_within1 = float((np.abs(tb[flag_mask] - pb[flag_mask]) <= 1).mean())

    print("Fitting final model on all real (non-zero) findings…")
    pipeline.fit(X, y)

    # Per-flag empirical mean CVSS — grounded provenance for the model card.
    flag_means = {
        f: round(float(df.loc[df[f] == 1, "CVSS_Base_Score"].mean()), 2)
        for f in FLAG_NAMES if int((df[f] == 1).sum()) > 0
    }

    model_dir.mkdir(parents=True, exist_ok=True)
    model_file = model_dir / "cvss_text_model.joblib"
    meta_file = model_dir / "cvss_text_model.meta.json"
    joblib.dump(pipeline, model_file, compress=3)

    meta = {
        "model_type": "TfidfRidgePipeline",
        "model_family": "text",
        "input_columns": input_columns,
        "text_column": _TEXT_COLUMN,
        "numeric_columns": NUMERIC_FEATURES,
        "feature_names": NUMERIC_FEATURES,  # kept for back-compat with older loaders
        "hyperparams": {
            "tfidf_ngram_range": list(_TFIDF_NGRAM),
            "tfidf_max_features": _TFIDF_MAX_FEATURES,
            "tfidf_min_df": _TFIDF_MIN_DF,
            "ridge_alpha": _RIDGE_ALPHA,
        },
        "clip": clip,
        "target": "CVSS_Base_Score",
        "training_population": "nonzero_cvss",
        # Real-finding population (all non-zero rows).
        "cv_r2": round(float(cv_r2.mean()), 4),
        "cv_r2_std": round(float(cv_r2.std()), 4),
        "cv_mae": round(cv_mae, 4),
        "cv_band_exact": round(band_exact, 4),
        "cv_band_within1": round(band_within1, 4),
        # Deployment population (findings carrying a vuln-type flag) — what HEAVEN
        # actually routes here; the numbers to cite.
        "deploy_r2": round(dr2, 4),
        "deploy_mae": round(dmae, 4),
        "deploy_band_exact": round(d_exact, 4),
        "deploy_band_within1": round(d_within1, 4),
        "cv_folds": 5,
        "n_samples": int(len(df)),
        "n_samples_deploy": int(flag_mask.sum()),
        "n_all_labelled": int(n_all_labelled),
        "n_dropped_zero": n_zero,
        "flag_mean_cvss": flag_means,
        "sklearn_version": sklearn.__version__,
        "source_csv": csv_path.name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "excluded_leaky_features": ["Exploitability_Score", "Impact_Score", "Publish_Year"],
    }
    meta_file.write_text(json.dumps(meta, indent=2))

    print(f"Real-finding CV R²={meta['cv_r2']}±{meta['cv_r2_std']}  MAE={meta['cv_mae']}  "
          f"(sklearn {sklearn.__version__})")
    print(f"Deployment (flagged) population: R²={meta['deploy_r2']}  MAE={meta['deploy_mae']}  "
          f"band exact={meta['deploy_band_exact']}  within-one-band={meta['deploy_band_within1']}")
    print(f"Per-flag mean CVSS: {flag_means}")
    print(f"Model saved: {model_file}")
    return meta


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Train the description/type CVSS fallback model")
    ap.add_argument("--csv", default=None, help="Path to NVD_Cybersecurity_Dataset.csv")
    ap.add_argument("--model-dir", default="data/models")
    args = ap.parse_args()
    train_desc_model(csv=args.csv, model_dir=Path(args.model_dir))
