"""
HEAVEN — CVSS Regression Model Trainer
Train ExtraTreesRegressor on NVD data (13-feature set matching NVD_model.pkl).
Run via: python -m heaven.ml.train_model  OR  heaven train-model
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import numpy as np


def train_cvss_model(data_dir: Path = Path("nvd_data"),
                     model_dir: Path = Path("models")) -> dict:
    """
    Download NVD data (if needed) and train an ExtraTreesRegressor CVSS predictor.

    Outputs:
      models/cvss_regressor.joblib — serialised model
      models/feature_names.json   — 13-feature name list
      models/metrics.json         — R², RMSE, MAE
    Also overwrites NVD_model.pkl in the project root for the risk_model loader.
    """
    from heaven.ml.nvd_pipeline import NVDPipeline
    import joblib
    from sklearn.ensemble import ExtraTreesRegressor
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import r2_score, mean_squared_error

    pipeline = NVDPipeline()

    jsonl = data_dir / "nvd_dataset.jsonl"
    if not jsonl.exists() or jsonl.stat().st_size == 0:
        print("Dataset not found. Downloading (this may take ~30 min without an NVD API key)…")
        asyncio.run(pipeline.download_dataset(data_dir))

    print("Parsing dataset…")
    X, y, feature_names = pipeline.parse_dataset(jsonl)
    if len(y) == 0:
        raise RuntimeError(
            "NVD dataset is empty. Run 'heaven train-model' after downloading the dataset "
            "or set NVD_API_KEY for faster downloads."
        )
    print(f"Dataset: {len(y):,} CVEs  |  {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("Training ExtraTreesRegressor (100 trees)…")
    model = ExtraTreesRegressor(
        n_estimators=100, max_depth=12, min_samples_leaf=2,
        n_jobs=-1, random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    r2   = r2_score(y_test, y_pred)
    rmse = float(np.sqrt(mean_squared_error(y_test, y_pred)))
    mae  = float(np.mean(np.abs(y_test - y_pred)))

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "cvss_regressor.joblib")
    (model_dir / "feature_names.json").write_text(json.dumps(feature_names))

    # Also overwrite the root NVD_model.pkl so the risk_model loader picks it up
    root_model = Path(__file__).parent.parent.parent / "NVD_model.pkl"
    joblib.dump(model, root_model)
    feat_json = Path(__file__).parent.parent.parent / "nvd_data" / "feature_names_nvd.json"
    feat_json.parent.mkdir(parents=True, exist_ok=True)
    feat_json.write_text(json.dumps(feature_names))
    print(f"NVD_model.pkl updated → {root_model}")

    metrics = {
        "r2": round(r2, 4), "rmse": round(rmse, 4),
        "mae": round(mae, 4), "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
    }
    (model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"R²={r2:.4f}  RMSE={rmse:.4f}  MAE={mae:.4f}")
    print(f"Model saved: {model_dir}/cvss_regressor.joblib")
    return metrics


if __name__ == "__main__":
    train_cvss_model()
