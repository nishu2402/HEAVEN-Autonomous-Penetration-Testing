"""
HEAVEN — CVSS Regression Model Trainer
Train GradientBoosting regressor on NVD data.
Run via: python -m heaven.ml.train_model
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import numpy as np


def train_cvss_model(data_dir: Path = Path("nvd_data"),
                     model_dir: Path = Path("models")) -> dict:
    """
    Train GradientBoosting regressor on NVD CVSS data.
    Run via: python -m heaven.ml.train_model
    """
    from heaven.ml.nvd_pipeline import NVDPipeline
    import joblib
    import json
    from sklearn.ensemble import GradientBoostingRegressor
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import r2_score, mean_squared_error

    pipeline = NVDPipeline()

    jsonl = data_dir / "nvd_dataset.jsonl"
    if not jsonl.exists():
        print("Dataset not found. Downloading (this takes ~30 min without API key)...")
        asyncio.run(pipeline.download_dataset(data_dir))

    print("Parsing dataset...")
    X, y, feature_names = pipeline.parse_dataset(jsonl)
    print(f"Dataset: {len(y):,} CVEs")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("Training GradientBoostingRegressor...")
    model = GradientBoostingRegressor(
        n_estimators=300, max_depth=5, learning_rate=0.08,
        subsample=0.85, random_state=42, verbose=1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    r2 = r2_score(y_test, y_pred)
    rmse = float(np.sqrt(mean_squared_error(y_test, y_pred)))
    mae = float(np.mean(np.abs(y_test - y_pred)))

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "cvss_regressor.joblib")
    (model_dir / "feature_names.json").write_text(json.dumps(feature_names))

    metrics = {"r2": round(r2, 4), "rmse": round(rmse, 4),
               "mae": round(mae, 4), "n_train": len(y_train),
               "n_test": len(y_test)}
    (model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"R²={r2:.4f}  RMSE={rmse:.4f}  MAE={mae:.4f}")
    print(f"Model saved: {model_dir}/cvss_regressor.joblib")
    return metrics


if __name__ == "__main__":
    train_cvss_model()
