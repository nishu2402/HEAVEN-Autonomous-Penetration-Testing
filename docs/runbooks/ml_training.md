# HEAVEN — ML Risk Model: Real Training Data

The risk-scoring model in `heaven/ml/risk_model.py` ships trained on the synthetic data in `heaven/ml/training_data.py`. That makes the model load and produce numbers, but those numbers have no calibrated meaning. This runbook gets you to a model trained on real CVE + EPSS history.

---

## What you need

Three public datasets:

1. **NVD CVE feed** — every published CVE with CVSS scores, CWE, CPE list, references.
   - URL: <https://nvd.nist.gov/feeds/json/cve/1.1/>
   - License: public domain (US Government work)
   - Size: ~3 GB uncompressed for the full historical archive
   - Get an API key for full rate: <https://nvd.nist.gov/developers/request-an-api-key>

2. **EPSS scores** — daily-updated probability that a CVE will be exploited in the next 30 days.
   - URL: <https://epss.cyentia.com/epss_scores-current.csv.gz>
   - License: free for commercial and non-commercial use
   - Size: ~6 MB

3. **CISA KEV (Known Exploited Vulnerabilities) catalog** — CVEs with confirmed in-the-wild exploitation.
   - URL: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
   - License: public domain
   - Size: ~1 MB

---

## Pipeline

The pipeline lives at `scripts/train_risk_model.py` (you'll create this). High-level:

```
  NVD JSON → flatten → CVE features (CVSS, CWE, year, vendor, product)
  EPSS CSV → join on CVE-ID → adds {epss_score, epss_percentile}
  KEV JSON → join on CVE-ID → adds {kev_known_exploited: bool}
                            ↓
                        Training set
                            ↓
                  XGBoost classifier
                  (target: kev_known_exploited)
                            ↓
                  Save → models/risk_model_v3.joblib
                            ↓
       At scan time: feature vector → model.predict_proba()
                     gives probability this CVE will be exploited.
```

The risk score the API returns becomes that probability × CVSS, scaled 0-100.

---

## Step-by-step

### 1. Download datasets

```bash
mkdir -p data/training
cd data/training

# NVD — yearly archives, 2002 to current year
for year in $(seq 2002 $(date +%Y)); do
    curl -O "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-${year}.json.gz"
done
gunzip nvdcve-1.1-*.json.gz

# EPSS
curl -O https://epss.cyentia.com/epss_scores-current.csv.gz
gunzip epss_scores-current.csv.gz

# CISA KEV
curl -O https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

### 2. Flatten NVD into a Pandas frame

Already partially done by `heaven/vulnscan/cve_mapper.py`. Reuse its `_flatten_cve` function — it produces dicts you can hand to `pd.DataFrame.from_records`.

### 3. Train the model

```python
# scripts/train_risk_model.py — sketch
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib

df = build_dataset()  # NVD + EPSS + KEV joined on CVE-ID

# Feature columns
feature_cols = [
    "cvss_v3_base", "cvss_v3_exploitability", "cvss_v3_impact",
    "epss_score", "epss_percentile",
    "cwe_id_top",  # one-hot top-50 CWEs
    "year_published",
    "has_public_exploit",  # from references containing exploit-db, github
    "vendor_top_10",       # one-hot top-10 vendors
    "is_remote",           # bool
    "auth_required",       # bool
]

X = df[feature_cols]
y = df["kev_known_exploited"]   # binary target

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y,
)

# Heavily imbalanced — KEV is ~3% of all CVEs
scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()

model = xgb.XGBClassifier(
    n_estimators=500, max_depth=6, learning_rate=0.05,
    objective="binary:logistic",
    scale_pos_weight=scale_pos_weight,
    eval_metric="aucpr",
)
model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

# Calibrate before saving — raw probabilities from XGBoost are not
# probability-meaningful; isotonic regression fixes that.
from sklearn.calibration import CalibratedClassifierCV
calibrated = CalibratedClassifierCV(model, cv="prefit", method="isotonic")
calibrated.fit(X_test, y_test)

# Validation
y_pred_proba = calibrated.predict_proba(X_test)[:, 1]
print(f"AUC-ROC: {roc_auc_score(y_test, y_pred_proba):.3f}")
print(classification_report(y_test, calibrated.predict(X_test)))

joblib.dump(calibrated, "models/risk_model_v3.joblib")
```

### 4. Sanity-check the trained model

A trained model on this dataset should achieve roughly:
- **AUC-ROC ≥ 0.85** — anything below that means the features don't carry signal
- **Recall on KEV ≥ 0.65** — catches at least 65% of known-exploited CVEs at the default threshold
- **Precision on KEV ≥ 0.40** — at least 40% of "predicted exploitable" actually are

If your numbers are far off these baselines, check: dataset balance, missing EPSS values (impute as 0, not NaN), CWE encoding (don't hash; one-hot the top 50).

### 5. Update `heaven/config.py`

```python
# heaven/config.py
@dataclass
class MLConfig:
    model_path: Path = field(default_factory=lambda: Path("models/risk_model_v3.joblib"))
```

Or set `HEAVEN_ML_MODEL=/path/to/risk_model_v3.joblib`.

### 6. Calibrate at runtime

After retraining, run a few hundred real scans against your engagement data and compare the predicted risk score to operator-assigned severity. If the model systematically over-rates or under-rates a class of finding, retrain with the corrected labels. This is normal and ongoing — security data drifts.

---

## What "honest output" looks like

Every finding in HEAVEN's report should carry:

```json
{
  "cve_id": "CVE-2024-12345",
  "cvss_v3": 9.8,
  "epss_score": 0.42,
  "epss_percentile": 0.97,
  "kev_known_exploited": true,
  "ml_predicted_exploitability": 0.81,
  "ml_model_version": "v3-2026-05",
  "risk_score": 87
}
```

The `ml_model_version` field is critical — it tells the consumer which training data and model the score came from. Without it, your "85/100 risk" is meaningless three months later.

---

## What NOT to do

- **Don't** train on synthetic data and ship the resulting model as-if-real. The current `training_data.py` is fine as a stub but the model trained on it is a placeholder.
- **Don't** report a "99.99% accuracy" or "AI-driven" label. The model is a calibrated XGBoost classifier on EPSS+KEV. Say that.
- **Don't** retrain on engagement-specific data and then publish the model — it leaks customer info via feature distributions.
