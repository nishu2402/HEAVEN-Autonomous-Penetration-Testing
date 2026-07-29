# HEAVEN — ML Risk Model: Training & Retraining

HEAVEN ships a **real, trained** CVSS-prediction model:
`data/models/NVD_model.pkl` — a `sklearn.ensemble.ExtraTreesRegressor` that
predicts a CVSS v3 base score (0.0–10.0) from a 13-feature vector, trained on
~220,000 real NVD CVE records (R² ≈ 0.9925 on a held-out 20%).

The authoritative, model-card reference is
[`data/models/NVD_model.MODEL_CARD.md`](../../data/models/NVD_model.MODEL_CARD.md)
— **required reading** before you consume the model's output. This runbook is the
operational how-to for getting the model onto a fresh machine and retraining it.

> The model is used to *fill gaps* — it estimates CVSS for a CVE whose official
> score hasn't been published yet, and gives a stable risk-ordering when a
> finding's CVE mapping is uncertain. When a real NVD/FIRST CVSS exists, HEAVEN
> uses that, not the prediction.

---

## Get the model onto a machine

The 48 MB binary is intentionally **git-ignored** (`*.pkl`), so a fresh clone
won't have it. Two ways to obtain it:

```bash
# Option A — download the prebuilt model
heaven download-model

# Option B — train it yourself from live NVD data (see below)
heaven train-model
```

Until one of these runs, `heaven/ml/risk_model.py` detects the missing model,
disables regression mode, and falls back to a deterministic CVSS-vector score —
so the tool still runs, just without ML-predicted CVSS.

---

## Retrain from live data

```bash
heaven train-model            # downloads NVD data → trains → writes the model
```

What happens under the hood:

1. **`heaven/ml/nvd_pipeline.py`** downloads the NVD JSON feeds and flattens them
   to `nvd_data/nvd_dataset.jsonl` (CVSS v3 records only; pre-2016 v2-era records
   are filtered out).
2. **`heaven/ml/feature_engine.py`** builds the 13-feature vector per CVE.
3. **`heaven/ml/train_model.py::train_cvss_model()`** does an 80/20 split
   (`random_state=42`), fits the `ExtraTreesRegressor`
   (`n_estimators=100, max_depth=12, min_samples_leaf=2`), and writes
   `NVD_model.pkl` plus a `metrics.json` (R², RMSE, MAE, n_train, n_test).

Speed up NVD ingestion with a free API key:

```bash
export NVD_API_KEY=…          # https://nvd.nist.gov/developers/request-an-api-key
heaven train-model
```

### The 13 features

The vector is CVSS-v3-derived plus real-world exploitation signals — **EPSS and
CISA KEV are already inputs** (features 12 and 13), so exploit-likelihood is baked
in, not bolted on:

| # | Feature | Source |
|---|---|---|
| 1–8 | `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `conf_impact`, `integ_impact`, `avail_impact` | CVSS v3 |
| 9 | `vuln_age_days` | derived from CVE publish date |
| 10 | `ref_count` | NVD reference count |
| 11 | `cpe_count` | affected-CPE list length |
| 12 | `epss_score_pct` | FIRST.org EPSS |
| 13 | `in_kev` | CISA Known Exploited Vulnerabilities catalog |

Full definitions and ranges are in the model card. Feature names live in code at
`heaven/ml/risk_model.py::HeavenRiskModel.NVD_FEATURE_NAMES`.

---

## Sanity-check a retrain

After `heaven train-model`, `data/models/metrics.json` should show roughly:

- **R² (held-out 20%) ≥ 0.98** — the CVSS score is largely a deterministic
  function of the categorical features, so a healthy model reverse-engineers the
  calculator with the numeric features as tie-breakers. A big drop means the NVD
  ingest or feature mapping broke.
- **RMSE ≈ 0.2–0.3** CVSS units.

If your numbers are far off, check: the NVD download completed, EPSS values were
joined (impute missing as 0, not NaN), and the v3-only filter is intact.

---

## Public data sources (reference)

| Dataset | URL | Note |
|---|---|---|
| NVD CVE feed | <https://nvd.nist.gov/developers> | primary training corpus; public domain |
| EPSS scores | <https://epss.cyentia.com/epss_scores-current.csv.gz> | daily exploit-probability; free use |
| CISA KEV | <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> | confirmed in-the-wild exploitation; public domain |

---

## Honest limits (see the model card for the full list)

- **CVSS is not risk.** A CVSS 9.8 in a service you don't run is zero risk to you.
  The model predicts CVSS; use the `heaven/ml/ai_brain.py` value-weighting layer
  and asset criticality for true prioritisation.
- **v3-only.** The model is trained on CVSS v3 records; a v4-shaped input is
  undefined. The caller must supply v3 features.
- **No model signing.** `joblib.load` executes pickle — **never load a model file
  from an untrusted source.** Always `download-model` from the project release or
  retrain from the trainer code in this repo.
- **Empirical priors are separate.** `heaven train-priors` builds the Bayesian
  service-priors table from your engagement history — that's a different artifact
  from this CVSS regressor.
