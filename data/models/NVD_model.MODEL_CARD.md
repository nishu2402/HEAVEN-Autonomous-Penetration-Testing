# Model Card: NVD_model.pkl

This document follows the [Model Cards for Model Reporting (Mitchell et
al., 2019)](https://arxiv.org/abs/1810.03993) format. It is **required
reading** before consuming this model's output in any high-stakes context.

## Model details

- **Name**: `NVD_model.pkl` (the vector half of HEAVEN's hybrid CVSS model)
- **Version**: 4.0 (retrained 2026-09-27 under scikit-learn 1.9.0 on the full NVD corpus)
- **Type**: `sklearn.ensemble.ExtraTreesRegressor`
- **Hyperparameters**: `n_estimators=100`, `max_depth=12`, `min_samples_leaf=2`, `random_state=42`
- **Serialised by**: `joblib` (`compress=3`)
- **File size**: ~10 MB (compressed)
- **Location**: `data/models/NVD_model.pkl` (load-bearing, `heaven.ml.risk_model` reads it from there; a repo-root copy and the user cache dir are also searched)
- **Owner**: HEAVEN project, Nisarg Chasmawala
- **License**: MIT (matches project)
- **Trainer code**: [heaven/ml/train_model.py](../../heaven/ml/train_model.py)
- **Retrain command**: `heaven train-model`

> **Hybrid model.** This card documents the **vector model**, a CVSS-v3-metric
> regressor used when a finding carries a real published CVSS vector/score. When a
> finding has NO published score, HEAVEN instead uses a **description/type model**
> ([heaven/ml/desc_model.py](../../heaven/ml/desc_model.py)), a TF-IDF text model
> (`TfidfVectorizer` + `Ridge`) trained on the NVD_Cybersecurity dataset
> (304,356 real, non-zero-score CVEs). See "Description/type fallback model" at the end of this
> card. The ML score feeds risk-ordering (`priority_score`/`risk_band`); the
> authoritative per-finding CVSS shown in reports comes from the deterministic
> `heaven.utils.cvss.objective_base_score` resolver, which prefers real published
> values.

## Intended use

- **Primary**: Predict a numeric CVSS v3 base score (0.0-10.0) for a CVE
  given its 13-feature vector, so that triage can prioritise CVEs whose
  CVSS has not yet been published (e.g., during a CNA delay window).
- **Secondary**: Provide a stable risk-ordering signal for findings whose
  CVE mapping is uncertain, the regressor produces a continuous score
  even when categorical features collide.
- **Out of scope**:
  - Replacing the official NVD/FIRST CVSS calculator for *known* CVEs (use the real values when available).
  - Predicting *exploit availability* (use EPSS for that, already a feature input).
  - Any non-CVE-shaped risk decision (e.g., business risk, asset criticality).

> **CVSS v4.0 note.** HEAVEN presents CVSS v4.0 as the current standard alongside
> CVSS v3.1. This model is trained on CVSS v3 metrics and outputs a numeric base
> score (0.0-10.0), which is not tied to a scoring version; it is the fallback for
> a finding with no published score. When a CVE ships a v4.0 vector (NVD / OSV)
> HEAVEN uses that published value directly, and the model is not consulted. NVD's
> v4.0 coverage is still sparse, so the model stays on the v3 feature set rather
> than retraining on a much smaller v4.0-labelled sample.

## Features

The model expects a 13-dimensional integer/float vector. Order matters.

| # | Feature | Type | Range | Source |
|---|---|---|---|---|
| 1  | `attack_vector` | int | 1=PHYSICAL, 2=LOCAL, 3=ADJACENT, 4=NETWORK | CVSS v3 |
| 2  | `attack_complexity` | int | 1=HIGH, 2=LOW | CVSS v3 |
| 3  | `privileges_required` | int | 1=HIGH, 2=LOW, 3=NONE | CVSS v3 |
| 4  | `user_interaction` | int | 1=REQUIRED, 2=NONE | CVSS v3 |
| 5  | `scope` | int | 1=UNCHANGED, 2=CHANGED | CVSS v3 |
| 6  | `conf_impact` | int | 1=NONE, 2=LOW, 3=HIGH | CVSS v3 |
| 7  | `integ_impact` | int | 1=NONE, 2=LOW, 3=HIGH | CVSS v3 |
| 8  | `avail_impact` | int | 1=NONE, 2=LOW, 3=HIGH | CVSS v3 |
| 9  | `vuln_age_days` | int | 0-3650 (10 years) | derived from CVE publish date |
| 10 | `ref_count` | int | ≥ 0 | NVD reference count |
| 11 | `cpe_count` | int | ≥ 0 | affected-CPE list length |
| 12 | `epss_score_pct` | float | 0.0-100.0 | FIRST.org EPSS |
| 13 | `in_kev` | int | 0 or 1 | CISA Known Exploited Vulnerabilities catalog |

Feature names live in code at
`heaven/ml/risk_model.py::HeavenRiskModel.NVD_FEATURE_NAMES` and are
mirrored to `nvd_data/feature_names_nvd.json` by the trainer.

## Training data

- **Source**: National Vulnerability Database (NVD) JSONL dump
- **Path**: `nvd_data/nvd_dataset.jsonl` (downloaded by `heaven.ml.nvd_pipeline`)
- **Cutoff**: dataset is downloaded at training time, so the cutoff is the
  date `heaven train-model` was last run. Check `data/models/metrics.json`
  for the latest run's `sklearn_version` and metrics.
- **Size at last training**: 304,430 CVEs parsed from the full NVD corpus (CVSS v3.x,
  with v4.0-only CVEs folded onto the v3 feature shape). Downloaded via
  `heaven.ml.nvd_pipeline` walking the NVD 2.0 API and keeping every scored CVE.
- **Split**: 80 / 20 train/test (`random_state=42`) for the point estimate, plus
  5-fold cross-validation for the stable headline figure.
- **Filter criteria**: only CVEs with a CVSS v3.x base score (or a v4.0 score
  recast onto the v3 feature shape). EPSS/KEV are joined when available.

## Performance

From the most recent training run (`heaven train-model`, recorded in
`data/models/metrics.json`; the CV figure is the honest headline, a single
80/20 split swings ±0.03 R² by luck on a dataset this size):

| Metric | Value |
|---|---|
| **R² (5-fold CV)** | **0.9901 ± 0.0003** |
| R² (held-out 20%) | 0.9896 |
| RMSE | 0.18 (CVSS score units) |
| MAE | 0.037 |
| **R² (temporal holdout, unseen newest year)** | **0.9695** (MAE 0.083, n=68,866) |
| n_samples | 304,430 |
| scikit-learn | 1.9.0 |

**Caveat**: R² this high is expected, not surprising: the CVSS v3 base score is
a *deterministic function* of the eight categorical vector components
(attack_vector, complexity, etc.), so the model is reverse-engineering the CVSS
calculator, with the numeric features as tie-breakers. On the old 2,788-CVE
slice the model reached R²=0.913 because that sample undersampled the metric grid
(~5,184 combinations); training on the full ~304k-CVE corpus covers the grid
densely, so the recovered formula reaches R²=0.99 on held-out CVEs and 0.97 on an
entirely unseen year. This is honest formula recovery, not novel predictive skill:
the client-facing badge is still the exact CVSS formula (below), and this model's
job is risk-ordering for findings whose score is missing or noisy. Earlier cards
quoted R²≈0.99 from a larger, then-non-reproducible dump and could not reproduce
it from the tiny in-repo slice; the full authoritative corpus now reproduces it
with `heaven train-model`.

## Evaluation

- **Held-out set**: 20% of the same NVD dump, random split
- **Temporal validation**: train on every year before the newest, test the
  newest, unseen year (68,866 CVEs), R²=0.9695, MAE=0.083. Recorded as
  `temporal_r2` / `temporal_mae` in `metrics.json`, so temporal drift is now
  measured, not a gap.
- **No subgroup analysis** (gap, should check performance by vendor, CWE
  class, severity bucket)

## Ethical considerations & limitations

- **Bias toward published, well-documented CVEs.** A vulnerability with
  few references and no CPE assignment will get noisy predictions. The
  model is most accurate on mature, widely-discussed CVEs.
- **EPSS leakage.** EPSS score is itself a model output trained on
  exploitation data. Including it as a feature means our model partly
  inherits whatever bias EPSS has. Acceptable trade-off because EPSS is
  the strongest single predictor of real-world risk, but document it.
- **CVSS is not risk.** A CVSS 9.8 RCE in a service you don't run is
  zero risk to you. The model predicts CVSS, not impact. Use alongside
  the `heaven/ml/ai_brain.py` value-weighting layer for true prioritisation.
- **No adversarial robustness testing.** A motivated attacker could
  craft input vectors to manipulate the predicted score. This isn't a
  threat for triage use but matters if outputs feed automated remediation
  budgets.
- **Distribution shift.** NVD's CVSS scoring methodology has changed over
  time (v2 → v3 → v3.1 → v4). The model is v3-only. A v4 input would
  produce undefined output. The trainer filters non-v3 records but the
  inference layer does not, so the caller must ensure v3 inputs.

## Caveats specific to deployment

- **Single-file serialization.** The `.pkl` is a serialised sklearn
  pipeline. It is tied to a specific sklearn / numpy / joblib version
  triple. The training environment is pinned via `requirements.txt`;
  if you upgrade sklearn beyond a major version, retrain.
- **No model signing.** The file is loaded by `joblib.load`, which
  executes arbitrary pickle. **Never deploy a model file from an
  untrusted source.** Always retrain from the trainer code in this repo.
- **~6 MB binary.** Out-of-band distribution (GitHub Release asset, fetched by
  `heaven download-model` and SHA-256 verified), not committed to git.

## Citation

If you use this model in academic work:

> HEAVEN NVD CVSS Regressor v4.0 (2026). ExtraTreesRegressor trained on
> 304k NIST NVD CVSS v3 records. Available at https://github.com/<repo>.

## Changelog

- **v4.0 (2026-09-27)**, retrained on the full NVD corpus (**304,430 scored CVEs**,
  up from 2,788), the entire scored slice of the NVD 2.0 API. Same recipe
  (a config sweep confirmed 100 trees / depth 12 / leaf 2 is still optimal on R²),
  so the lift is purely from dense coverage of the CVSS metric grid: **5-fold CV
  R² 0.913 → 0.990**, MAE 0.22 → 0.037, plus a new **temporal holdout** (train
  pre-2026 → test unseen 2026) at **R²=0.9695**. Serialised with `compress=3`
  (~10 MB). Re-attach `NVD_model.pkl` to the release; `download-model`'s pin was
  updated to the new digest.
- **v3.0 (2026-08-29)**, re-pickled under scikit-learn 1.9.0 (clears the
  1.8.0→1.9.0 `InconsistentVersionWarning` / version-skew risk) and paired with
  a new description/type fallback model (below), making HEAVEN's CVSS model a
  hybrid. Metrics restated to the honest, reproducible figures from the in-repo
  dataset (5-fold CV R²=0.913); prior cards' R²≈0.99 came from a larger,
  non-reproducible dump.
- **v2.0 (May 2026)**, retrained on updated NVD dump including 2024-2026
  CVEs. EPSS feature added. KEV flag added.
- **v1.0 (initial)**, 11-feature ExtraTreesRegressor, no EPSS, no KEV.

---

## Description/type fallback model (`cvss_text_model.joblib`)

The second half of the hybrid, used when a finding has **no** published CVSS.

- **Type**: a scikit-learn `Pipeline`, a `ColumnTransformer` that runs a
  `TfidfVectorizer` over the finding's description text (word 1-3 grams,
  `max_features=100000`, `min_df=3`, `sublinear_tf=True`) alongside the seven
  vulnerability-type flags and two length features (passthrough), feeding a
  `Ridge(alpha=3.0)` regressor. Hyper-parameters chosen by honest 5-fold CV, the
  1-3 gram / 100k recipe beats the older 1-2 gram / 50k one on every deployment
  metric at once (see the architecture search below).
- **Trainer**: [heaven/ml/train_desc_model.py](../../heaven/ml/train_desc_model.py), `heaven train-model --csv <NVD_Cybersecurity_Dataset.csv>`
- **Inference**: [heaven/ml/desc_model.py](../../heaven/ml/desc_model.py)
- **Training data**: the NVD_Cybersecurity dataset, now **regenerated from the same
  full NVD 2.0 pull as the vector model** (`nvd_data/NVD_Cybersecurity_Dataset.csv`,
  built by parsing the corpus, no external / user-specific file needed). Of the
  304,426 CVEs carrying a published `CVSS_Base_Score`, the model trains on the
  **304,356 with a non-zero score** (real, exploitable vulnerabilities; only 70
  score-0.0 rows are dropped: HEAVEN never routes an informational CVE here, since
  a finding reaches this model only when it carries a real vuln-type signal). The
  **142,854 non-zero CVEs that carry a vuln-type flag** are the **deployment
  population**, exactly what HEAVEN's router feeds this model, and the numbers to
  cite.
- **Features**: the CVE **description text** (TF-IDF, the dominant signal) plus
  the seven vulnerability-type flags (XSS, SQLi, Buffer Overflow, RCE, Privilege
  Escalation, DoS, Directory Traversal) and the descriptive-text `Word_Count` and
  `Char_Length` (clipped to the training p1-p99 range so a short finding title
  never extrapolates the model). The flags/length are a robust backbone for terse
  finding titles where the TF-IDF vocabulary barely fires.
- **Target**: `CVSS_Base_Score` (0.0-10.0 regression).
- **Size**: ~2 MB (`joblib`, compressed).

### Performance (5-fold out-of-fold, sklearn 1.9.0)

Measured on the two honest populations. The **deployment population** (findings
carrying a vuln-type flag) is what HEAVEN actually routes to this model, so it is
the number to cite. Because this model is a **ranking aid** for scoreless findings
that never sets a badge, the lenses that match its job are the **rank correlation**
(does it order findings by true severity?) and the **band accuracy**, not the
exact-score R²:

| Population | Spearman ρ | band exact | within one band | exact-score R² | MAE |
|---|---|---|---|---|---|
| **Deployment (flagged findings)**, what HEAVEN scores | **0.81** | **73.4%** | **99.2%** | **0.65** | **0.68** |
| All real findings (non-zero score) | 0.74 | 68.7% | 98.6% | 0.54 | 0.85 |

**Temporal generalisation** (train on CVEs older than the newest year, test the
newest year the model never trained on, the honest "future vulnerabilities" read):
on the deployment population (25,768 flagged 2026 CVEs) it keeps **Spearman ρ=0.70**
and **98.0% within one band** (exact-score R²=0.45). The ordering transfers to
unseen CVEs; only the exact decimal drifts under distribution shift.

**Why not a single, higher R²?** R² can only be pushed above this by leaking the
CVSS formula's own sub-scores, and the training CSV carries no CVSS metric columns
to switch to (by design, a scoreless finding has none at inference either).
Feature-set / architecture ablation that selected the recipe (5-fold, deployment
population; the shipped row is re-measured on the current 304k corpus, the
comparison rows are from the recipe-selection search on the development corpus):

| Feature set / model | deploy R² | Usable at scan time? |
|---|---|---|
| **Text (TF-IDF word 1-3 gram @ 100k) + flags + length, Ridge** (shipped) | **0.65** | ✅ |
| Text (TF-IDF word 1-2 gram @ 50k) + flags + length, Ridge (previous) | 0.63 | ✅ |
| + char n-grams (3-5) | 0.63 | ✅ but ~10x fit time, bloated artifact, no real lift |
| HistGradientBoosting on TruncatedSVD(300) of the TF-IDF | 0.62 | ✅ but loses (SVD drops most text variance) |
| Vuln-type flags + text length only (older) | 0.43 | ✅ |
| + `Exploitability_Score` | 0.70 | ❌ leakage |
| + `Exploitability` + `Impact_Score` | 0.999 | ❌ leakage (re-derives the CVSS formula) |

Reading the finding's actual description **sharply lifts** honest R² over a
flags-and-length-only model (up to **R²=0.54** on all real findings and **0.65**
on the deployment population), because the text carries the impact/access wording
the flags only crudely approximate. The **architecture search** settled the recipe:
word 1-3 grams @ 100k features beat 1-2 grams @ 50k on every deployment metric at
once; char n-grams,
gradient boosting on a TruncatedSVD, MAE-loss linear models, and a direct 5-band
classifier (higher exact-match but nearly double the gross-error rate and no
continuous score) were all beaten by this linear text model on the deployment
population.

**Rank correlation and band accuracy are the metrics that reflect real use.** R²
is a harsh lens for a CVSS predictor: the same vuln class genuinely spans a wide
score range in the NVD data, so no honest feature available at scan time can pin
the exact number, but HEAVEN only needs this model to **order** scoreless findings
and land them in the right band. Out-of-fold on the deployment population it does:
**Spearman ρ=0.81, 73.4% exact band, 99.2% within one band** (`deploy_spearman` /
`deploy_band_exact` / `deploy_band_within1` in the meta; the `cv_*` fields carry
the all-real-findings figures, and the `temporal_deploy_*` fields the unseen-year
generalisation).

The genuine "100%" is the CVSS formula applied to a finding's actual metric vector
(R²=1.0, MAE=0). That is what HEAVEN uses for every **reported** severity (per-class
vector → reference scorer → `reconcile_severity`), and this text model is pinned to
that authoritative severity; it is only a secondary ranking signal for scoreless
findings and can never move a report's badge.

**Deliberate exclusions.** `Exploitability_Score` and `Impact_Score` are CVSS
sub-formula components, a model using them just reconstructs a score you must
already have, so they are leakage for the "no published score" use case (they
are what makes the often-quoted ~0.99 on this dataset). `Publish_Year` is known
at scan time but is a single constant across one scan, so it cannot help order
that scan's findings; it is excluded to keep the reported accuracy honest to
deployment.

**Grounded per-type means** (from the 304,356 real findings, the signal the flags
carry): RCE 8.22 · Buffer Overflow 8.02 · SQLi 7.81 · Privilege Escalation 7.79 ·
Directory Traversal 7.28 · DoS 6.84 · XSS 5.90.

**Limitations.** This model gives a *grounded estimate* for risk-ordering, not an
authoritative CVSS: exact-score R²≈0.65 on the deployment population means a CVE
description predicts the exact decimal only moderately-strongly, which is why the
ranking (ρ=0.81) and band (99% within one) figures are the ones to read for its
actual job. Finding text is shorter than CVE text, so predictions skew slightly
conservative (mitigated by the flag/length backbone and the p1-p99 clip). Under a
temporal shift to unseen future CVEs the exact-score R² drops to ~0.45 while the
ordering holds (ρ=0.70), so treat the decimal as a within-band estimate, not a
year-over-year-stable number. The hybrid routes a finding here only when it has no
published score **and** matches one of the seven trained vuln-type classes;
outside those classes it keeps the vector model's curated per-class vector, so
high-severity classes the text model would understate (SSRF, default credentials,
XXE) are never dropped. Like the vector model it is gitignored and distributed
out-of-band.
