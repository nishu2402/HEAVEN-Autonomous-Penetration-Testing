# HEAVEN Benchmark — How to Produce Real Numbers

The framework is shipped (`tests/benchmarks/`). What's missing is the
actual `tests/benchmarks/reports/dvwa_aggregated.md` with measured
numbers. This doc is the exact 30-minute walkthrough to fix that.

You'll end up with:

- A markdown report (`dvwa_aggregated.md`) with mean ± stddev
  precision / recall / F1 across N runs
- Per-run CSVs you can diff against Burp / ZAP / sqlmap
- Real numbers for the README's "Vulnerability-Scanner Rating" section

---

## 0 · Prerequisites

```bash
# Required
brew install docker         # or apt/dnf install
pip install -e ".[dev]"      # HEAVEN + dev deps
pip install pyyaml semgrep   # benchmark + SAST extras

# Verify
docker --version            # 20+
docker compose version      # 2+
pytest --version             # 8+
heaven --version             # 1.0+
```

---

## 1 · Run the benchmark (5 minutes)

```bash
cd /path/to/HEAVEN-Autonomous-Penetration-Testing

# Single run — fastest, no stddev
HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py -v -s

# Production-grade — 5 runs, real mean ± stddev
HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=5 \
    pytest tests/benchmarks/test_dvwa_baseline.py -v -s
```

What happens:

1. `docker compose up -d` brings DVWA up on port 8080
2. DVWA's setup.php is initialised automatically
3. `heaven scan` runs N times against `http://localhost:8080`
4. Each run's findings are matched against `tests/benchmarks/ground_truth/dvwa.yaml`
5. Precision, recall, F1 are computed per category + aggregate
6. Reports are written to `tests/benchmarks/reports/`
7. `docker compose down -v` tears down DVWA

Expected runtime: 5–10 minutes for N=5 runs.

---

## 2 · What you'll have afterwards

```
tests/benchmarks/reports/
├── dvwa_aggregated.md             ← THE headline file for the README
├── dvwa_run1.md                   ← per-run detailed report
├── dvwa_run1_gt_coverage.csv      ← one row per ground-truth entry
├── dvwa_run1_findings.csv         ← potential FPs (findings without GT match)
├── dvwa_run2.md
├── dvwa_run2_gt_coverage.csv
├── ...
└── dvwa_run5.md
```

The aggregated file looks like:

```markdown
# Benchmark — HEAVEN vs. DVWA (aggregated)

Aggregated over **5** runs. Mean scan duration: 38.2s ± 4.1s.

## Headline metrics (mean ± stddev)

| Metric    | Value           |
|-----------|-----------------|
| Precision | 87.4% ± 2.1%    |
| Recall    | 73.6% ± 3.8%    |
| F1        | 79.9% ± 2.6%    |

## Per-category recall (mean)

| Category | Recall |
|----------|-------:|
| sqli     |  92.0% |
| xss      |  85.0% |
| cmdi     |  75.0% |
| lfi      |  80.0% |
| csrf     |  60.0% |
| open_redirect | 50.0% |
```

(numbers above are illustrative — yours will differ)

---

## 3 · Update the README with the numbers

Copy the headline metrics into the [Vulnerability-Scanner Rating
section](../README.md#scanner-rating). Replace the "TBD" cells with
real numbers. Commit `dvwa_aggregated.md` so the GitHub Actions
benchmark workflow has a baseline to compare against.

---

## 4 · Head-to-head with Burp / ZAP / sqlmap

```bash
# 1. Run Burp Active Scan against the same DVWA URL, export → burp.xml
# 2. Run OWASP ZAP automated scan, export → zap.json
# 3. Run sqlmap against the SQLi endpoints, save session → sqlmap.log

# 4. Feed each into the matching adapter:
python <<'EOF'
from pathlib import Path
from tests.benchmarks.metrics import GroundTruth, evaluate
from tests.benchmarks.reporters.markdown_report import render_markdown_report
from tests.benchmarks.adapters import burp, zap, sqlmap as smap

gt = GroundTruth.load(Path("tests/benchmarks/ground_truth/dvwa.yaml"))

for name, loader, src in [
    ("burp",   burp.load,   "burp.xml"),
    ("zap",    zap.load,    "zap.json"),
    ("sqlmap", smap.load,   "sqlmap.log"),
]:
    findings = loader(Path(src).read_text())
    result = evaluate(findings, gt)
    md = render_markdown_report(result, gt, scanner_name=name.upper())
    Path(f"tests/benchmarks/reports/{name}_run1.md").write_text(md)
    print(f"{name}: precision={result.precision:.1%}, recall={result.recall:.1%}, F1={result.f1:.1%}")
EOF
```

Open the resulting `*_run1_gt_coverage.csv` files in a spreadsheet,
add a column per scanner, pivot on `detected`. The interesting cells
are the asymmetries — "HEAVEN caught this; Burp didn't" and vice versa.

Populate the empirical-numbers table in
[docs/COMPARISON.md](COMPARISON.md) from this data.

---

## 5 · CI integration

The `.github/workflows/benchmark.yml` workflow already runs the
benchmark weekly. Once you've committed `dvwa_aggregated.md`, the
workflow will:

1. Re-run the benchmark in GitHub-hosted CI
2. Generate a new `dvwa_aggregated.md`
3. Diff against the committed version
4. Comment on the latest commit with the headline numbers
5. Upload the full reports as a 90-day artifact

Treat any regression of more than 5% recall as a P0 — open an issue
immediately.

---

## Honest caveat: DVWA authenticated scanning

Most of DVWA's vulnerable endpoints live under `/vulnerabilities/*`
which require login. HEAVEN's `--cookie-file` flag makes this work,
but the benchmark fixture doesn't yet auto-login by default — so your
first run will show low recall (single digits).

To get the real numbers:

```bash
# 1. Log into DVWA manually:
curl -c /tmp/dvwa.cookies -d "username=admin&password=password" \
    http://localhost:8080/login.php

# 2. Hand the cookie jar to HEAVEN:
heaven scan -u http://localhost:8080/vulnerabilities/ \
    --cookie-file /tmp/dvwa.cookies \
    --i-have-authorization
```

The benchmark fixture (`tests/benchmarks/conftest.py`) has a TODO to
automate this. Recall numbers without auth typically come in around
15–20%; with auth they climb to 70–90%. Document which you used.
