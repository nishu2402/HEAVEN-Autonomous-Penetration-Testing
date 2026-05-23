# HEAVEN benchmark suite

Reproducible measurement of HEAVEN's detection rate and false-positive rate
against vulnerable-by-design web apps. Without numbers from this suite,
every "X% accuracy" claim elsewhere in the project is unverifiable.

## What's here

```
tests/benchmarks/
├── README.md                     ← this file
├── docker-compose.yml            ← brings up DVWA at localhost:8080
├── conftest.py                   ← pytest fixtures (Docker, ground-truth loader)
├── metrics.py                    ← scanner-agnostic precision/recall/F1
├── ground_truth/
│   └── dvwa.yaml                 ← labeled vulns in DVWA v1.10 (low + medium)
├── reporters/
│   ├── markdown_report.py        ← publication-style markdown
│   └── comparison_csv.py         ← head-to-head CSV for Burp/ZAP comparison
├── test_metrics.py               ← unit tests (run in normal CI, no Docker)
├── test_dvwa_baseline.py         ← the actual DVWA benchmark
└── reports/                      ← per-run outputs (gitignored)
```

## Run it

```bash
# Unit-test the metrics math (fast, no Docker, runs in regular CI):
pytest tests/benchmarks/test_metrics.py -v

# Full DVWA benchmark (needs Docker, ~5 min):
HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_dvwa_baseline.py -v -s

# Multi-run for mean ± stddev (publication numbers):
HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=5 \
  pytest tests/benchmarks/test_dvwa_baseline.py -v -s
```

Outputs land in `tests/benchmarks/reports/`:
- `dvwa_run<N>.md` — per-run markdown report
- `dvwa_run<N>_gt_coverage.csv` — one row per ground-truth entry (detected y/n)
- `dvwa_run<N>_findings.csv` — false-positive analysis
- `dvwa_aggregated.md` — **the headline file** (use this in papers / README)

## How to read a report

Each report includes:

1. **Headline metrics** — precision, recall, F1, scan duration. Recall is computed against `detection_required` entries only; `recall_overall` includes opportunistic targets (stored XSS, file upload, etc.) which not every scanner probes.
2. **Per-category recall** — by SQLi/XSS/cmdi/LFI/CSRF/etc. Shows where the scanner is strong vs. weak.
3. **Missed required vulnerabilities** — every required GT entry the scanner didn't find. Each missed entry is a publication-blocking bug.
4. **Findings without GT match** — either true positives (your ground truth is incomplete — go add them) or false positives (real precision issues).

## Honest caveats — what these numbers don't yet mean

**The current DVWA recall ceiling is structural.** HEAVEN does not yet
support authenticated scanning. DVWA's vulnerable endpoints all live
under `/vulnerabilities/*` which require a logged-in session, so the
unauthenticated scan only exercises the small public surface
(`/login.php`, `/setup.php`, the index page, `robots.txt`).

Expect baseline recall in the single digits until **HEAVEN gains a
`--cookie-file` or `--session` flag** on `heaven scan`. That's the #1
unblock — every other detection improvement is bottlenecked on it.

Other known caveats:

- The benchmark CSVs are formatted for direct comparison with Burp Scanner
  XML and OWASP ZAP JSON exports, but the import adapters for those tools
  are **not** in this repo yet. Until then, you can manually copy other
  scanners' findings into the same `findings_<scanner>.csv` shape.
- The DVWA ground truth covers **low** and **medium** difficulty only;
  `high` is intentionally hardened (real-world-ish defences); `impossible`
  should yield zero findings (if HEAVEN flags one, that's a high-confidence
  false positive worth investigating).
- Stored XSS, file upload, and brute-force entries are marked
  `detection_required: false` because they require multi-step interactions
  most unauthenticated scanners can't drive. They still appear in
  `recall_overall`.

## Adding a new target app

1. Create `ground_truth/<app>.yaml` following the schema documented in
   `tests/benchmarks/__init__.py`.
2. Add a `<app>` service to `docker-compose.yml`.
3. Copy `test_dvwa_baseline.py` to `test_<app>_baseline.py`, replace the
   fixture, retarget the URL.
4. Run; the same metrics + reporters work unchanged.

Suggested next targets: **OWASP Juice Shop** (Node SPA, no-auth surface,
ideal for the current HEAVEN), **VAmPI** (OWASP API Top 10), **WebGoat**
(Java, lesson-based, covers obscure classes).

## Head-to-head with other scanners

The metrics layer is intentionally scanner-agnostic. To benchmark Burp /
ZAP / sqlmap against the same ground truth:

```python
from tests.benchmarks.metrics import Finding, GroundTruth, evaluate

# Write an adapter that turns the other scanner's output into list[Finding]
def burp_to_findings(burp_xml: str) -> list[Finding]:
    ...

gt = GroundTruth.load(Path("tests/benchmarks/ground_truth/dvwa.yaml"))
result = evaluate(burp_to_findings(open("burp.xml").read()), gt)
```

Then write the result with the same reporters and diff `gt_coverage.csv`
between scanners — the rows are stably keyed by `gt_id`.

## Tightening thresholds

`test_dvwa_baseline.py` ships with **no assertions** on precision/recall —
only "scan completed without crashing." This is deliberate: until HEAVEN
has auth support and we've calibrated, hard thresholds would either be
trivially met (1 finding = pass) or constantly broken.

When you're ready to gate releases on benchmark numbers:

```python
# At the end of test_heaven_vs_dvwa_baseline:
assert agg.mean_recall >= 0.40, f"Recall regressed: {agg.mean_recall:.1%}"
assert agg.mean_precision >= 0.70, f"Precision regressed: {agg.mean_precision:.1%}"
```

Pick numbers from the most recent passing aggregated run as the floor.
