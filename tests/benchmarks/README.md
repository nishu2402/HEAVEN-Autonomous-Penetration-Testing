# HEAVEN benchmark suite

Reproducible measurement of HEAVEN's detection rate and false-positive rate
against vulnerable-by-design web apps. Without numbers from this suite,
every "X% accuracy" claim elsewhere in the project is unverifiable.

## What's here

```
tests/benchmarks/
├── README.md                     ← this file
├── docker-compose.yml            ← brings up DVWA at 127.0.0.1:8080
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
- `dvwa_run<N>.md`, per-run markdown report
- `dvwa_run<N>_gt_coverage.csv`, one row per ground-truth entry (detected y/n)
- `dvwa_run<N>_findings.csv`, false-positive analysis
- `dvwa_aggregated.md`, **the headline file** (use this in papers / README)

## How to read a report

Each report includes:

1. **Headline metrics**: precision, recall, F1, scan duration. Recall is computed against `detection_required` entries only; `recall_overall` includes opportunistic targets (stored XSS, file upload, etc.) which not every scanner probes.
2. **Per-category recall**: by SQLi/XSS/cmdi/LFI/CSRF/etc. Shows where the scanner is strong vs. weak.
3. **Missed required vulnerabilities**: every required GT entry the scanner didn't find. Each missed entry is a publication-blocking bug.
4. **Findings without GT match**: either true positives (your ground truth is incomplete: go add them) or false positives (real precision issues).

## Honest caveats: what these numbers don't yet mean

**This benchmark runs AUTHENTICATED.** DVWA's vulnerable endpoints all live
under `/vulnerabilities/*` behind a login, so the fixture logs in as
admin/password and hands the scan a cookie jar (session + `security=low`) via
`heaven scan --cookie-file`. The authenticated crawl reaches the protected
surface and the injection scanner confirms the SQLi / reflected-XSS /
command-injection / LFI there. Run in isolation, HEAVEN detects all of DVWA's
core injection classes on this live target.

**The target runs native, so the numbers reflect the detectors, not the
emulator.** The fixture uses the official multi-arch `ghcr.io/digininja/dvwa`
image with a MariaDB backend. It has a native arm64 build, so on Apple Silicon
it runs directly instead of under QEMU. That matters: the old amd64-only
`vulnerables/web-dvwa` image had to be emulated on arm64, and the emulation's
multi-second timing jitter made time-based blind SQLi indistinguishable from
scheduling noise (and the fragile MySQL/PHP stack would collapse mid-scan).
Running native, request baselines are sub-second and the timing oracle is
stable. The global per-target throttle (`heaven/net/throttle.py`) still paces
the scan so a single small VM's MariaDB is not saturated; this fixture pins a
modest `HEAVEN_THROTTLE_START=8 MAX=16 MIN=2` (via `setdefault`, so your own
`HEAVEN_THROTTLE_*` env still wins).

Measured, authenticated, one run on a 2-CPU colima VM:

| Metric | Result |
|---|---|
| **Recall (detection-required)** | **100%, 10 / 10** |
| Per class | SQLi (error/UNION/**blind-timing**) · reflected XSS ×2 · cmdi ×2 · LFI ×2 · **GET-based CSRF** |
| Opportunistic (not required) also found | 4 / 8 (stored XSS, header-reflected XSS, CSP include, fi-header XSS) |
| Scan duration | ~12.5 min (full `-m web` pipeline, throttled) |

All ten required classes now detect deterministically. Blind-timing SQLi works
because native baselines are stable enough for the differential oracle (single
sleep clears the baseline, doubling the sleep scales the delay). CSRF is caught
because two real gaps were fixed: the crawler now hands the auth scanner the
actual forms it discovered (they were previously dropped, so `_audit_csrf` saw
nothing), and `_audit_csrf` now audits state-changing GET forms (DVWA's low CSRF
submits a password change over GET) while still excluding plain login/search
forms. The detectors are never loosened to inflate the number.

Precision reads low on this fixture (~9%) because the scan also reports DVWA's
real outdated-component / CVE findings and its other tokenless forms, which the
injection-focused ground truth doesn't enumerate. They are true positives
without a GT row, not false positives (see "Findings without GT match" above).

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
between scanners, the rows are stably keyed by `gt_id`.

## Thresholds

`test_dvwa_baseline.py` gates on a **recall floor of 0.9** (`agg.mean_recall`):
against the native target all ten detection-required entries detect (100%), and
the floor locks that in while allowing a single transient miss on a loaded CI
runner rather than flaking. A drop well below it is a real regression, most often
an authenticated-crawl session collapse.

There is deliberately **no precision floor**: precision on this fixture is low by
design (~9%) because HEAVEN also reports DVWA's real CVE / outdated-component
findings and its other tokenless forms, none of which the injection-focused
ground truth enumerates. Those are true positives without a GT row, so a
precision gate here would punish correct extra findings. Precision is asserted
instead on the deterministic native benchmark (`test_native_benchmark.py`), where
the ground truth is complete.
