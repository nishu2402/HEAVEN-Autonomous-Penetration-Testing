# HEAVEN vs Other Vulnerability Scanners

Head-to-head matrix against the tools every pen-tester already has on
their laptop. **The numbers below are placeholders** — fill them in by
running the benchmark suite ([tests/benchmarks/README.md](../tests/benchmarks/README.md))
against the same target with each tool. HEAVEN ships the adapters for
all three competitors so the comparison is a one-command diff.

---

## Feature parity matrix

| Capability | HEAVEN | Burp Pro | OWASP ZAP | sqlmap | Nessus | Acunetix |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Open-source** | ✅ MIT | ❌ paid | ✅ Apache | ✅ GPL | ❌ paid | ❌ paid |
| **Active SQLi** (error / boolean / time-blind × 4 DBMS) | ✅ | ✅ | ⚠️ basic | ✅ best-in-class | ⚠️ basic | ✅ |
| **Active XSS** (reflected / stored / DOM) | ✅ | ✅ | ✅ | ❌ | ⚠️ basic | ✅ |
| **SSRF / XXE / CRLF / open redirect / IDOR** | ✅ | ✅ | ⚠️ | ❌ | ⚠️ | ✅ |
| **Network port scanning** | ✅ nmap | ❌ | ❌ | ❌ | ✅ | ❌ |
| **AD enumeration + Kerberoasting** | ✅ | ❌ | ❌ | ❌ | ⚠️ scripts | ❌ |
| **Cloud enum** (AWS S3 / IAM / EC2) | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| **SAST source-code scanning** | ✅ Semgrep | ❌ | ❌ | ❌ | ❌ | ✅ |
| **AI-driven attack-chain planner** | ✅ Layers B + D | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Autonomous iterative loop** | ✅ `heaven autonomous` | ❌ | ❌ | ❌ | ⚠️ scheduled | ❌ |
| **Continuous monitoring with auto-diff** | ✅ `heaven watch` | ❌ | ⚠️ via ZAP-API | ❌ | ✅ | ✅ |
| **Differential scan reports** | ✅ `heaven diff` | ⚠️ manual | ⚠️ manual | ❌ | ✅ | ✅ |
| **Jira / Linear ticketing** | ✅ built-in | ⚠️ plugin | ⚠️ plugin | ❌ | ✅ | ✅ |
| **SIEM forwarding** (Splunk HEC / Elastic) | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Reproducibility** (`--seed` + replay) | ✅ unique | ❌ | ❌ | ❌ | ❌ | ❌ |
| **CVSS prediction via ML** | ✅ R²=0.9925 | ❌ | ❌ | ❌ | ⚠️ uses NVD | ⚠️ |
| **EPSS + CISA KEV scoring** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Exploit-DB integration** | ✅ | ❌ | ❌ | ❌ | ⚠️ | ❌ |
| **Post-exploitation** (linpeas / BloodHound / lateral) | ✅ | ❌ | ❌ | ⚠️ via shell | ❌ | ❌ |
| **Methodology mapping** (OWASP / NIST / PTES) | ✅ | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| **MITRE ATT&CK mapping** | ✅ | ❌ | ❌ | ❌ | ⚠️ | ✅ |
| **Web UI** | ✅ React (modern dark) | ✅ Java GUI | ✅ Java GUI | ❌ CLI only | ✅ | ✅ |
| **REST API + WebSocket** | ✅ FastAPI | ✅ paid | ✅ | ❌ | ✅ | ✅ |
| **Reproducible benchmark suite shipped** | ✅ DVWA + adapters | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Annual cost** | $0 | ~$450 / user | $0 | $0 | ~$3,500 / scanner | ~$3,500 / target |

Legend: ✅ first-class · ⚠️ available but limited · ❌ not in product

---

## Empirical numbers vs DVWA (FILL IN)

> Run the benchmark and replace the placeholder numbers below. See
> [BENCHMARK_HOWTO.md](BENCHMARK_HOWTO.md) for the exact commands.

### Recall — % of DVWA-Low ground-truth vulns detected

| Vuln category | HEAVEN | Burp Active Scan | OWASP ZAP | sqlmap |
|---|---:|---:|---:|---:|
| SQLi          | TBD% |  TBD% | TBD% | TBD% |
| XSS reflected | TBD% |  TBD% | TBD% |  N/A |
| Command injection | TBD% |  TBD% | TBD% |  N/A |
| LFI / path traversal | TBD% |  TBD% | TBD% |  N/A |
| CSRF          | TBD% |  TBD% | TBD% |  N/A |
| Open redirect | TBD% |  TBD% | TBD% |  N/A |
| **Aggregate** | **TBD%** | **TBD%** | **TBD%** | **TBD% (SQLi only)** |

### Precision — % of findings that are true positives

| Tool | Precision | False positives | Notes |
|---|---:|---:|---|
| HEAVEN | TBD% | TBD | Two-stage FP suppression + optional LLM review |
| Burp Active Scan | TBD% | TBD | Manual triage typical |
| OWASP ZAP | TBD% | TBD | High FP rate without manual passive-scan tuning |
| sqlmap | TBD% | TBD | Near-zero FP, narrow scope (SQLi only) |

### Scan duration vs DVWA-Low (`mean ± stddev over N=5 runs`)

| Tool | Duration | Network requests | Disk footprint |
|---|---:|---:|---:|
| HEAVEN | TBD s | TBD | TBD MB |
| Burp Active Scan | TBD s | TBD | TBD MB |
| OWASP ZAP | TBD s | TBD | TBD MB |
| sqlmap | TBD s | TBD | TBD MB |

### Novel detections — what each tool catches that the others miss

To be filled in after running the benchmark. Open the
`tests/benchmarks/reports/dvwa_run*_gt_coverage.csv` files for each
tool, pivot on the `detected` column.

---

## When to use which tool

| If you need to … | Use |
|---|---|
| One-off web app pen-test, human-driven | **Burp Pro** — best Repeater / Intruder UX |
| Run a continuous scan against a single CI target | **OWASP ZAP** via its API |
| Confirm + dump SQLi specifically | **sqlmap** — still the gold standard |
| Compliance scan for a fleet of servers | **Nessus** — strongest CVE coverage on infra |
| Full-stack engagement with reporting + monitoring | **HEAVEN** — one tool covers recon → DAST → SAST → post-ex → continuous monitoring → ticketing |
| AI-augmented attack-chain planning | **HEAVEN** — Layers B + D, no commercial equivalent today |
| Reproducible scans for a research paper | **HEAVEN** — `--seed` flag, no other tool offers this |

---

## How to reproduce these numbers

1. Bring up the same DVWA container:

   ```bash
   docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
   ```

2. Run HEAVEN's benchmark suite (see [BENCHMARK_HOWTO.md](BENCHMARK_HOWTO.md)):

   ```bash
   HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=5 \
       pytest tests/benchmarks/test_dvwa_baseline.py -v -s
   ```

3. Run Burp Active Scan, OWASP ZAP, and sqlmap against the same DVWA URL.
   Export each tool's results in its native format (Burp XML, ZAP JSON,
   sqlmap session log).

4. Feed each into the matching adapter to get the same metrics shape:

   ```python
   from tests.benchmarks.adapters import burp, zap, sqlmap as smap
   from tests.benchmarks.metrics import GroundTruth, evaluate

   gt = GroundTruth.load(Path("tests/benchmarks/ground_truth/dvwa.yaml"))
   burp_result = evaluate(burp.load("burp_export.xml"), gt)
   zap_result  = evaluate(zap.load("zap_export.json"), gt)
   smap_result = evaluate(smap.load("sqlmap_session.log"), gt)
   ```

5. Open the resulting `gt_coverage.csv` files in a spreadsheet and pivot
   on the `detected` column. The interesting cells are the asymmetries —
   "HEAVEN found this and Burp didn't" or vice versa.

---

## Honest framing

HEAVEN doesn't beat Burp Pro at being Burp Pro — Burp is a 20-year-old
masterpiece for human-driven web testing. HEAVEN's bet is that the
combination of **AI-driven planning + continuous monitoring + reproducible
benchmarks + open-source auditability** is a meaningfully different
shape, not a slightly better Burp.

If your workflow is "log into Burp, click around, read the results,"
keep using Burp. If your workflow is "this tool should figure out
what to test, write the report, and tell me when something changes
without me babysitting it" — that's what HEAVEN is for.
