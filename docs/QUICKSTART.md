# HEAVEN — 5-minute Quick Start

Goal: scan your first target and view the report. No production setup
required.

> **Authorization:** every command below assumes you have written
> authorization for the target. The `--i-have-authorization` flag is
> required because scanning systems you don't own is illegal almost
> everywhere. Use the localhost or a deliberately-vulnerable target
> (DVWA, Juice Shop) for evaluation.

---

## 1 · Install (60 seconds)

```bash
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing
cd HEAVEN-Autonomous-Penetration-Testing
./install.sh          # creates venv, installs deps, builds React UI
```

---

## 2 · First scan (30 seconds)

Spin up a deliberately-vulnerable target:

```bash
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```

Wait ~10 seconds for it to boot, then scan it:

```bash
heaven scan -u http://localhost:8080 -m web --i-have-authorization
```

You'll see a live HUD with phase progress, severity counts, and a
streaming findings table. The scan completes in ~30 seconds against
DVWA's public surface.

---

## 3 · Persist findings into an engagement (30 seconds)

Engagements are SQLite-backed projects that aggregate scans, findings,
and operator notes:

```bash
heaven engage init my-first-pentest --client "Personal" --sow "evaluation"
heaven scope add http://localhost:8080 --kind url --engagement my-first-pentest
heaven scan -u http://localhost:8080 -m web \
    --engagement my-first-pentest \
    --i-have-authorization
```

List findings:

```bash
heaven findings --engagement my-first-pentest
heaven findings --engagement my-first-pentest --severity high
heaven show <finding-id>          # full evidence + curl repro
```

---

## 4 · Launch the Web UI (30 seconds)

```bash
heaven serve
```

Open <http://localhost:8443> and log in with:

- Username: `admin`
- Password: `admin` on a fresh install — the UI then forces a password change
  on first login. Set `HEAVEN_ADMIN_PASSWORD` beforehand to use a strong
  password from the start and skip the prompt.

You'll see 19 pages:

| Page | What it does |
|---|---|
| Dashboard | Severity distribution, MITRE coverage heat-map |
| Scans | Launch + history + live progress + ↻ Replay button |
| Findings | Filter by severity / confidence / status |
| Watch | Continuous-monitoring iterations + alert channels |
| Scan Diff | Pick two scans → bucketed new / resolved / regressed view |
| SAST | Semgrep launcher + results |
| Autonomous | LLM-driven iterative pen-test loop |
| AI Plans | Multi-step attack-chain reasoner |
| Coverage | Self-grading — "what didn't we test?" |
| Methodology | OWASP / NIST / PTES mapping viewer |
| Benchmark | Latest DVWA precision / recall / F1 |
| … + 8 more |

---

## 5 · Run the benchmark to see numbers (5 minutes, Docker required)

This produces the actual precision / recall / F1 numbers your README
references:

```bash
HEAVEN_RUN_BENCHMARKS=1 HEAVEN_BENCH_RUNS=3 \
    pytest tests/benchmarks/test_dvwa_baseline.py -v -s
```

Results land in `tests/benchmarks/reports/dvwa_aggregated.md`. Commit it
so the README's benchmark badge has a target to link to.

---

## What to do next

| You want to … | Read |
|---|---|
| Set up production HEAVEN | [README — Installation (Detailed)](../README.md#installation-detailed) |
| Add an LLM to the AI layer | Set `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` and re-run any scan |
| Continuously monitor a target | [README — Continuous Monitoring](../README.md#continuous-monitoring) |
| Compare HEAVEN vs Burp / ZAP / sqlmap | [COMPARISON.md](COMPARISON.md) |
| Record a demo video | [DEMO.md](DEMO.md) |
| Contribute code | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Report a vulnerability in HEAVEN | [SECURITY.md](../SECURITY.md) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `heaven: command not found` | `pip install -e .` from the repo root, or open a new shell so `~/.local/bin` is on PATH |
| `nmap: command not found` | `brew install nmap` (macOS) / `apt install nmap` (Linux) — HEAVEN degrades gracefully but coverage drops |
| Web UI shows blank page | `cd heaven-ui && npm install && npm run build` |
| `HEAVEN_ADMIN_PASSWORD not set` warning | Run `heaven init` for an interactive setup, or `export HEAVEN_ADMIN_PASSWORD=…` |
| Scan exits "Authorization required" | Add `--i-have-authorization` flag (mandatory and intentional) |
