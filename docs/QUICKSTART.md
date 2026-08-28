# HEAVEN: 5-minute Quick Start

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
./scripts/install.sh  # creates venv, installs deps, builds React UI
```

---

## 2 · First scan (30 seconds)

Spin up a deliberately-vulnerable target (the official DVWA image plus a
MariaDB backend, which runs native on Apple Silicon and x86 rather than under
emulation):

```bash
docker compose -f tests/benchmarks/docker-compose.yml up -d
```

Give it ~20 seconds to boot, then open http://127.0.0.1:8080/setup.php once and
click "Create / Reset Database". Now scan it:

```bash
heaven scan -u http://127.0.0.1:8080 -m web --i-have-authorization
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
heaven use my-first-pentest          # make it active, no more --engagement
heaven scope add http://127.0.0.1:8080 --kind url
heaven scan -u http://127.0.0.1:8080 -m web --i-have-authorization
```

`heaven use` sets a git-branch-style sticky context, so every following
command targets that engagement automatically. Run `heaven use` with no
argument to see the current selection, or `heaven use --clear` to reset.

List findings:

```bash
heaven findings                       # uses the active engagement
heaven findings --severity high
heaven show <finding-id>              # full evidence + curl repro
```

---

## 4 · Launch the Web UI (30 seconds)

```bash
heaven serve
```

This **opens <http://localhost:8443> in your browser automatically** once the
server is ready (use `heaven serve --no-open` to suppress that). Log in with:

- Username: `admin`
- Password: `admin` on a fresh install, the UI then forces a password change
  on first login. Set `HEAVEN_ADMIN_PASSWORD` beforehand to use a strong
  password from the start and skip the prompt.

You'll see 25 pages:

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
| Coverage | Self-grading, "what didn't we test?" |
| Methodology | OWASP / NIST / PTES mapping viewer |
| Benchmark | Latest DVWA precision / recall / F1 |
| … + 14 more |

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
| Set up production HEAVEN | [README: Quick Start](../README.md#quick-start) |
| Add an LLM to the AI layer | `pip install -e ".[gemini]"`, set `GEMINI_API_KEY` (or Anthropic/OpenAI), re-run. Full guide: [README: API Keys](../README.md#api-keys) |
| Continuously monitor a target | [README, CLI Reference (`watch`)](../README.md#cli) |
| Compare HEAVEN vs Burp / ZAP / sqlmap | [COMPARISON.md](COMPARISON.md) |
| Contribute code | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Report a vulnerability in HEAVEN | [SECURITY.md](../SECURITY.md) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `heaven: command not found` | `pip install -e .` from the repo root, or open a new shell so `~/.local/bin` is on PATH |
| A scanner tool shows "missing" (`nmap`, `sqlmap`, `ffuf`, `searchsploit`, `semgrep`) | `heaven install-tools`, installs them all with your package manager (idempotent). HEAVEN still runs without them, just at reduced power |
| Web UI shows blank page | `cd heaven-ui && npm install && npm run build` |
| `HEAVEN_ADMIN_PASSWORD not set` warning | Run `heaven init` for an interactive setup, or `export HEAVEN_ADMIN_PASSWORD=…` |
| Scan exits "Authorization required" | Add `--i-have-authorization` flag (mandatory and intentional) |
| Not sure what's wired up | Run `heaven doctor`, shows LLM / SIEM / tickets / tool / engagement state |
