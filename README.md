# HEAVEN

**A modular vulnerability-discovery and engagement-management platform for authorized security testing.**

HEAVEN is a Python-based scanning framework for working pentesters. It combines async reconnaissance, common-class vulnerability detection (with second-stage false-positive suppression), MITRE ATT&CK + Cyber Kill Chain mapping, and an engagement workflow (scope, deduplication, status tracking, evidence packages) into a single CLI + REST API.

It is *not* a replacement for a human pentester. It is a tool that handles the repetitive parts of a workflow so you can spend your time on the parts that actually require judgement — scope decisions, business logic, exploit chaining, and writing the report.

---

## Where HEAVEN fits in your toolkit

If you've been doing this for ten years you already have a toolkit you trust. Here's an honest position vs. that toolkit:

| Job | Best-in-class tool | What HEAVEN does instead |
|---|---|---|
| Web app testing | **Burp Suite Pro** | HEAVEN flags candidates and produces curl reproductions; you pivot into Burp for manual exploitation. HEAVEN is not a replacement, it's a triage front-end. |
| Network vuln scanning | **Nessus / OpenVAS** | HEAVEN runs lighter scans suitable for a single engagement. Nessus is still better for the full-CVE breadth on internal infra. |
| Templated detection | **Nuclei** | HEAVEN actually shells out to Nuclei. The added value is the orchestration, the FP suppression layer, and the engagement DB. |
| AD recon | **BloodHound + impacket** | HEAVEN's `ad_scanner` does inventory + roastable accounts + delegation checks. For graph-based path finding you still want BloodHound. |
| Exploitation | **Metasploit / sqlmap / etc.** | HEAVEN does **not** exploit. It finds, validates, and reports. Exploitation is on you. |
| Engagement management | Notes app, spreadsheet | This is where HEAVEN earns its place. Per-engagement DB, scope file, finding deduplication across re-scans, status tracking, evidence packages with copy-paste repro. |

The pitch: **HEAVEN handles "find + triage + dedupe + organize"; your existing tools handle "exploit + validate manually + write the final report."** It's the connective tissue between recon and the per-finding deep dive you're going to do anyway.

---

## What you get

- **Async scan engine.** Web crawler, network scanner (nmap wrapper), JS endpoint extraction, secret pattern matching, DNS/subdomain enumeration. Per-segment concurrency caps.
- **Common-class detection with FP suppression.** SQLi (boolean / error / time-based), XSS (with canary reflection check), SSRF (response + OOB), SSTI, XXE, open-redirect, CRLF, JWT none-alg, JWT weak-secret. Every candidate is re-tested against measured baseline noise before reaching the report. Findings carry `confidence` and a bucket (`strong / high / medium / low / discarded`).
- **CVE / EPSS / KEV enrichment.** NVD lookup with optional API key, EPSS scores joined in, CISA KEV flag.
- **MITRE ATT&CK + Lockheed Cyber Kill Chain mapping.** Per-finding technique + tactic, per-engagement coverage report and Mermaid diagram.
- **Engagement DB.** SQLite per engagement, holds scope, scans, findings (deduplicated across re-scans), operator notes, status. Designed to be one file you put in your engagement folder.
- **Evidence package per finding.** Request, response excerpt, copy-paste curl command, repro steps, remediation, MITRE mapping. Renders to Markdown / CSV / JSON / SARIF.
- **REST API + WebSocket** for live scan progress and real-time log streaming. JWT/RBAC auth, rate limited, audit logged.
- **Self-test / accuracy mode.** Run against OWASP Juice Shop / DVWA / VAmPI / WebGoat fixtures and compute precision / recall / F1. This is how accuracy is *measured* — not claimed.

---

## What you don't get

- No reverse shells, payload delivery, persistence, or C2.
- No autonomous exploit chaining.
- No "click here to exploit this" buttons in the UI.
- No fake confidence numbers ("99% accurate" is not a number you'll find in this codebase).

If you need any of the above for an engagement, you have other tools for it. HEAVEN's job ends at finding and reporting.

---

## Status — honest per-module assessment

| Module | Status | Notes |
|---|---|---|
| `main.py`, `orchestrator.py`, `config.py`, `api/server.py` | **Solid** | Tested, hardened, auth + rate-limit wired |
| `engagement.py`, `devsecops/evidence.py` | **Solid** | New; full test coverage |
| `recon/network_scanner.py`, `recon/web_crawler.py` | **Solid** | Backed by nmap + aiohttp |
| `vulnscan/safe_validator.py` + `fp_suppress.py` | **Solid** | SQLi/XSS/SSRF probes with FP suppression layer |
| `vulnscan/cve_mapper.py` | **Solid** | NVD + EPSS; needs API key for full rate limit |
| `mitre/attack_mapper.py`, `mitre/kill_chain.py` | **Solid** | ATT&CK + Lockheed phase mapping |
| `security/auth.py`, `security/audit.py`, `security/vault.py` | **Solid** | RBAC, audit log, AES-256-GCM vault |
| `recon/ad_scanner.py` | **Working but rough** | Needs domain creds + impacket setup. See `docs/runbooks/ad_lab.md` |
| `recon/iot_scanner.py` | **Working but rough** | Modbus/MQTT/BACnet probes. Needs real OT/SCADA hardware to validate. Treat as candidate-only. |
| `vulnscan/zeroday_engine.py` | **Working but rough** | Heuristic fuzzing. High FP rate by definition; calibrate confidence threshold for your environment. |
| `ml/risk_model.py` | **Working but synthetic data** | Model trains and scores; training set is synthetic. See `docs/runbooks/ml_training.md` for the real-data pipeline. |
| `recon/wireless_recon.py` | **Scaffolded** | Needs root + monitor-mode interface; won't run in containers |
| `recon/cloud_enum.py` | **Partial** | AWS path is solid; GCP/Azure are stubs |
| `db/connection.py` + Alembic migrations | **Solid** | Async asyncpg; bootstrap migration provided |
| `heaven-ui/` (React frontend) | **Outdated** | Pre-dates the new auth API. See `docs/runbooks/frontend_audit.md` |

---

## Quick start

```bash
git clone <repo>
cd heaven
./install.sh                    # creates venv, installs deps, optional Postgres setup

export HEAVEN_ADMIN_PASSWORD='<choose-strong>'
export HEAVEN_DB_PASSWORD='<choose-strong>'

heaven --version                # smoke check
heaven self-audit               # baseline security score
```

For a one-off scan with no engagement tracking:

```bash
heaven scan -u https://app.example.com -m web --i-have-authorization \
    --output-file findings.json
```

---

## The pentester workflow (engagement-mode)

This is what differentiates HEAVEN from "just another scanner". One engagement = one SQLite DB file. Findings dedupe across re-scans, status persists, scope is enforced.

### 1. Initialize an engagement

```bash
heaven engage init acme-q2 --client "ACME Corp" --sow "SOW-2026-001"
# Engagement initialised: engagements/acme-q2.db
# Set HEAVEN_ENGAGEMENT=engagements/acme-q2.db in your shell to use it by default.

export HEAVEN_ENGAGEMENT=engagements/acme-q2.db
```

### 2. Define scope

```bash
# One target at a time
heaven scope add api.acme.example --kind host
heaven scope add 10.0.0.0/24 --kind cidr
heaven scope add https://app.acme.example --kind url

# Or import from a scope file (one target per line, # for comments)
heaven scope import engagement-scope.txt

heaven scope list
#   ✓ 10.0.0.0/24                              (cidr)
#   ✓ api.acme.example                         (host)
#   ✓ https://app.acme.example                 (url)
```

### 3. Scan — scope is enforced

```bash
heaven scan \
    -u https://app.acme.example \
    -t 10.0.0.5 \
    -t out.of.scope.example \
    --engagement acme-q2 \
    --i-have-authorization

# Targets dropped (not in engagement scope):
#   - out.of.scope.example
#
# Scan completed in 14s
#   Tasks: 22/22 (failed: 0)
#   Persisted to engagement: 7 findings into engagements/acme-q2.db
```

### 4. Triage

```bash
# List by severity
heaven findings --severity critical

#   CRIT a359e73e4297db5a  conf=0.94  sqli   api.acme.example  open
#   CRIT 7b1f3c9a8d2e4f5a  conf=0.91  ssrf   api.acme.example  open

# Show full evidence for a single finding (request, response, repro, remediation)
heaven show a359e73e4297db5a

# Get the curl command to manually verify in your terminal / Burp
heaven replay a359e73e4297db5a
#   curl -X POST -i --max-time 30 --data 'id='"'"' OR 1=1--' https://app.acme.example/login

# After confirming in Burp, mark verified
heaven mark a359e73e4297db5a verified --notes "confirmed via burp, dumps users table"

# Mark a false positive
heaven mark 7b1f3c9a8d2e4f5a false_positive --notes "WAF blocks payload, not actually exploitable"
```

### 5. Re-scan — dedup, no duplicate findings

```bash
heaven scan -u https://app.acme.example --engagement acme-q2 --i-have-authorization

# Same SQLi gets seen_count++ but stays in your "verified" status
# New findings get inserted as "open"
# Operator notes are preserved across re-scans
```

### 6. Coverage analysis

```bash
heaven kill-chain
#
# Cyber Kill Chain Coverage: 71/100  (5/7 phases)
#
#   Reconnaissance               4 finding(s)
#   Weaponization                2 finding(s)
#   Delivery                     0 finding(s)
#   Exploitation                 3 finding(s)
#   Installation                 0 finding(s)
#   Command & Control            1 finding(s)
#   Actions on Objectives        2 finding(s)
#
# Attacker workflow if these findings are chained:
#   → [Reconnaissance] Exposed admin panel at /admin (high)
#   → [Weaponization] Outdated Apache 2.4.49 (medium)
#   → [Exploitation] SQL injection in /login id parameter (critical)
#   → [Command & Control] Exposed phpMyAdmin (high)
#   → [Actions on Objectives] Public S3 bucket with backups (critical)
```

### 7. Export

```bash
# Markdown — drop straight into your final report
heaven export -o report.md --format markdown --severity high

# CSV — import into Jira / spreadsheet
heaven export -o findings.csv --format csv

# SARIF — for code-scanning dashboards
heaven export -o findings.sarif --format sarif

# JSON — pipe into your own tooling
heaven export -o findings.json --format json --status verified

# Burp Suite — load into Burp's Site Map for manual replay in Repeater
heaven export -o findings.xml --format burp
# In Burp: File → Import → Items → findings.xml

# mitmproxy / Caido JSONL — full request/response per line
heaven export -o findings.jsonl --format proxy-jsonl
```

### 8. Resume an interrupted scan

If your scan dies mid-run (network, ctrl-C, machine reboot), the engagement DB
holds checkpoints for every completed task. Pick up where it left off:

```bash
heaven resume --engagement acme-q2 --i-have-authorization
# Resuming most recent unfinished scan: a3b1c4d5
# Tasks already completed: 14 (skipped on resume)
# ...continues from task 15
```

### 9. Web UI

```bash
heaven serve
# → http://localhost:8443
```

The web UI includes:
- Login screen (uses `HEAVEN_ADMIN_PASSWORD`)
- Engagement-scoped dashboard with severity / status breakdown
- Findings page with filters (severity, status, target, min-confidence)
- Per-finding detail view with full evidence package, copy-paste curl, and status workflow buttons
- Kill chain coverage page with Mermaid-rendered phase diagram and attack path
- Live log terminal (WebSocket-streamed orchestrator logs)
- Scans tracker (auto-refreshes every 10s)

The UI is **read-and-triage only.** Scans must be launched from the CLI — that's where the authorization gate is enforced. The UI lets you mark findings as verified / false-positive / accepted-risk and read evidence packages, but it deliberately can't add scope or kick off scans.

### 10. Engagement summary

```bash
heaven engage status

# Engagement: acme-q2
# Client: ACME Corp
# Targets in scope: 4
# Scans run: 3
# Total findings: 12
#
# By severity:
#   critical  : 2
#   high      : 4
#   medium    : 5
#   low       : 1
#
# By status:
#   open              : 7
#   verified          : 4
#   false_positive    : 1
```

---

## CLI command reference

```
heaven <command> [options]

Engagement workflow:
  engage init NAME [--client] [--sow]    Initialize a new engagement
  engage status                          Show engagement summary
  scope add TARGET [--kind] [--notes]    Add a target to scope
  scope import FILE                      Bulk import from file
  scope list [--all]                     List in-scope (or all) targets
  scope remove TARGET                    Remove a target

Scanning:
  scan [-t TARGET] [-u URL] [-m MODE] [--engagement]
       [--i-have-authorization]          Run a scan, optionally into an engagement DB
  resume --engagement [--scan-id]
       [--i-have-authorization]          Resume an interrupted scan from checkpoints
  schedule INTERVAL_MIN -t TARGET        Continuous monitoring scans

Findings:
  findings [filters]                     List findings (severity/status/target/min-confidence)
  show ID                                Full details + repro for one finding
  replay ID                              Print only the curl command for manual repro
  mark ID STATUS [--notes]               Update finding status
                                         (open/verified/false_positive/accepted_risk/fixed)

Reporting:
  export -o FILE --format FMT [filters]  Export findings:
                                           markdown      → operator report w/ curl repros
                                           csv           → Jira / spreadsheet
                                           json          → raw findings + evidence
                                           sarif         → code-scanning dashboards
                                           burp          → Burp Suite Items XML
                                           proxy-jsonl   → mitmproxy / Caido replay
  kill-chain [--output FILE]             Cyber Kill Chain coverage report
  mitre-report [--output FILE]           MITRE ATT&CK Navigator JSON layer

Server:
  serve [--host] [--port]                Start the API server + web UI
  init-db                                Initialize PostgreSQL schema
  self-audit [--output FILE]             Run security self-audit on HEAVEN

Other:
  info                                   Platform / dependency check
```

---

## REST API — selected endpoints

```
GET  /api/health                                        unauthenticated health check
POST /api/auth/login                                    JWT auth (rate limited 5/min)
POST /api/auth/logout                                   revoke token

GET  /api/engagement                                    active engagement summary
GET  /api/engagement/findings?severity=&status=&...     list with filters
GET  /api/engagement/findings/{id}/evidence             full evidence package + markdown
PUT  /api/engagement/findings/{id}/status               update status (verified/FP/etc)

POST /api/scans                                         create a new scan
GET  /api/scans/{id}                                    scan status
GET  /api/dashboard                                     dashboard aggregate
GET  /api/kill-chain/{scan_id}                          kill chain coverage report
GET  /api/attack-tree/{scan_id}                         attack tree mermaid diagram
GET  /api/vulnerabilities                               flat finding list

WS   /api/ws/scan/{scan_id}?token=...                   live scan progress
WS   /api/ws/logs?token=...                             live orchestrator logs
```

Full API docs at `/api/docs` (FastAPI auto-generated).

---

## Authorization gate

HEAVEN refuses to scan unless one of:
- `--i-have-authorization` flag set explicitly per run, or
- `HEAVEN_AUTHORIZED_SCOPE` env var lists every target, or
- the target is in scope of the active engagement (`--engagement <name>`), or
- operator confirms interactively at TTY prompt

The flag is a guardrail, not a license. You're still responsible for confirming you have written authorization (signed SoW, ROE, bug-bounty scope) for every target.

---

## Configuration

Important environment variables. Set in shell or via `.env` file with `--config-file`:

| Variable | Required | Purpose |
|---|---|---|
| `HEAVEN_ADMIN_PASSWORD` | yes | API admin password (else random one logged once) |
| `HEAVEN_DB_PASSWORD` | yes | PostgreSQL password (else random per-run) |
| `HEAVEN_ENGAGEMENT` | recommended | Path to active engagement DB |
| `HEAVEN_AUTHORIZED_SCOPE` | optional | Comma-separated allowed targets (alternative to --i-have-authorization) |
| `HEAVEN_NVD_API_KEY` | optional | Raises NVD API rate limit |
| `HEAVEN_API_HOST` | optional | API bind host (default 127.0.0.1) |
| `HEAVEN_CORS_ORIGINS` | optional | Comma-separated CORS origins |
| `HEAVEN_RATE_LIMIT_DEFAULT` | optional | Global API rate (default `100/minute`) |
| `HEAVEN_RATE_LIMIT_LOGIN` | optional | Login endpoint rate (default `5/minute`) |
| `HEAVEN_DISABLE_AUTH` | dev only | Disables API auth (do not use in production) |

---

## Measuring accuracy

There is no honest single number for "accuracy" of a vulnerability scanner — it depends on your environment, your fixtures, and the threat model. The right way is to *measure* against a known target.

```bash
# 1. Spin up a vulnerable test app
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. Add it to a test engagement
heaven engage init juice-shop-test
heaven scope add http://localhost:3000 --kind url

# 3. Scan
heaven scan -u http://localhost:3000 -m web --engagement juice-shop-test \
    --i-have-authorization --output-file scan.json

# 4. Compare to ground truth and get precision/recall/F1
python -m heaven.testing.selftest measure-against \
    --findings-file scan.json \
    --ground-truth tests/fixtures/juice_shop_truth.json
```

This produces a real number — calibrated to that fixture. Use it on your CV, in your dissertation, or in an engagement report. Don't make up numbers.

---

## Self-audit

HEAVEN ships with a `self-audit` command that runs SAST against itself: secrets in source, weak crypto, missing auth, CORS misconfiguration, etc.

```bash
heaven self-audit
# Security score: 100/100 (grade: A)
#   Critical: 0  High: 0  Medium: 0  Low: 0
```

Run this in CI to catch regressions on the tool itself.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│  CLI (click)         REST API (FastAPI)         WebSocket logs     │
│  ──────────          ─────────────────          ─────────────      │
│       │                       │                         │          │
│       └──────┬────────────────┴─────────────────────────┘          │
│              │                                                     │
│              ▼                                                     │
│  ┌───────────────────────────────────────────────────────┐         │
│  │       Async Orchestrator (DAG, semaphores, deps)      │         │
│  └─┬──────────┬──────────┬──────────┬──────────┬─────────┘         │
│    │          │          │          │          │                   │
│    ▼          ▼          ▼          ▼          ▼                   │
│  recon/    vulnscan/   ml/        mitre/     devsecops/            │
│  network   cve_mapper  risk       attack_    aggregator            │
│  web       validator   model      mapper     evidence              │
│  cloud     fp_suppress features   kill_chain pdf_report            │
│  ad        nuclei                                                  │
│                                                                    │
│           ↓                                                        │
│  ┌────────────────────┐    ┌──────────────────────────────┐        │
│  │ engagement.py      │    │ security/                    │        │
│  │  (per-eng SQLite)  │    │  auth.py (JWT/RBAC/lockout)  │        │
│  │  scope             │    │  audit.py (audit log)        │        │
│  │  scan history      │    │  vault.py (AES-256-GCM)      │        │
│  │  findings + dedup  │    │  self_audit.py (SAST)        │        │
│  └────────────────────┘    └──────────────────────────────┘        │
└────────────────────────────────────────────────────────────────────┘
```

---

## Development

```bash
pip install -e ".[dev]"
ruff check heaven/ tests/
mypy heaven/
pytest tests/ -v --cov=heaven
```

CI runs all of the above plus `pip-audit` and `bandit` SAST on every push (`.github/workflows/ci.yml`).

Current test count: **94 tests**, including Hypothesis property-based fuzzing on parsers and validators.

---

## Legal

HEAVEN performs active vulnerability testing. Running it against systems without written authorization is illegal in most jurisdictions:

- **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **United Kingdom** — Computer Misuse Act 1990
- **European Union** — NIS2 Directive
- **India** — IT Act 2000, Sections 43 and 66

The authorization gate is a guardrail. It is not a substitute for written consent (signed SoW, Rules of Engagement, or bug-bounty program scope).

---

## License

MIT — see `LICENSE`.

---

## Acknowledgements

HEAVEN integrates with or is inspired by:

- **Nuclei** — templated detection engine
- **NVD / NIST** — public CVE database
- **EPSS / FIRST** — Exploit Prediction Scoring System
- **CISA KEV** — Known Exploited Vulnerabilities catalog
- **MITRE ATT&CK** — adversary tactics and techniques framework
- **Lockheed Martin** — Cyber Kill Chain model
- **OWASP** — Juice Shop, WebGoat, Top 10
- **impacket** — for AD / Kerberos primitives

If you're new to security testing, learn the underlying tools first (Burp, sqlmap, Nuclei, BloodHound). HEAVEN's value is in workflow and orchestration; the security primitives are not original to it.
