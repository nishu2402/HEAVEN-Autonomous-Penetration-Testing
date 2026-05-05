<div align="center">

```
██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗
██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║
███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
```

**Autonomous Penetration Testing Framework**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-00ff41?style=flat-square&logo=python&logoColor=black)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00d4ff?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-108%20passing-00ff41?style=flat-square&logo=pytest&logoColor=black)](tests/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Async](https://img.shields.io/badge/Async-asyncio-6366f1?style=flat-square)](https://docs.python.org/3/library/asyncio.html)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-ff003c?style=flat-square)](https://attack.mitre.org)

*Find it. Triage it. Report it. — While you do the work that actually requires judgment.*

</div>

---

## What is HEAVEN?

HEAVEN is a real-world penetration testing platform that automates the **repetitive parts** of an engagement — reconnaissance, vulnerability detection, false-positive suppression, MITRE mapping, and report generation — so you can focus on what actually requires a human: scope decisions, business logic, exploit chaining, and the final report.

**It is not a point-and-click hacking tool.** Every scan requires explicit written-authorization confirmation. The tool ends at finding and reporting — not exploitation and persistence.

---

## Architecture at a glance

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   CLI (Click)          REST API (FastAPI/JWT)       WebSocket Logs      │
│   ──────────           ─────────────────────        ──────────────      │
│        │                        │                         │             │
│        └──────────┬─────────────┴─────────────────────────┘             │
│                   ▼                                                     │
│    ┌──────────────────────────────────────────────────────────┐         │
│    │   Async Orchestrator  (DAG · Semaphores · Retry · Deps)  │         │
│    └──┬──────────┬──────────┬──────────┬──────────┬───────────┘         │
│       │          │          │          │          │                     │
│       ▼          ▼          ▼          ▼          ▼                     │
│   recon/      vulnscan/   ml/        mitre/    devsecops/               │
│   network     safe_valid  risk_model attack_   compliance_report        │
│   web_crawl   fp_suppress nvd_pipe   mapper    evidence                 │
│   cloud_enum  nuclei      ai_brain   kill_chain aggregator              │
│   ad_scanner  advanced_   zeroday_   ──────────                         │
│   deep_recon  attacks     engine                                        │
│   shodan_rec  sqlmap_run                                                │
│               msf_client                                                │
│                   │                                                     │
│        ┌──────────┴──────────────────────────────┐                      │
│        │  Engagement Store (SQLite per engagement)│                     │
│        │  ─ scope enforcement                     │                     │
│        │  ─ finding deduplication across re-scans │                     │
│        │  ─ operator notes + status workflow      │                     │
│        │  ─ full evidence packages                │                     │
│        └──────────────────────────────────────────┘                     │
│        ┌──────────────────────────────────────────┐                     │
│        │  Security Layer                          │                     │
│        │  ─ JWT/RBAC + brute-force lockout        │                     │
│        │  ─ HMAC audit log                        │                     │
│        │  ─ AES-256-GCM credential vault          │                     │
│        │  ─ self-audit SAST (runs on itself)      │                     │
│        └──────────────────────────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Quick install (recommended)

```bash
git clone https://github.com/nishu2402/Autonomous-penetration-testing--heaven-.git
cd "Autonomous penetration testing (heaven)"
chmod +x install.sh && ./install.sh
```

The installer handles Python validation, virtualenv, all dependencies, optional frontend build, and optional PostgreSQL setup. **PostgreSQL is not required** — HEAVEN uses SQLite for all engagement data by default.

### Manual install

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

### After install

```bash
# Set the admin password (required for the API/UI)
export HEAVEN_ADMIN_PASSWORD='your-strong-password-here'

# Verify it works
heaven --version
heaven self-audit
```

> **PostgreSQL is optional.** HEAVEN's core workflow uses per-engagement SQLite files that live alongside your engagement notes. PostgreSQL is only used for multi-operator centralized mode. If you see a PostgreSQL error on first run, ignore it — everything still works.

---

## Quick scan

```bash
# No engagement DB — just scan and dump results
heaven scan -u https://app.example.com -m web \
    --i-have-authorization \
    --output-file findings.json
```

---

## The engagement workflow

This is HEAVEN's core value. One engagement = one SQLite file. Findings deduplicate across re-scans. Scope is enforced. Status persists.

### 1  ·  Initialize

```bash
heaven engage init acme-q2 --client "ACME Corp" --sow "SOW-2026-001"
# → Engagement initialized: engagements/acme-q2.db

export HEAVEN_ENGAGEMENT=engagements/acme-q2.db
```

### 2  ·  Define scope

```bash
heaven scope add api.acme.example --kind host
heaven scope add 10.0.0.0/24     --kind cidr
heaven scope add https://app.acme.example --kind url

heaven scope import engagement-scope.txt   # bulk import
heaven scope list
```

### 3  ·  Scan — scope is enforced

```bash
heaven scan \
    -u https://app.acme.example \
    -t 10.0.0.5 \
    -t out-of-scope.example \    # ← automatically dropped
    --engagement acme-q2 \
    --i-have-authorization

# Targets dropped (not in engagement scope):
#   - out-of-scope.example
#
# Scan completed in 14s
#   Tasks: 22/22 (failed: 0)
#   Findings persisted: 7 → engagements/acme-q2.db
```

### 4  ·  Triage findings

```bash
heaven findings --severity critical

#   CRIT a359e73e  conf=0.94  sqli    api.acme.example  open
#   CRIT 7b1f3c9a  conf=0.91  ssrf    api.acme.example  open

# Full evidence: request, response, curl repro, remediation, MITRE mapping
heaven show a359e73e

# Get the exact curl command to replay in your terminal or Burp Repeater
heaven replay a359e73e
#   curl -X POST -i --max-time 30 --data "id=' OR 1=1--" https://app.acme.example/login

# Confirm in Burp → mark verified
heaven mark a359e73e verified --notes "confirmed via burp, dumps users table"

# Mark false positive with reason
heaven mark 7b1f3c9a false_positive --notes "WAF blocks payload"
```

### 5  ·  Re-scan — no duplicates

```bash
heaven scan -u https://app.acme.example --engagement acme-q2 --i-have-authorization

# Known SQLi: seen_count++ | status preserved | notes preserved
# New findings: inserted as "open"
```

### 6  ·  Kill chain coverage

```bash
heaven kill-chain

# Cyber Kill Chain Coverage: 71/100  (5/7 phases)
#
#   Reconnaissance          4 findings
#   Weaponization           2 findings
#   Delivery                0 findings   ← gap
#   Exploitation            3 findings
#   Installation            0 findings   ← gap
#   Command & Control       1 finding
#   Actions on Objectives   2 findings
#
# Chained attack path:
#   [Recon]   → Exposed admin panel /admin
#   [Weapon]  → Apache 2.4.49 CVE-2021-41773
#   [Exploit] → SQL injection /login (critical)
#   [C2]      → Exposed phpMyAdmin
#   [Obj]     → Public S3 bucket with database backups
```

### 7  ·  Export

```bash
heaven export -o report.md    --format markdown  --severity high     # pentest report
heaven export -o findings.csv --format csv                           # Jira / spreadsheet
heaven export -o findings.sarif --format sarif                       # code-scanning dashboards
heaven export -o findings.json --format json   --status verified     # pipe to your tooling
heaven export -o findings.xml  --format burp                         # Burp Site Map import
heaven export -o findings.jsonl --format proxy-jsonl                 # mitmproxy / Caido
```

### 8  ·  Resume an interrupted scan

```bash
heaven resume --engagement acme-q2 --i-have-authorization
# Resuming: a3b1c4d5
# Completed tasks on disk: 14 (skipped)
# Continuing from task 15...
```

### 9  ·  Web UI

```bash
heaven serve
# → http://localhost:8443
```

Log in with `HEAVEN_ADMIN_PASSWORD`. The UI gives you:

| Feature | Description |
|---------|-------------|
| Dashboard | Severity / status breakdown with live charts |
| Findings | Filter by severity, status, target, confidence |
| Finding detail | Full evidence package, curl repro, status buttons |
| Kill Chain | Phase diagram + chained attack path |
| Live terminal | WebSocket-streamed orchestrator logs |
| Scans tracker | Real-time scan progress |

> The UI is **triage-only**. Scans launch from the CLI where the authorization gate is enforced.

### 10  ·  Engagement summary

```bash
heaven engage status

# Engagement: acme-q2 | Client: ACME Corp
# Scope: 4 targets | Scans: 3 | Findings: 12
#
# By severity:    critical=2  high=4  medium=5  low=1
# By status:      open=7  verified=4  false_positive=1
```

---

## What HEAVEN detects

| Category | Techniques |
|----------|-----------|
| **Injection** | SQLi (boolean/error/time-based), XSS (reflected/stored), SSTI, XXE, CRLF, command injection |
| **Auth & Sessions** | JWT alg:none, JWT weak secret, default credentials (35+ pairs), session fixation |
| **Web** | SSRF (response + OOB), open redirect, request smuggling (CL.TE), race conditions |
| **Infrastructure** | Open ports, exposed services, SSL/TLS misconfig, directory listing, exposed git |
| **Active Directory** | Kerberoasting, AS-REP roasting, DCSync rights, delegation abuse, NTLM relay, ACL abuse |
| **Cloud** | S3 bucket exposure, AWS metadata SSRF, GCP/Azure storage misconfig |
| **CVE intelligence** | NVD lookup, EPSS scoring, CISA KEV flag — every finding enriched |
| **Subdomain** | DNS brute force, certificate transparency, subdomain takeover (dangling CNAME) |
| **Secrets** | API keys, tokens, private keys in source and JS files |

### False-positive suppression

Every candidate goes through a second-stage validation layer before reaching the report:

1. **Baseline measurement** — probe with benign payloads, measure response distribution
2. **Canary confirmation** — for XSS: check the exact reflected string appears; for SQLi: compare boolean branches
3. **Confidence scoring** — Bayesian-calibrated 0–1 score, not a fake "99% accurate" claim
4. **FP suppression** — findings below confidence threshold are discarded, not reported

---

## What HEAVEN does NOT do

- No reverse shells, payload delivery, persistence, or C2
- No autonomous exploit chaining
- No "click here to own this box" buttons
- No fake accuracy numbers

If you need exploitation for an engagement, use Metasploit, sqlmap, or Cobalt Strike. HEAVEN's job ends at **find → validate → report**.

---

## Scan modes

| Mode | Flag | What runs |
|------|------|-----------|
| Web | `-m web` | Crawl, JWT, XSS, SQLi, SSRF, SSTI, nuclei templates |
| Network | `-m network` | nmap, banner grab, CVE lookup, service detection |
| Full | `-m full` | Everything: web + network + AD + cloud + deep recon |
| AD | `-m ad` | Active Directory: Kerberoasting, ACL, DCSync, delegation |
| Cloud | `-m cloud` | AWS/GCP/Azure enumeration |
| IoT | `-m iot` | Modbus, MQTT, BACnet, OT/SCADA |

---

## CLI reference

```
Engagement:
  engage init NAME [--client] [--sow]    New engagement
  engage status                          Summary
  scope add TARGET [--kind] [--notes]    Add to scope
  scope import FILE                      Bulk import
  scope list [--all]                     List scope
  scope remove TARGET                    Remove target

Scanning:
  scan [-t TARGET] [-u URL] [-m MODE]
       [--engagement NAME]
       [--i-have-authorization]          Run a scan
  resume [--engagement] [--scan-id]
       [--i-have-authorization]          Resume interrupted scan
  schedule INTERVAL_MIN -t TARGET        Continuous monitoring

Findings:
  findings [--severity] [--status]
           [--target] [--min-confidence] List findings
  show ID                                Full detail + repro
  replay ID                              Print curl command only
  mark ID STATUS [--notes]               Update status
                                         (open/verified/false_positive/
                                          accepted_risk/fixed)

Reporting:
  export -o FILE --format FMT [filters]  Export findings
                                          markdown / csv / json /
                                          sarif / burp / proxy-jsonl
  kill-chain [--output FILE]             Kill Chain coverage
  mitre-report [--output FILE]           ATT&CK Navigator JSON

Server:
  serve [--host] [--port]                API server + web UI
  init-db                                Initialize PostgreSQL (optional)
  self-audit [--output FILE]             Security self-audit

Utilities:
  info                                   Platform + dependency check
  train-model [--data-dir] [--model-dir] Train CVSS ML model on NVD data
```

---

## REST API

```
Auth:
  POST /api/auth/login                   JWT (5 req/min limit)
  POST /api/auth/logout                  Revoke token

Engagement:
  GET  /api/engagement                   Active engagement summary
  GET  /api/engagement/findings          List with filters
  POST /api/engagement/findings          Create manual finding (Burp integration)
  GET  /api/engagement/findings/{id}/evidence   Full evidence package
  PUT  /api/engagement/findings/{id}/status     Update status

Scans:
  POST /api/scans                        Launch scan
  GET  /api/scans/{id}                   Scan status

Dashboards:
  GET  /api/dashboard                    Aggregate stats
  GET  /api/kill-chain/{scan_id}         Kill Chain report
  GET  /api/attack-tree/{scan_id}        Attack tree diagram
  GET  /api/vulnerabilities              Flat finding list
  GET  /api/health                       Health check (unauthenticated)

WebSocket:
  WS   /api/ws/scan/{scan_id}?token=...  Live scan progress
  WS   /api/ws/logs?token=...            Live orchestrator logs
```

Full interactive docs at `/api/docs` (FastAPI auto-generated, JWT auth required).

---

## Configuration

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `HEAVEN_ADMIN_PASSWORD` | **Yes** | random (logged once) | API / UI admin password |
| `HEAVEN_ENGAGEMENT` | Recommended | — | Path to active `.db` engagement file |
| `HEAVEN_DB_PASSWORD` | No | — | PostgreSQL password (optional centralized mode) |
| `HEAVEN_NVD_API_KEY` | No | — | Raises NVD API rate limit (free at nvd.nist.gov) |
| `HEAVEN_API_HOST` | No | `127.0.0.1` | API bind host |
| `HEAVEN_API_PORT` | No | `8443` | API port |
| `HEAVEN_CORS_ORIGINS` | No | `localhost:5173` | Comma-separated CORS origins |
| `HEAVEN_RATE_LIMIT_DEFAULT` | No | `100/minute` | Global API rate limit |
| `HEAVEN_AUTHORIZED_SCOPE` | No | — | Pre-authorized targets (comma-separated) |
| `HEAVEN_DISABLE_AUTH` | **Dev only** | off | Disables JWT auth — never use in production |
| `SHODAN_API_KEY` | No | — | Enables passive Shodan intelligence in RECON |

---

## Authorization gate

HEAVEN refuses to scan unless one of these conditions is met:

```
1. --i-have-authorization flag is set on the CLI command, OR
2. HEAVEN_AUTHORIZED_SCOPE env var includes the target, OR
3. The target is in scope of the active --engagement, OR
4. You confirm interactively at a TTY prompt
```

This is a guardrail — **not a license**. You are responsible for holding written authorization (signed SoW, Rules of Engagement, or bug-bounty program scope) for every target before scanning.

---

## Measuring accuracy

```bash
# 1. Spin up a vulnerable target
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. Create a test engagement
heaven engage init juice-shop-test
heaven scope add http://localhost:3000 --kind url

# 3. Scan it
heaven scan -u http://localhost:3000 -m web \
    --engagement juice-shop-test \
    --i-have-authorization

# 4. Measure against ground truth
python -m heaven.testing.selftest measure-against \
    --findings-file scan.json \
    --ground-truth tests/fixtures/juice_shop_truth.json

# → Precision: 0.87 | Recall: 0.72 | F1: 0.79
# Real numbers from your environment. Not marketing copy.
```

---

## Self-audit

HEAVEN runs SAST against its own codebase to catch regressions:

```bash
heaven self-audit
# Security score: 100/100 (grade: A)
# Critical: 0  High: 0  Medium: 0  Low: 0
```

Run this in CI to ensure every commit passes. The self-audit checks:
secrets in source, weak crypto, missing auth, CORS misconfiguration, hardcoded credentials, and more.

---

## Where HEAVEN fits vs. your existing tools

| Job | Best-in-class | HEAVEN's role |
|-----|--------------|---------------|
| Web app testing | **Burp Suite Pro** | Triage front-end. Flags candidates with curl repros — you pivot into Burp for validation and exploitation. |
| Network scanning | **Nessus / OpenVAS** | Lighter engagement scans. Nessus wins on CVE breadth for internal infra. |
| Templated detection | **Nuclei** | HEAVEN shells out to Nuclei. Added value: orchestration, FP suppression, engagement DB. |
| AD recon | **BloodHound + impacket** | Inventory + roastable accounts + delegation. For shortest-path graphs, still use BloodHound. |
| Exploitation | **Metasploit / sqlmap** | HEAVEN finds and validates. Exploitation is on you. sqlmap and Metasploit RPC are wired in as optional backends for confirmed findings. |
| Engagement management | Notes app / spreadsheet | **This is where HEAVEN earns its place.** Per-engagement SQLite, scope enforcement, dedup across re-scans, status workflow, evidence packages. |

**Bottom line:** HEAVEN handles *find → triage → dedupe → organize*. Your existing tools handle *exploit → validate manually → write the final report*. HEAVEN is the connective tissue.

---

## Development

```bash
pip install -e ".[dev]"

# Lint + type check
ruff check heaven/ tests/
mypy heaven/

# Tests (108 passing)
pytest tests/ -v --cov=heaven

# Skip slow property tests
pytest tests/ -v --ignore=tests/test_properties.py

# Audit the tool itself
pip-audit
bandit -r heaven/
```

---

## Module status

| Module | Status | Notes |
|--------|--------|-------|
| `orchestrator.py` | ✅ Solid | Async DAG, retry, checkpoints, dynamic task injection |
| `engagement.py` | ✅ Solid | SQLite, scope, dedup, pause/resume |
| `recon/network_scanner.py` | ✅ Solid | nmap wrapper, evasion timing |
| `recon/web_crawler.py` | ✅ Solid | BFS, form/API discovery, auth_config, Playwright backend |
| `recon/ad_scanner.py` | ✅ Solid | Kerberoasting + hash extraction, DCSync, delegation |
| `recon/shodan_recon.py` | ✅ Solid | Passive Shodan host/domain lookup |
| `vulnscan/safe_validator.py` | ✅ Solid | SQLi/XSS/SSRF with FP suppression |
| `vulnscan/advanced_attacks.py` | ✅ Solid | JWT forge, race conditions, smuggling, credential spray |
| `vulnscan/sqlmap_runner.py` | ✅ Solid | sqlmap integration for confirmed SQLi |
| `vulnscan/msf_client.py` | ✅ Solid | Metasploit RPC (requires `--enable-exploitation`) |
| `vulnscan/nuclei_scanner.py` | ✅ Solid | Nuclei with stealth levels |
| `ml/risk_model.py` | ✅ Solid | NVD/EPSS-trained CVSS regressor |
| `ml/ai_brain.py` | ✅ Solid | Bayesian target prioritizer, cross-scan persistence |
| `mitre/attack_mapper.py` | ✅ Solid | ATT&CK technique tagging |
| `mitre/kill_chain.py` | ✅ Solid | Lockheed CKC phase mapping |
| `devsecops/compliance_report.py` | ✅ Solid | OWASP Top 10 HTML report |
| `api/server.py` | ✅ Solid | FastAPI, JWT/RBAC, WebSocket, security headers |
| `security/auth.py` | ✅ Solid | RBAC, brute-force lockout |
| `security/vault.py` | ✅ Solid | AES-256-GCM credential vault |
| `recon/deep_recon.py` | ⚠️ Good | DNS brute force, cert transparency |
| `vulnscan/zeroday_engine.py` | ⚠️ Good | Heuristic fuzzing; high FP rate by design |
| `recon/cloud_enum.py` | ⚠️ Good | AWS solid; GCP/Azure need SDK install |
| `recon/iot_scanner.py` | ⚠️ Rough | Modbus/MQTT/BACnet — needs real OT hardware to validate |
| `recon/wireless_recon.py` | 🔧 Scaffolded | Needs root + monitor-mode — won't run in containers |

---

## Legal

HEAVEN performs **active vulnerability testing**. Running it without written authorization is illegal:

- 🇺🇸 **United States** — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- 🇬🇧 **United Kingdom** — Computer Misuse Act 1990
- 🇪🇺 **European Union** — NIS2 Directive
- 🇮🇳 **India** — IT Act 2000, Sections 43 and 66

The `--i-have-authorization` flag is a guardrail — not a substitute for a signed Statement of Work or Rules of Engagement.

---

## Acknowledgements

HEAVEN integrates with or builds on:

- [Nuclei](https://github.com/projectdiscovery/nuclei) — templated detection engine
- [NVD / NIST](https://nvd.nist.gov) — public CVE database
- [EPSS / FIRST](https://www.first.org/epss/) — Exploit Prediction Scoring System
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities
- [MITRE ATT&CK](https://attack.mitre.org) — adversary tactics and techniques
- [Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) — Cyber Kill Chain
- [OWASP](https://owasp.org) — Juice Shop, WebGoat, Top 10
- [impacket](https://github.com/fortra/impacket) — AD / Kerberos primitives
- [Shodan](https://shodan.io) — passive host intelligence

---

## License

MIT — see [LICENSE](LICENSE).

<div align="center">

---

*Built for pentesters, by someone who got tired of context-switching between five tools.*
*HEAVEN is the connective tissue — not the weapon.*

</div>
