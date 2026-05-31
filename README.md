# ☠️ HEAVEN — Autonomous Penetration-Testing Framework

<div align="center">

<a href="https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/actions/workflows/ci.yml"><img src="https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"/></a>
<a href="https://pypi.org/project/heaven-pentest/"><img src="https://img.shields.io/pypi/v/heaven-pentest.svg?label=PyPI&color=2bd46a" alt="PyPI"/></a>
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python"/>
<img src="https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
<img src="https://img.shields.io/badge/tests-313_passing-2bd46a?logo=pytest&logoColor=white" alt="Tests"/>
<img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/>

**Find it. Confirm it. Report it.**
Recon → ML risk-scoring → verified exploitation → reporting — orchestrated end-to-end, for one engagement, from one console.

</div>

> ⚠️ **Authorized use only.** HEAVEN is an offensive-security tool. Every destructive
> action requires the explicit `--i-have-authorization` flag. Use it only against
> systems you own or have **written permission** to test. See [Legal](#legal).

---

## Table of Contents

- [What is HEAVEN?](#what-is-heaven)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Reference](#cli)
- [Web UI](#web-ui)
- [REST API](#api)
- [Reports & Export](#reports)
- [Integrations](#integrations)
- [Risk Scoring (ML)](#risk-scoring)
- [Security Controls](#security)
- [Project Structure](#structure)
- [Development](#development)
- [Documentation](#docs)
- [Legal & Disclaimer](#legal)

---

<a id="what-is-heaven"></a>
## 🧠 What is HEAVEN?

HEAVEN is a **production-grade penetration-testing platform** that automates the
repeatable, time-consuming parts of a professional engagement — reconnaissance,
vulnerability detection, exploitation proof, risk triage, and reporting — so the
operator can focus on the judgment work only a human can do.

It runs three ways from the **same engagement dataset**:

- **CLI** — 35 commands for scriptable, CI-friendly workflows.
- **Web UI** — a 19-page React command centre (scan launcher, live findings, kill-chain, reports).
- **REST + WebSocket API** — 45 RBAC-protected routes for automation and integration.

<div align="center">
<img width="540" alt="HEAVEN overview" src="https://github.com/user-attachments/assets/76d75a34-463f-4063-b4c5-97d759bb0219" />
</div>

---

<a id="capabilities"></a>
## ⚡ Capabilities

| Area | What it does |
|---|---|
| 🔍 **Reconnaissance** | nmap · web crawling · DNS brute-force · cert transparency · Shodan · AD enumeration · cloud (AWS/GCP/Azure) · containers & Kubernetes (Docker socket / K8s API / RBAC) · IoT/SCADA · wireless · Git secrets · email OSINT · honeypot detection |
| 🎯 **Vuln detection** | SQLi (error/boolean/time-blind) · XSS · SSRF · XXE · CORS · CRLF · open redirect · IDOR · mass assignment · dir/file fuzzing · JWT attacks · race conditions · request smuggling · GraphQL introspection · default creds · subdomain takeover · Nuclei templates |
| 🧬 **API security** | OWASP API Top 10 — BOLA/IDOR, broken auth, mass assignment, excessive data exposure (REST + GraphQL) |
| 💥 **Verified exploitation** | Active proof, not guesses — sqlmap SQLi dump · RCE canary file drop/read · SSRF out-of-band callback listener |
| 🔓 **Post-exploitation** | linPEAS privesc enum · BloodHound AD collection · SSH/SMB/PsExec lateral movement · credential reuse / pass-the-hash |
| 🤖 **Autonomous AI** | LLM observe→plan→act loop · recon agent · attack-chain planner · LLM false-positive review · cross-engagement knowledge graph. Provider-agnostic (Anthropic / OpenAI / Gemini) with a **deterministic fallback that needs no API key** |
| 📊 **Risk scoring** | CVSS-v3 ML predictor (R²=0.9925, 13-feature ExtraTrees) · EPSS · CISA KEV · asset-criticality multiplier · empirical Bayesian priors |
| 🗺️ **Mapping** | Every finding mapped to MITRE ATT&CK techniques + Lockheed Cyber Kill Chain phases · TAXII threat-intel feed |
| 🔁 **Continuous & DevSecOps** | Scheduled re-scans with differential alerts (`watch`) · SAST (Semgrep) · SBOM · Jira / Linear ticketing · Splunk / Elastic SIEM forwarding |
| 📄 **Reporting** | PDF · HTML · compliance-mapped HTML (OWASP/NIST) · Markdown · CSV · JSON · SARIF · Burp XML · proxy-JSONL — from the **CLI and the web UI** |
| 🔇 **FP suppression** | Two-stage confirmation pass; sub-0.40-confidence results discarded · optional LLM second opinion |

---

<a id="architecture"></a>
## ⚙️ Architecture

```
            ┌─────────────────────────────────────────────────────────┐
  CLI ──────┤                                                         │
  Web UI ───┤   ORCHESTRATOR  (async dependency-aware task graph)     │
  REST API ─┤   resumable · checkpointed · stealth timing 1–5         │
            └───────────────────────────┬─────────────────────────────┘
                                         │
   ┌──────────────┬───────────────┬──────┴───────┬──────────────┬────────────┐
   │   RECON      │  VULN DETECT  │  EXPLOIT/POST │  AI / ML     │ REPORTING  │
   │ nmap · web   │ SQLi/XSS/SSRF │ sqlmap proof  │ CVSS model   │ PDF · HTML │
   │ DNS · cloud  │ IDOR · fuzz   │ RCE canary    │ recon agent  │ SARIF·Burp │
   │ AD · K8s     │ Nuclei · API  │ linPEAS·BH    │ attack plan  │ compliance │
   │ IoT · OSINT  │ FP suppress   │ lateral move  │ knowledge gr │ ticketing  │
   └──────────────┴───────────────┴──────────────┴──────────────┴────────────┘
                                         │
   ┌─────────────────────────────────────┴────────────────────────────────────┐
   │  STORAGE — PostgreSQL (async, 23-table schema, partitioned audit log)      │
   │  with a zero-config SQLite fallback (same interface, file = one engagement)│
   │  SECURITY — JWT RBAC · AES-256-GCM credential vault · HMAC-signed audit log │
   └────────────────────────────────────────────────────────────────────────────┘
```

---

<a id="quick-start"></a>
## 🚀 Quick Start

**Requirements:** Python 3.11+, `git`, `nmap`. Optional: `nuclei`, `ffuf`,
`sqlmap`, `searchsploit` (richer recon/exploitation when present; HEAVEN degrades
gracefully without them).

```bash
# 1. Install
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh      # venv + deps + builds the web UI

# 2. (Optional) configure — otherwise the UI ships with admin/admin + forced change
export HEAVEN_ADMIN_PASSWORD="your-strong-password"
export SHODAN_API_KEY="…"                # optional passive recon
export HEAVEN_ENGAGEMENT="client-q3"     # default engagement name

# 3. Scan
heaven --version
heaven engage init my-engagement
heaven scan -u https://target.example.com -m web --i-have-authorization
heaven scan -t 10.0.0.0/24 -m network --i-have-authorization

# 4. Web UI
heaven serve            # → http://localhost:8443
```

> 🐳 Or run containerized: `docker compose up` (bundles PostgreSQL).

---

<a id="cli"></a>
## ⌨️ CLI Reference

35 commands. Run `heaven <command> --help` for full options.

| Command | Purpose |
|---|---|
| `scan` | Launch a vulnerability scan (`-m web\|network\|full`, `--stealth 1-5`, `--auto-prove`, `--autonomous`) |
| `serve` | Start the API server + web UI |
| `engage` · `scope` | Manage engagements / in-scope targets |
| `findings` · `show` · `mark` | List findings · full detail · set triage status |
| `export` · `report` | Export findings (8 formats) · generate compliance HTML/PDF |
| `kill-chain` · `coverage` | Kill-chain phase coverage · OWASP coverage grade |
| `autonomous` | LLM-driven observe→plan→act loop (bounded budget) |
| `watch` · `schedule` | Continuous monitoring with differential alerts |
| `diff` | Compare two scans (new / resolved / regressed / unchanged) |
| `sast` | Semgrep static analysis + curated OWASP rule pack |
| `lateral` · `knowledge` | Lateral movement · cross-engagement knowledge graph |
| `exploitdb` · `mitre-report` | Exploit-DB lookup · ATT&CK Navigator layer |
| `tickets` | Push findings to Jira / Linear |
| `pause` · `resume` · `replay` | Pause · resume · deterministically replay a scan |
| `train-model` · `train-priors` | Retrain the CVSS model · learn Bayesian priors |
| `init` · `init-db` · `update` | Setup wizard · PostgreSQL schema · refresh CVE/Nuclei feeds |
| `self-audit` · `sys-status` · `info` | Security self-audit · system status · platform info |
| `completion` | Shell-completion script (bash / zsh / fish) |

```bash
# Verified exploitation + autonomous loop
heaven scan -u https://app.example.com --auto-prove --i-have-authorization
heaven autonomous -t 10.0.0.5 --engagement test --i-have-authorization

# Works with no API key (deterministic planner)
heaven autonomous -t 10.0.0.5 --no-llm --i-have-authorization
```

---

<a id="web-ui"></a>
## 🖥️ Web UI

`heaven serve`, then open `http://localhost:8443`. A modern dark, glassmorphic
React console (Inter + JetBrains Mono) with a command palette (⌘K), live log
streaming, and a 3D network-topology view.

<div align="center">
<img width="1600" alt="HEAVEN web UI" src="https://github.com/user-attachments/assets/6e40d32d-67a4-4ab3-8faf-46a5fb4e3192" />
</div>

19 pages including: **Dashboard** (severity distribution + ATT&CK heat-map),
**Scans**, **Findings** (filter + **download report**), **Finding Detail**
(description · impact · remediation · CWE/OWASP/MITRE · references · evidence ·
curl repro), **Kill Chain**, **Watch**, **Scan Diff**, **SAST**, **Autonomous**,
**AI Plans**, **Coverage**, **Post-Ex**, **Lateral**, **Knowledge**, **Tickets**,
**Benchmark**, **Methodology**.

> **First login:** a fresh install ships with `admin` / `admin` and **forces a
> password change** on first sign-in. Set `HEAVEN_ADMIN_PASSWORD` beforehand to
> skip the prompt. JWTs are held in memory only (never `localStorage`).

---

<a id="api"></a>
## 🌐 REST API

45 RBAC-protected routes on port 8443. Interactive docs at `/docs`.

```bash
# Health (no auth)
curl http://localhost:8443/api/health

# Login → JWT
curl -X POST http://localhost:8443/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'

# Use the token
curl http://localhost:8443/api/engagement/findings \
     -H "Authorization: Bearer <token>"
```

Highlights:

| Endpoint | Permission | Purpose |
|---|---|---|
| `POST /api/scans` · `GET /api/scans` | `scan.create` / `scan.view` | Launch / list scans |
| `GET /api/engagement/findings` | `vuln.view` | Findings (filterable) |
| `GET /api/engagement/findings/{id}/evidence` | `vuln.view` | Full evidence package |
| `POST /api/findings/{id}/prove` | `vuln.validate` | Verified exploitation proof |
| `POST /api/autonomous/run` | `scan.create` | Iterative LLM pen-test loop |
| `GET /api/scans/{id}/diff?baseline=…` | `scan.view` | Differential scan |
| `POST /api/sast/scan` | `scan.create` | Semgrep SAST |
| `POST /api/lateral/run` · `/api/postex/{module}/run` | admin | Lateral / post-ex |
| `GET /api/report/export?format=…` | `report.view` | **Download report** (8 formats) |
| `POST /api/auth/change-password` | session | Change password |
| `GET /api/ws/logs` · `/api/ws/scan/{id}` | token (query) | WebSocket live streams |

---

<a id="reports"></a>
## 📄 Reports & Export

Generate a report from the **CLI** or the **web UI** (Findings → *Download
report*) — identical output, eight standards:

| Format | Use |
|---|---|
| **PDF** | Client / executive deliverable (needs `reportlab`) |
| **HTML** | Self-contained, compliance-mapped (OWASP Top 10 / NIST CSF) |
| **Markdown** | Wiki / Git |
| **CSV** | Spreadsheet / triage |
| **JSON** | Automation / re-import |
| **SARIF** | GitHub code scanning |
| **Burp XML** | Import into Burp Suite |
| **proxy-JSONL** | Replay / mitmproxy / Caido |

```bash
heaven export -o report.sarif --format sarif
heaven report --framework OWASP_TOP10 -o compliance.html
```

Every finding carries a defensible **evidence package**: request/response, a
copy-pasteable curl repro, detection rationale, remediation, and CWE / OWASP /
MITRE references (sourced from a built-in vulnerability knowledge base when the
finding itself doesn't carry them).

---

<a id="integrations"></a>
## 🔌 Integrations

| Tool | How |
|---|---|
| **Nuclei** | Auto-run when on `PATH`; `nuclei -update-templates` |
| **sqlmap** | Auto-runs on confirmed SQLi candidates |
| **searchsploit / Exploit-DB** | CVE → PoC and product/version → PoC lookup |
| **Shodan** | `export SHODAN_API_KEY=…` → merged into recon |
| **Metasploit** | `msfrpcd` + `HEAVEN_MSF_*` env, `--enable-exploitation` |
| **Jira / Linear** | `HEAVEN_JIRA_*` / `HEAVEN_LINEAR_*` env → `heaven tickets` |
| **Splunk / Elastic** | SIEM forwarding via `HEAVEN_SPLUNK_HEC_*` / `HEAVEN_ELASTIC_*` |

---

<a id="risk-scoring"></a>
## 📊 Risk Scoring (ML)

HEAVEN predicts a CVSS-v3 base score for every finding with a 13-feature
`ExtraTreesRegressor` trained on the NVD (held-out R²=0.9925), then layers on:

- **EPSS** exploit-probability and **CISA KEV** membership,
- an **asset-criticality** multiplier (`scope add --criticality crown_jewel`),
- empirical **Bayesian priors** learned from your past engagements (`train-priors`).

Model provenance and caveats are documented in
[`data/models/NVD_model.MODEL_CARD.md`](data/models/NVD_model.MODEL_CARD.md).
Retrain anytime with `heaven train-model`.

---

<a id="security"></a>
## 🔒 Security Controls

- **JWT RBAC** — `admin` / `operator` / `viewer` / `auditor` roles; brute-force lockout with exponential backoff.
- **Default-credential protection** — seeded `admin/admin` forces a password change on first login; `self-audit` flags it as critical until changed.
- **AES-256-GCM credential vault** for stored secrets.
- **HMAC-signed, append-only audit log** of every operator action.
- **LLM redaction** — operator credentials are scrubbed before any prompt reaches a third-party endpoint.
- **Authorization gate** — destructive actions refuse to run without `--i-have-authorization`.
- Run `heaven self-audit` to score your own installation.

---

<a id="structure"></a>
## 📁 Project Structure

```
heaven/
├── recon/        network · web · DNS · cloud · containers/K8s · AD · IoT · wireless · Git · email
├── vulnscan/     injection · IDOR · API · SSL · Nuclei · exploit-proof · exploitdb · SAST · FP-suppress
├── postex/       linPEAS · BloodHound · lateral movement · credential reuse
├── ai/           LLM gateway · recon agent · attack-chain planner · FP review · knowledge graph
├── ml/           CVSS model · feature engine · Bayesian priors · training
├── mitre/        ATT&CK mapping · kill chain · TAXII threat-intel
├── devsecops/    PDF/compliance reports · vuln KB · SBOM · diff · alerting · ticketing
├── db/           PostgreSQL (async ORM, 23-table schema) + SQLite fallback
├── security/     JWT RBAC · AES-256 vault · HMAC audit log
├── api/          FastAPI server + WebSocket (45 routes)
└── cli/          Click CLI — one module per command group (35 commands)

heaven-ui/        React + Vite web console (19 pages)
tests/            313 pytest tests + DVWA benchmark suite
docs/             QUICKSTART · methodology (OWASP/NIST/PTES) · runbooks
```

---

<a id="development"></a>
## 🛠️ Development

```bash
pip install -e ".[dev]"
ruff check heaven/ tests/      # lint
pytest tests/                  # 313 tests, ~6s
heaven self-audit              # security self-check
```

CI runs lint (ruff), type-check (mypy), the test matrix (3.11 / 3.12),
`pip-audit`, Bandit SAST, the HEAVEN self-audit, and a Docker image build +
smoke-test. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

<a id="docs"></a>
## 📚 Documentation

| Doc | Purpose |
|---|---|
| [`docs/QUICKSTART.md`](docs/QUICKSTART.md) | 5-minute walkthrough |
| [`docs/BENCHMARK_HOWTO.md`](docs/BENCHMARK_HOWTO.md) | Reproduce DVWA precision/recall numbers |
| [`docs/COMPARISON.md`](docs/COMPARISON.md) | Head-to-head vs Burp / ZAP / Nessus / sqlmap |
| [`docs/methodology/`](docs/methodology/) | OWASP Testing Guide v4 · NIST SP 800-115 · PTES |
| [`CHANGELOG.md`](CHANGELOG.md) · [`SECURITY.md`](SECURITY.md) | Version history · responsible disclosure |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributing · conduct |

---

<a id="legal"></a>
## ⚠️ Legal & Disclaimer

HEAVEN is intended for **authorized security testing and education only**.
Running it against systems you do not own or lack **explicit written permission**
to test is illegal in most jurisdictions and may carry criminal penalties.

- Every destructive action requires the `--i-have-authorization` flag.
- All scan activity is logged to an HMAC-signed audit trail.
- The authors accept **no liability** for misuse or damage.

By using HEAVEN you agree you are solely responsible for ensuring you have proper
authorization. Licensed under [MIT](LICENSE).

---

<div align="center">

**Author — Nisarg Chasmawala** (alias **HEAVEN**) · Offensive Security Engineer
[LinkedIn](https://www.linkedin.com/in/nisarg-chasmawala) · [GitHub](https://github.com/nishu2402)

313 tests · 128 modules · 35 CLI commands · 45 API routes · 19 UI pages · PostgreSQL + SQLite · MIT

</div>
