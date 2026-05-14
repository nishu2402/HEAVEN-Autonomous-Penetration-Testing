# ☠️ HEAVEN — AUTONOMOUS PENETRATION TESTING FRAMEWORK

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&height=320&color=0:05070F,15:080F08,30:0A1F0A,45:1A3A00,60:A8FF3E,75:7B2FBE,90:FF073A,100:05070F&text=HEAVEN%20PENTEST%20FRAMEWORK&fontSize=40&fontAlignY=38&fontColor=ffffff&animation=twinkling&desc=Autonomous%20Penetration%20Testing%20%7C%20Real-World%20%7C%20Not%20a%20Simulation%20%7C%20163%20Tests%20Passing&descAlignY=65&descSize=18"/>
</p>

<p align="center">
<img src="https://readme-typing-svg.herokuapp.com?font=Orbitron&weight=700&size=26&duration=2500&pause=700&color=A8FF3E&center=true&vCenter=true&width=1200&lines=Find+It.+Confirm+It.+Report+It.;Recon+%C2%B7+Vuln+Detection+%C2%B7+CVSS+ML+Scoring+%C2%B7+ATT%26CK+Mapping;SQLi+%C2%B7+XSS+%C2%B7+SSRF+%C2%B7+IDOR+%C2%B7+Dir+Fuzzing+%C2%B7+JWT+%C2%B7+Race+Conditions;CVSS+Predictor+R%C2%B2%3D0.9925+%E2%80%94+ExtraTreesRegressor+on+NVD;31+Live+Modules+%C2%B7+163+Tests+%C2%B7+PostgreSQL+%2B+SQLite+%2B+FastAPI+%2B+React+HUD"/>
</p>

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=6&color=0:A8FF3E,25:00CFFF,50:7B2FBE,75:FF073A,100:FFF176"/>
</p>

---

<div align="center">

  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-A8FF3E?style=for-the-badge&logo=python&logoColor=black" alt="Python"/>
    <img src="https://img.shields.io/badge/API-FastAPI-7B2FBE?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
    <img src="https://img.shields.io/badge/Tests-163_Passing-A8FF3E?style=for-the-badge&logo=pytest&logoColor=black" alt="Tests"/>
    <img src="https://img.shields.io/badge/MITRE-ATT%26CK_Mapped-FF073A?style=for-the-badge&logo=cncf&logoColor=white" alt="MITRE"/>
    <img src="https://img.shields.io/badge/OWASP-Top_10_%2B_API_Top_10-00CFFF?style=for-the-badge&logo=owasp&logoColor=black" alt="OWASP"/>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Modules-31_Live-A8FF3E?style=flat-square&logo=python&logoColor=black" alt="Modules"/>
    <img src="https://img.shields.io/badge/CVSS_Predictor-R²%3D0.9925-7B2FBE?style=flat-square&logo=databricks&logoColor=white" alt="CVSS"/>
    <img src="https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_Windows-FF073A?style=flat-square" alt="Platform"/>
    <img src="https://img.shields.io/badge/Vault-AES--256--GCM-00CFFF?style=flat-square&logo=letsencrypt&logoColor=black" alt="Vault"/>
    <img src="https://img.shields.io/badge/License-MIT-FFF176?style=flat-square&logo=opensourceinitiative&logoColor=black" alt="License"/>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Stars-★_Give_a_Star-A8FF3E?style=flat-square&logo=github&logoColor=black" alt="Stars"/>
    <img src="https://img.shields.io/badge/Forks-Share_This_Project-7B2FBE?style=flat-square&logo=git&logoColor=white" alt="Forks"/>
    <img src="https://img.shields.io/badge/Issues-Report_a_Bug-FF073A?style=flat-square&logo=quicklook&logoColor=white" alt="Issues"/>
  </p>

</div>

---

<a id="authors"></a>
## 👾 Authors

### Nisarg Chasmawala · Alias: **HEAVEN**

<div align="center">

| | Detail |
|---|---|
| 🔗 **LinkedIn** | [linkedin.com/in/nisarg-chasmawala](https://www.linkedin.com/in/nisarg-chasmawala) |
| 🐙 **GitHub** | [github.com/nishu2402](https://github.com/nishu2402) |
| 🎯 **Role** | Offensive Security Engineer · Penetration Tester |

</div>

---

## 📋 Table of Contents

- [👾 Authors](#authors)
- [🧠 What is HEAVEN?](#what-is-heaven)
- [⚙️ Architecture](#architecture)
- [📦 Feature Status](#feature-status)
- [🚀 Quick Start](#quick-start)
- [🔧 Installation (Detailed)](#installation-detailed)
- [⌨️ CLI Reference](#cli-reference)
- [🖥️ Web UI](#web-ui)
- [🌐 API](#api)
- [🔌 Integrations](#integrations)
- [📊 CVSS & Risk Scoring](#cvss-risk-scoring)
- [🏢 Active Directory](#active-directory)
- [🛡️ False-Positive Handling](#false-positive-handling)
- [🔒 Security Controls](#security)
- [🔧 Troubleshooting](#troubleshooting)
- [🛠️ Development](#development)
- [📁 Project Structure](#project-structure)
- [⚠️ Legal & Disclaimer](#legal)

---

<a id="what-is-heaven"></a>
## 🧠 What is HEAVEN?

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:A8FF3E,50:7B2FBE,100:FF073A"/>
</p>

HEAVEN is a **production-grade autonomous penetration testing platform** that automates the repeatable, time-consuming parts of a professional engagement — so you can focus on what only humans can do.

<div align="center">

| Capability | Detail |
|---|---|
| 🔍 **Reconnaissance** | nmap · web crawling · DNS brute-force · cert transparency · Shodan · AD enumeration · cloud enum (AWS/GCP/Azure) · IoT/SCADA · wireless · Git secrets · email OSINT · honeypot detection |
| 🎯 **Vulnerability Detection** | Nuclei templates + custom engines for SQLi (error/boolean/time-based blind) · XSS · SSRF · XXE · CORS · CRLF · open redirect · IDOR · mass assignment · directory/file fuzzing · JWT attacks · race conditions · HTTP request smuggling · GraphQL introspection · default credentials · subdomain takeover |
| 🔇 **False-Positive Suppression** | Two-stage confirmation pass — sub-0.40-confidence results automatically discarded |
| 📊 **Risk Scoring** | CVSS v3 ML predictor (R²=0.9925) · EPSS exploit-probability · CISA KEV membership |
| 🗺️ **MITRE ATT&CK** | Every finding mapped to ATT&CK techniques + Lockheed Cyber Kill Chain phases |
| 📄 **Report Generation** | Professional PDF/HTML pentest report (cover page · CVSS v3.1 vectors · MITRE ATT&CK mapping · remediation roadmap · SLA) · Markdown · CSV · JSON · SARIF · Burp XML · proxy JSONL · OWASP Top 10 / NIST CSF compliance HTML |
| 🔢 **Tests** | **163 pytest tests passing** |
| 🏗️ **Stack** | FastAPI + JWT RBAC + WebSocket · React web UI (dark matrix) · PostgreSQL (23-table schema, partitioned audit log, 9 analytical views) · SQLite offline fallback (zero-config, same interface) |

</div>

> *Find it. Confirm it. Report it. So you can focus on what only humans can do.*

---

<a id="architecture"></a>
## ⚙️ Architecture

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:00CFFF,50:A8FF3E,100:FFF176"/>
</p>

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          HEAVEN Platform                                 │
├──────────────────┬──────────────────────────┬────────────────────────────┤
│   RECON          │ VULNERABILITY DETECTION  │   AI / RISK SCORING        │
│                  │                          │                            │
│ • nmap (XML)     │ • Nuclei templates       │ • CVSS 3.x ML predictor    │
│ • Web crawler    │ • SQLi (error-based,     │   (ExtraTreesRegressor,    │
│ • DNS brute-force│   boolean-blind,         │   R²=0.9925, 13 features)  │
│ • Cert transp.   │   time-based blind)      │ • EPSS exploit probability │
│ • Shodan API     │ • XSS (reflected/stored) │ • CISA KEV flag            │
│ • AD enumeration │ • IDOR + mass assignment │ • Bayesian host priority   │
│ • Cloud enum     │ • Dir/file fuzzing       │ • Cross-scan belief update │
│   (AWS/GCP/Azure)│   (250+ paths + ffuf)    │                            │
│ • IoT/SCADA      │ • SSRF + cloud metadata  │                            │
│ • Wireless recon │ • XXE / CRLF injection   │                            │
│ • Git secrets    │ • CORS misconfiguration  │                            │
│ • Email OSINT    │ • JWT (none/weak secret) │                            │
│ • Honeypot detect│ • Race conditions        │                            │
│                  │ • HTTP request smuggling │                            │
│                  │ • GraphQL introspection  │                            │
│                  │ • Default credentials    │                            │
│                  │   (web + SSH via asyncssh│                            │
│                  │ • Subdomain takeover     │                            │
├──────────────────┴──────────────────────────┴────────────────────────────┤
│              FALSE-POSITIVE SUPPRESSION (2-stage verification)           │
│   • Baseline noise measurement (timing / content-length jitter)          │
│   • Reproducibility checks (time-based: 2/3 passes, boolean: stdev)      │
│   • Confidence buckets: strong ≥0.95, high ≥0.80, discarded <0.40        │
├──────────────────────────────────────────────────────────────────────────┤
│                    ORCHESTRATOR (async DAG)                              │
│   • Dependency-aware parallel task execution                             │
│   • Dynamic task injection (services → SSH/SMB/RDP scanners)             │
│   • Resumable scans — checkpoint saved per phase                         │
│   • Stealth timing levels 1–5 with randomized delays                     │
├──────────────────────────────────────────────────────────────────────────┤
│              FastAPI + JWT RBAC + WebSocket live feed                    │
│   • React web UI — dark matrix aesthetic                                 │
│   • Scan launcher  ·  Live findings feed  ·  3D topology                 │
│   • Kill chain view  ·  Triage workflow  ·  Operator notes               │
│   • AES-256-GCM credential vault  ·  HMAC-signed audit log               │
├──────────────────────────────────────────────────────────────────────────┤
│              DATABASE LAYER (Ultra Edition)                              │
│   • PostgreSQL: 23 tables · 9 views · partitioned audit log (by quarter) │
│   • SQLite: offline fallback — same interface, zero config               │
│   • Repository / DAL pattern — typed async CRUD for all entities         │
│   • Alembic migrations (0001 bootstrap → 0002 extended schema)           │
│   • Health check endpoint · bulk insert · SSL mode · retry + backoff     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

<a id="feature-status"></a>
## 📦 Feature Status

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FF073A,50:7B2FBE,100:A8FF3E"/>
</p>

<div align="center">

| Module | Status | What it does |
|---|:---:|---|
| `recon/network_scanner.py` | ✅ Live | Real nmap execution, XML parsing, OS detection, honeypot avoidance |
| `recon/web_crawler.py` | ✅ Live | BFS crawler, form/param discovery, JS endpoint extraction, auth support |
| `recon/deep_recon.py` | ✅ Live | DNS brute-force, cert transparency, OSINT enrichment |
| `recon/ad_scanner.py` | ✅ Live | AD enumeration, Kerberoasting, AS-REP hashes via impacket |
| `recon/shodan_recon.py` | ✅ Live | Passive host/org lookups (requires `SHODAN_API_KEY`) |
| `recon/cloud_enum.py` | ✅ AWS | GCP/Azure stubs present; AWS full |
| `recon/honeypot_detector.py` | ✅ Live | Heuristic honeypot scoring, automatic target skip |
| `vulnscan/nuclei_scanner.py` | ✅ Live | Real nuclei binary execution, JSONL output parsed |
| `vulnscan/injection_scanner.py` | ✅ Live | First-pass XSS + SQLi discovery: error-based, boolean-blind, time-based blind across all crawled input vectors |
| `vulnscan/dir_fuzzer.py` | ✅ Live | Directory & file fuzzing — 250+ curated paths, ffuf integration, wildcard-response filtering, tech-aware extensions |
| `vulnscan/idor_scanner.py` | ✅ Live | IDOR detection — path/param ID enumeration, UUID probing, horizontal privilege escalation, mass assignment |
| `vulnscan/safe_validator.py` | ✅ Live | SQLi / XSS / SSRF / XXE / CORS / CRLF / open redirect |
| `vulnscan/advanced_attacks.py` | ✅ Live | JWT forging, race conditions, request smuggling, GraphQL, SSH credential spray |
| `vulnscan/fp_suppress.py` | ✅ Live | Two-stage FP suppression with baseline noise measurement |
| `vulnscan/zeroday_engine.py` | ✅ Live | Behavioural fuzzing: buffer overflow, format string, auth bypass |
| `vulnscan/api_scanner.py` | ✅ Live | BOLA/IDOR, GraphQL, REST parameter fuzzing |
| `vulnscan/sqlmap_runner.py` | ✅ Live | Auto-runs sqlmap on confirmed SQLi candidates |
| `vulnscan/msf_client.py` | ✅ Live | Metasploit RPC (requires `--enable-exploitation` + msfrpcd) |
| `ml/risk_model.py` | ✅ Live | CVSS prediction, NVD/EPSS enrichment, KEV flag |
| `ml/ai_brain.py` | ✅ Live | Bayesian host prioritisation with cross-scan memory |
| `mitre/attack_mapper.py` | ✅ Live | ATT&CK technique mapping per finding |
| `mitre/kill_chain.py` | ✅ Live | Cyber Kill Chain coverage + attack path summary |
| `devsecops/pdf_report.py` | ✅ Live | Professional HTML/PDF report — cover page, executive summary, CVSS v3.1 vectors, MITRE ATT&CK mapping, remediation roadmap, SLA per finding |
| `devsecops/compliance_report.py` | ✅ Live | OWASP Top 10 / NIST CSF compliance mapping |
| `devsecops/alerting.py` | ✅ Live | Webhook alerting (Slack, Teams, custom) via aiohttp |
| `security/vault.py` | ✅ Live | AES-256-GCM credential vault |
| `security/audit.py` | ✅ Live | HMAC-signed append-only audit log |
| `api/server.py` | ✅ Live | FastAPI + JWT RBAC + WebSocket + rate limiting |
| `db/connection.py` | ✅ Live | PostgreSQL (asyncpg pool + SQLAlchemy ORM) · SQLite offline fallback · SSL · retry/backoff · health check · bulk insert |
| `db/models.py` | ✅ Live | 23-table SQLAlchemy 2.0 async ORM (engagements, DNS, SSL, web paths, credentials, MITRE, topology, cloud, reports, audit, tags, notes) |
| `db/repository.py` | ✅ Live | Typed async repository / DAL — ScanRepo · AssetRepo · VulnRepo · EngagementRepo · WebPathRepo · AuditRepo · ReportRepo |
| Web UI | ✅ Live | Dark matrix theme, scan launcher, live findings, kill chain |

</div>

---

<a id="quick-start"></a>
## 🚀 Quick Start

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:A8FF3E,50:00CFFF,100:7B2FBE"/>
</p>

### Requirements

- **Python 3.11+**
- **Git**
- `nmap` — `apt install nmap` / `brew install nmap`
- `nuclei` (recommended) — [projectdiscovery.io/open-source/nuclei](https://projectdiscovery.io/open-source/nuclei)
- `ffuf` (optional, faster dir fuzzing) — [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)
- `sqlmap` (optional, deep SQLi exploitation) — `pip install sqlmap`

### 1. Install

```bash
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
```

The installer:
1. Creates a Python virtual environment
2. Installs all dependencies
3. Writes a global `heaven` wrapper to `/usr/local/bin` (system-wide) or `~/.local/bin` (user)
4. Builds the React web UI (if npm is available)

> **Linux users:** If the installer placed `heaven` in `~/.local/bin`, run `source ~/.bashrc` (or `~/.zshrc`) **once** after install. All future terminals will have `heaven` in PATH automatically.

To uninstall:
```bash
chmod +x uninstall.sh && ./uninstall.sh
```

### 2. Configure

```bash
# Required — API and web UI login
export HEAVEN_ADMIN_PASSWORD="your-strong-password"

# Optional enrichments
export SHODAN_API_KEY="your-shodan-key"          # passive recon
export HEAVEN_ENGAGEMENT="client-webapp-q3"      # default engagement name

# Optional — Metasploit integration
export HEAVEN_MSF_HOST="127.0.0.1"
export HEAVEN_MSF_PORT="55553"
export HEAVEN_MSF_PASSWORD="msf-rpc-password"
```

Add to `~/.bashrc` or `~/.zshrc` to persist.

### 3. Scan

```bash
# Verify installation
heaven --version

# Create an engagement
heaven engage init my-engagement

# Web application scan (requires authorization)
heaven scan -u https://target.example.com -m web --i-have-authorization

# Network scan
heaven scan -t 10.0.0.0/24 -m network --i-have-authorization

# Full scan (web + network + deep recon)
heaven scan -u https://app.example.com -t 10.0.0.1 -m full \
    --engagement my-engagement --stealth 2 --i-have-authorization

# Start the web UI
heaven serve
# → Open http://localhost:8443
```

---

<a id="installation-detailed"></a>
## 🔧 Installation (Detailed)

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:7B2FBE,50:FF073A,100:FFF176"/>
</p>

### macOS

```bash
brew install python@3.12
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
```

### Linux (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap git
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
source ~/.bashrc   # activate PATH for current terminal (one-time only)
```

### Linux (Fedora / RHEL / CentOS)

```bash
sudo dnf install -y python3 python3-venv nmap git
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
source ~/.bashrc
```

### Docker

The Dockerfile is a **3-stage build**: Node 20 compiles the React UI → Python 3.12 installs all packages → a lean runtime image bundles both. The API server at `:8443` serves the compiled UI automatically.

```bash
# Build (requires Docker 20+ with BuildKit)
docker build -t heaven .

# Quick single-container run (SQLite offline mode, no Postgres needed)
docker run -it --rm \
    -e HEAVEN_ADMIN_PASSWORD=yourpassword \
    -p 127.0.0.1:8443:8443 \
    heaven

# Full stack with PostgreSQL (recommended for persistent engagements)
cp .env.example .env          # fill in HEAVEN_DB_PASSWORD + HEAVEN_ADMIN_PASSWORD
docker compose up -d
```

---

<a id="cli-reference"></a>
## ⌨️ CLI Reference

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:A8FF3E,33:00CFFF,66:7B2FBE,100:FF073A"/>
</p>

```bash
heaven --help        # list all commands
heaven --version     # show version
```

### Engagement Management

```bash
heaven engage init <name>      # create a new engagement
heaven engage list             # list all engagements
heaven scope add <target>      # add target to scope
heaven scope list              # show scope
```

### Scanning

```bash
heaven scan \
    -u <url>               \   # web target (URL)
    -t <ip/cidr>           \   # network target (IP or CIDR)
    -m <mode>              \   # web | network | full | ad | cloud
    --stealth <1-5>        \   # 1=ghost … 5=loud
    --engagement <name>    \   # engagement context
    --ports <spec>         \   # port range e.g. "1-1024" or "22,80,443"
    --i-have-authorization     # required — confirms written permission

heaven resume --engagement <name> --i-have-authorization   # resume interrupted scan
```

**Scan modes:**

| Mode | Modules Activated |
|---|---|
| `web` | Crawl → Nuclei → SQLi (error/boolean/time-blind) · XSS · SSRF · IDOR · Dir fuzzing · JWT · race · smuggling · GraphQL → FP suppress → sqlmap |
| `network` | nmap → service enum → dynamic injection (SSH/SMB/RDP) → CVE lookup |
| `full` | web + network + deep recon + Shodan + cloud enum |
| `ad` | AD enum → Kerberoasting → AS-REP roasting → privilege path analysis |
| `cloud` | AWS S3/IAM/EC2 enumeration; GCP/Azure basic |

**Stealth levels:**

| Level | Description |
|---|---|
| 1 — Ghost | Very slow, maximum evasion, randomized timing |
| 2 — Cautious | Slow, randomized, honeypot avoidance |
| 3 — Normal | Balanced speed / stealth |
| 4 — Aggressive | Faster, minimal evasion |
| 5 — Loud | Full speed, no evasion (lab use only) |

### Findings

```bash
heaven findings list                         # list all findings
heaven findings list --severity critical     # filter by severity
heaven findings list --min-confidence 0.8   # filter by confidence
heaven findings show <id>                    # full evidence + curl repro
heaven findings mark <id> verified           # triage workflow
heaven findings mark <id> false_positive     # dismiss
heaven findings replay <id>                  # print curl command to re-test
```

### Reporting

```bash
heaven export -o report.md     --format markdown
heaven export -o report.csv    --format csv
heaven export -o report.json   --format json
heaven export -o report.sarif  --format sarif          # GitHub code scanning
heaven export -o report.xml    --format burp            # import into Burp Suite
heaven export -o history.jsonl --format proxy-jsonl    # mitmproxy / Caido

# Compliance-mapped HTML report
heaven report --framework OWASP_TOP10 -o compliance.html
heaven report --framework NIST_CSF    -o compliance.html

# MITRE ATT&CK kill chain coverage
heaven kill-chain
heaven kill-chain -o kill-chain.json
```

### Server

```bash
heaven serve                                # start API + web UI on :8443
heaven serve --host 0.0.0.0 --port 8443    # bind to all interfaces
heaven self-audit                           # security baseline check
```

### Model

```bash
heaven train-model    # retrain CVSS predictor on NVD data
```

---

<a id="web-ui"></a>
## 🖥️ Web UI

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FFF176,50:A8FF3E,100:00CFFF"/>
</p>

Start with `heaven serve`, then open `http://localhost:8443`.

<div align="center">

| Page | Description |
|---|---|
| **Dashboard** | Engagement stats, severity distribution, MITRE ATT&CK coverage heat-map |
| **Scans** | Launch scans, view history, live progress with phase indicators |
| **Findings** | Full finding list — filter by severity, confidence, status, vuln type |
| **Finding Detail** | Evidence package, request/response, curl repro, triage controls, operator notes |
| **Kill Chain** | Cyber Kill Chain phase coverage, chained attack path summary |
| **Engagement** | Scope management, target list, configuration |
| **API Docs** | OpenAPI / Swagger interactive docs at `/docs` |

</div>

---

<a id="api"></a>
## 🌐 API

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:7B2FBE,50:FF073A,100:A8FF3E"/>
</p>

HEAVEN exposes a REST + WebSocket API on port 8443. All write endpoints require JWT auth.

```bash
# Health check (no auth)
curl http://localhost:8443/api/health

# Login → receive JWT
curl -X POST http://localhost:8443/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'

# List findings
curl http://localhost:8443/api/engagement/findings \
     -H "Authorization: Bearer <token>"

# Launch scan
curl -X POST http://localhost:8443/api/scans \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "targets": ["https://app.example.com"],
       "mode": "web",
       "i_have_authorization": true
     }'

# Add manual finding
curl -X POST http://localhost:8443/api/engagement/findings \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "https://app.example.com/admin",
       "vuln_type": "idor",
       "title": "Unauthenticated admin panel access",
       "severity": "critical",
       "confidence": 0.95
     }'
```

Full interactive docs: `http://localhost:8443/docs`

WebSocket live feed: `ws://localhost:8443/ws/scans/<scan_id>`

---

<a id="integrations"></a>
## 🔌 Integrations

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:00CFFF,50:FFF176,100:7B2FBE"/>
</p>

### Nuclei

HEAVEN runs nuclei automatically when it is in PATH. Keep templates up to date:

```bash
nuclei -update-templates
which nuclei   # must be in PATH
```

### sqlmap

Runs automatically on findings where HEAVEN confirms a SQLi candidate at HIGH severity or above:

```bash
which sqlmap   # must be in PATH
# pip install sqlmap  or  apt install sqlmap
```

### Shodan

```bash
export SHODAN_API_KEY="your-key"
heaven scan -t example.com -m full --i-have-authorization
# Shodan data is automatically merged into RECON results
```

### Metasploit

```bash
# 1. Start msfrpcd
msfrpcd -P your-password -S -f

# 2. Set env vars
export HEAVEN_MSF_HOST=127.0.0.1
export HEAVEN_MSF_PORT=55553
export HEAVEN_MSF_PASSWORD=your-password

# 3. Scan with exploitation enabled (requires explicit flag)
heaven scan -t 10.0.0.1 --enable-exploitation --i-have-authorization
```

### Webhook Alerting (Slack / Teams / Custom)

```bash
export HEAVEN_WEBHOOK_URL="https://hooks.slack.com/services/..."
# Critical findings will be POSTed to this webhook automatically
```

---

<a id="cvss-risk-scoring"></a>
## 📊 CVSS & Risk Scoring

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FF073A,50:A8FF3E,100:00CFFF"/>
</p>

HEAVEN computes realistic severity scores using a four-layer pipeline:

<div align="center">

| Layer | Source | Detail |
|---|---|---|
| 1 | **Vuln-type rules** | `docker_socket_exposed`→9.8 · `sqli`→9.0 · `xss`→6.1 etc. |
| 2 | **CVSS vector** | Parsed from finding evidence if available |
| 3 | **ML predictor** | `NVD_model.pkl` — ExtraTreesRegressor · R²=0.9925 · 13 features |
| 4 | **NVD enrichment** | Real CVE CVSS score when a CVE ID is known |

</div>

The final **priority score** combines: CVSS base + EPSS percentile + KEV flag + asset exposure + attack chain potential.

Retrain the model at any time with real NVD data:
```bash
heaven train-model
```

---

<a id="active-directory"></a>
## 🏢 Active Directory

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:A8FF3E,50:7B2FBE,100:FF073A"/>
</p>

HEAVEN performs full AD attack-path enumeration:

```bash
heaven scan -t 192.168.1.10 -m ad --i-have-authorization
```

**Output includes:**

- **Kerberoastable accounts** → `$krb5tgs$` hashes, ready for hashcat
- **AS-REP roastable accounts** → `$krb5asrep$` hashes (no credentials needed)
- **Domain users / computers / groups** enumerated via impacket
- **Privilege path analysis** — who can reach Domain Admin from current position
- **Shares and ACL weaknesses** — writable shares, excessive permissions

---

<a id="false-positive-handling"></a>
## 🛡️ False-Positive Handling

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FFF176,50:FF073A,100:A8FF3E"/>
</p>

Every finding goes through a two-stage process before it reaches the report:

1. **Primary validator** — sends real payloads, checks for evidence signals (error patterns, timing delays, reflection, header injection)
2. **FP suppressor** — re-sends benign probes to establish a noise baseline, then checks whether the original signal is reproducible above the noise floor

<div align="center">

| Bucket | Range | Interpretation |
|---|---|---|
| `strong` | ≥0.95 | Two independent signals confirmed |
| `high` | ≥0.80 | One confirmed signal, reproducible |
| `medium` | ≥0.60 | One signal, not fully reproducible |
| `low` | ≥0.40 | Probable FP — heavily caveated |
| `discarded` | <0.40 | Automatically suppressed — never reported |

</div>

> Time-based SQLi is confirmed only when the delay is reproducible in ≥2/3 independent requests AND at least 2.5 s above the mean baseline ± 5× baseline stdev.

---

<a id="security"></a>
## 🔒 Security Controls

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:7B2FBE,50:00CFFF,100:FFF176"/>
</p>

<div align="center">

| Control | Implementation |
|---|---|
| **Authentication** | JWT (HS256), 8-hour expiry, refresh token support |
| **Brute-force protection** | 5 failed attempts → 15-minute lockout |
| **Audit log** | HMAC-SHA256 signed, append-only, all operator actions recorded |
| **Credential storage** | AES-256-GCM vault, master key from environment |
| **API authorization** | Role-based: `vuln.read` · `vuln.create` · `scan.run` · `admin` |
| **HTTP security headers** | X-Frame-Options · X-Content-Type-Options · HSTS · Referrer-Policy · CSP |
| **Scope enforcement** | Every scan target validated against declared engagement scope |
| **Authorization gate** | `--i-have-authorization` required on every scan; interactive confirm on TTY |

</div>

---

<a id="troubleshooting"></a>
## 🔧 Troubleshooting

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FF073A,50:FFF176,100:A8FF3E"/>
</p>

### `heaven: command not found` after install

**Cause:** `~/.local/bin` was not yet in your PATH for the current terminal session.

```bash
source ~/.bashrc      # bash
source ~/.zshrc       # zsh
# or open a new terminal
```

If that doesn't work, use the full path directly:
```bash
/path/to/HEAVEN-Autonomous-Penetration-Testing/venv/bin/python -m heaven.main --version
```

### `nmap: command not found`

```bash
sudo apt install nmap        # Debian/Ubuntu
sudo dnf install nmap        # Fedora/RHEL
brew install nmap            # macOS
```

### Nuclei not finding vulnerabilities

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Web scan shows no findings

1. Confirm the target URL is reachable: `curl -I https://target`
2. Confirm you passed `--i-have-authorization`
3. Check scan logs: `heaven status --engagement <name>`

### ImportError on startup

```bash
cd HEAVEN-Autonomous-Penetration-Testing
venv/bin/pip install -r requirements.txt
venv/bin/pip install -e .
```

### `HEAVEN_ADMIN_PASSWORD` not set

```bash
export HEAVEN_ADMIN_PASSWORD="your-strong-password"
heaven serve
```

---

<a id="development"></a>
## 🛠️ Development

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:00CFFF,50:A8FF3E,100:7B2FBE"/>
</p>

```bash
# Clone and set up dev environment
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with auto-reload
uvicorn heaven.api.server:create_app --factory --reload --port 8443

# Rebuild UI
cd heaven-ui && npm install --legacy-peer-deps && npm run build

# Lint
ruff check heaven/
```

---

<a id="project-structure"></a>
## 📁 Project Structure

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:A8FF3E,50:FF073A,100:FFF176"/>
</p>

```
HEAVEN-Autonomous-Penetration-Testing/
│
├── 🐍 heaven/                      ← Python package
│   ├── api/                        ← FastAPI server + WebSocket
│   ├── recon/                      ← Reconnaissance modules (7 modules)
│   ├── vulnscan/                   ← Vulnerability detection + FP suppression (10 modules)
│   ├── ml/                         ← Risk scoring + ML pipeline
│   ├── mitre/                      ← ATT&CK mapping + kill chain
│   ├── devsecops/                  ← Reporting + alerting + compliance
│   ├── security/                   ← Auth · vault · audit log
│   ├── db/                         ← Database layer (Ultra Edition)
│   │   ├── schema.sql              ← PostgreSQL schema (23 tables, 9 views, 4 functions, partitioned audit log)
│   │   ├── models.py               ← SQLAlchemy 2.0 async ORM models
│   │   ├── connection.py           ← asyncpg pool + ORM engine + SQLite fallback + health check
│   │   └── repository.py           ← Typed async DAL — 8 repository classes
│   ├── main.py                     ← CLI entry point (Click)
│   ├── orchestrator.py             ← Async DAG scan engine
│   ├── engagement.py               ← Finding + engagement storage (SQLite)
│   └── config.py                   ← Configuration + env vars
│
├── ⚛️  heaven-ui/                   ← React frontend (Vite)
│   └── dist/                       ← Pre-built, served by FastAPI
│
├── 🧪 tests/                       ← 163 pytest tests
├── 🤖 NVD_model.pkl                ← Trained CVSS predictor (13-feature ExtraTrees, R²=0.9925)
├── 📊 nvd_data/                    ← NVD feature names + dataset
├── 🔧 install.sh                   ← One-command installer
├── 🗑️  uninstall.sh                ← Clean uninstaller
├── 🐳 Dockerfile                   ← Container support
└── 🐳 docker-compose.yml           ← Optional PostgreSQL stack
```

---

<a id="legal"></a>
## ⚠️ Legal & Disclaimer

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=rect&height=4&color=0:FF073A,50:FFF176,100:FF073A"/>
</p>

> **HEAVEN is a defensive and authorized-offensive security tool.**
>
> `--i-have-authorization` is **required** on every scan invocation. Only use HEAVEN against systems you own or have **explicit written permission** to test. Unauthorized use is illegal, unethical, and a criminal offence in most jurisdictions. All scan activity is HMAC-audited.
>
> The CVSS predictions, EPSS enrichments, and MITRE ATT&CK mappings are heuristic — they augment but do not replace qualified human security review. Findings should be validated by a certified penetration tester before remediation actions are taken in production.

---

<p align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&height=200&color=0:05070F,20:080F08,40:0A1F0A,60:1A3A00,80:A8FF3E,100:05070F&section=footer&text=Made%20with%20%F0%9F%94%90%20by%20Nisarg%20Chasmawala%20(HEAVEN)&fontSize=22&fontAlignY=65&fontColor=A8FF3E&animation=twinkling"/>
</p>

<p align="center">
<strong>163 tests · 31 live modules · PostgreSQL + SQLite · MIT License · Built for real-world pen-testing engagements</strong>
</p>

<p align="center">
<img src="https://img.shields.io/github/stars/nishu2402/HEAVEN-Autonomous-Penetration-Testing?style=social" alt="Stars"/>
<img src="https://img.shields.io/github/forks/nishu2402/HEAVEN-Autonomous-Penetration-Testing?style=social" alt="Forks"/>
<img src="https://img.shields.io/github/watchers/nishu2402/HEAVEN-Autonomous-Penetration-Testing?style=social" alt="Watchers"/>
</p>
