<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║       ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗        ║
║       ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║        ║
║       ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║        ║
║       ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║        ║
║       ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║        ║
║       ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

# HEAVEN — Autonomous Penetration Testing Framework

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-00ff41?style=flat-square&logo=python&logoColor=black)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00d4ff?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-112%20passing-00ff41?style=flat-square&logo=pytest&logoColor=black)](tests/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-6366f1?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-ff003c?style=flat-square)](https://attack.mitre.org)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20%2B%20API%20Top%2010-0088cc?style=flat-square)](https://owasp.org)

**Real-world autonomous penetration testing — not a simulation.**

*Find it. Confirm it. Report it. So you can focus on what only humans can do.*

</div>

---

## What is HEAVEN?

HEAVEN is a **production-grade autonomous penetration testing platform** that automates the repeatable, time-consuming parts of a professional engagement:

- **Reconnaissance** — nmap port scanning, web crawling, DNS brute-force, cert transparency, Shodan enrichment, Active Directory enumeration
- **Vulnerability detection** — Nuclei template scanning + custom validation engines for SQLi, XSS, SSRF, XXE, CORS, CRLF, open redirect, JWT attacks, race conditions, request smuggling, GraphQL introspection, and more
- **False-positive suppression** — every "finding" goes through a two-stage confirmation pass before it enters the report; sub-0.40-confidence results are automatically discarded
- **Risk scoring** — CVSS v3 prediction via a calibrated ML model (R²=0.9925) trained on NVD data, enriched with EPSS exploit-probability and CISA KEV membership
- **MITRE ATT&CK mapping** — every finding is mapped to ATT&CK techniques and Lockheed Cyber Kill Chain phases
- **Report generation** — Markdown, CSV, JSON, SARIF, Burp XML, proxy JSONL, and compliance-mapped HTML (OWASP Top 10 / NIST CSF)

The result: a professional-grade finding list with evidence packages, curl reproduction commands, triage workflow, and remediation patches — ready for your report in minutes, not days.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          HEAVEN Platform                                │
├──────────────────┬─────────────────────────┬────────────────────────────┤
│   RECON          │   VULNERABILITY DETECTION│   AI / RISK SCORING        │
│                  │                         │                            │
│ • nmap (XML)     │ • Nuclei templates       │ • CVSS 3.x ML predictor    │
│ • Web crawler    │ • SQLi (boolean/time/    │   (ExtraTreesRegressor,    │
│ • DNS brute-force│   error/union)           │   R²=0.9925, 13 features)  │
│ • Cert transp.   │ • XSS (reflected/stored) │ • EPSS exploit probability │
│ • Shodan API     │ • SSRF + cloud metadata  │ • CISA KEV flag            │
│ • AD enumeration │ • XXE / CRLF injection   │ • Bayesian host priority   │
│ • Cloud enum     │ • CORS misconfiguration  │ • Cross-scan belief update │
│   (AWS/GCP/Azure)│ • JWT (none/weak secret) │                            │
│ • IoT/SCADA      │ • Race conditions        │                            │
│ • Wireless recon │ • HTTP request smuggling │                            │
│ • Git secrets    │ • GraphQL introspection  │                            │
│ • Email OSINT    │ • Default credentials    │                            │
│ • Honeypot detect│ • Subdomain takeover     │                            │
├──────────────────┴─────────────────────────┴────────────────────────────┤
│              FALSE-POSITIVE SUPPRESSION (2-stage verification)          │
│   • Baseline noise measurement (timing / content-length jitter)        │
│   • Reproducibility checks (time-based: 2/3 passes, boolean: stdev)    │
│   • Confidence buckets: strong ≥0.95, high ≥0.80, discarded <0.40     │
├─────────────────────────────────────────────────────────────────────────┤
│                    ORCHESTRATOR (async DAG)                              │
│   • Dependency-aware parallel task execution                            │
│   • Dynamic task injection (services → SSH/SMB/RDP scanners)           │
│   • Resumable scans — checkpoint saved per phase                        │
│   • Stealth timing levels 1–5 with randomized delays                   │
├─────────────────────────────────────────────────────────────────────────┤
│              FastAPI + JWT RBAC + WebSocket live feed                   │
│   • React web UI — dark matrix aesthetic                                │
│   • Scan launcher  ·  Live findings feed  ·  3D topology                │
│   • Kill chain view  ·  Triage workflow  ·  Operator notes              │
│   • AES-256-GCM credential vault  ·  HMAC-signed audit log             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Status

| Module | Status | What it does |
|--------|:------:|--------------|
| `recon/network_scanner.py` | ✅ Live | Real nmap execution, XML parsing, OS detection, honeypot avoidance |
| `recon/web_crawler.py` | ✅ Live | BFS crawler, form/param discovery, JS endpoint extraction, auth support |
| `recon/deep_recon.py` | ✅ Live | DNS brute-force, cert transparency, OSINT enrichment |
| `recon/ad_scanner.py` | ✅ Live | AD enumeration, Kerberoasting, AS-REP hashes via impacket |
| `recon/shodan_recon.py` | ✅ Live | Passive host/org lookups (requires `SHODAN_API_KEY`) |
| `recon/cloud_enum.py` | ✅ AWS | GCP/Azure stubs present; AWS full |
| `recon/honeypot_detector.py` | ✅ Live | Heuristic honeypot scoring, automatic target skip |
| `vulnscan/nuclei_scanner.py` | ✅ Live | Real nuclei binary execution, JSONL output parsed |
| `vulnscan/safe_validator.py` | ✅ Live | SQLi / XSS / SSRF / XXE / CORS / CRLF / open redirect |
| `vulnscan/advanced_attacks.py` | ✅ Live | JWT forging, race conditions, request smuggling, GraphQL |
| `vulnscan/fp_suppress.py` | ✅ Live | Two-stage FP suppression with baseline noise measurement |
| `vulnscan/zeroday_engine.py` | ✅ Live | Behavioural fuzzing: buffer overflow, format string, auth bypass |
| `vulnscan/api_scanner.py` | ✅ Live | BOLA/IDOR, GraphQL, REST parameter fuzzing |
| `vulnscan/sqlmap_runner.py` | ✅ Live | Auto-runs sqlmap on confirmed SQLi candidates |
| `vulnscan/msf_client.py` | ✅ Live | Metasploit RPC (requires `--enable-exploitation` + msfrpcd) |
| `ml/risk_model.py` | ✅ Live | CVSS prediction, NVD/EPSS enrichment, KEV flag |
| `ml/ai_brain.py` | ✅ Live | Bayesian host prioritisation with cross-scan memory |
| `mitre/attack_mapper.py` | ✅ Live | ATT&CK technique mapping per finding |
| `mitre/kill_chain.py` | ✅ Live | Cyber Kill Chain coverage + attack path summary |
| `devsecops/pdf_report.py` | ✅ Live | Professional HTML/PDF report generation |
| `devsecops/compliance_report.py` | ✅ Live | OWASP Top 10 / NIST CSF compliance mapping |
| `devsecops/alerting.py` | ✅ Live | Webhook alerting (Slack, Teams, custom) via aiohttp |
| `security/vault.py` | ✅ Live | AES-256-GCM credential vault |
| `security/audit.py` | ✅ Live | HMAC-signed append-only audit log |
| `api/server.py` | ✅ Live | FastAPI + JWT RBAC + WebSocket + rate limiting |
| Web UI | ✅ Live | Dark matrix theme, scan launcher, live findings, kill chain |

---

## Quick Start

### Requirements

- **Python 3.11+**
- **Git**
- `nmap` (highly recommended) — `apt install nmap` / `brew install nmap`
- `nuclei` (recommended) — [projectdiscovery.io/open-source/nuclei](https://projectdiscovery.io/open-source/nuclei)

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

> **Linux users:** If the installer placed `heaven` in `~/.local/bin`, run `source ~/.bashrc` (or `~/.zshrc`) **once** after install, or open a new terminal. All future terminals will have `heaven` in PATH automatically.

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

Add these to your `~/.bashrc` or `~/.zshrc` to persist them.

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
# → Open http://localhost:8443 in your browser
```

---

## Installation (Detailed)

### macOS

```bash
# Install Python 3.11+ via Homebrew (if needed)
brew install python@3.12

git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
```

### Linux (Ubuntu / Debian)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-venv nmap git

# Clone and install
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh

# Activate PATH for current terminal (one-time only)
source ~/.bashrc
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

```bash
docker build -t heaven .
docker run -it --rm \
    -e HEAVEN_ADMIN_PASSWORD=yourpassword \
    -p 8443:8443 \
    heaven serve
```

---

## CLI Reference

```
heaven --help                              # list all commands
heaven --version                           # show version
```

### Engagement management

```bash
heaven engage init <name>                  # create a new engagement
heaven engage list                         # list all engagements
heaven scope add <target>                  # add target to scope
heaven scope list                          # show scope
```

### Scanning

```bash
heaven scan \
    -u <url>          \   # web target (URL)
    -t <ip/cidr>      \   # network target (IP or CIDR)
    -m <mode>         \   # web | network | full | ad | cloud
    --stealth <1-5>   \   # 1=ghost … 5=loud
    --engagement <name>\  # engagement context
    --ports <spec>    \   # port range e.g. "1-1024" or "22,80,443"
    --i-have-authorization   # required — confirms written permission

heaven resume --engagement <name> --i-have-authorization  # resume interrupted scan
```

**Scan modes:**

| Mode | Modules activated |
|------|-------------------|
| `web` | Crawl → Nuclei → SQLi/XSS/SSRF/JWT/race/smuggling/GraphQL → FP suppress |
| `network` | nmap → service enum → dynamic injection (SSH/SMB/RDP) → CVE lookup |
| `full` | web + network + deep recon + Shodan + cloud enum |
| `ad` | AD enum → Kerberoasting → AS-REP roasting → privilege path analysis |
| `cloud` | AWS S3/IAM/EC2 enumeration; GCP/Azure basic |

**Stealth levels:**

| Level | Description |
|-------|-------------|
| 1 — Ghost | Very slow, maximum evasion, randomized timing |
| 2 — Cautious | Slow, randomized, honeypot avoidance |
| 3 — Normal | Balanced speed / stealth |
| 4 — Aggressive | Faster, minimal evasion |
| 5 — Loud | Full speed, no evasion (lab use) |

### Findings

```bash
heaven findings list                        # list all findings
heaven findings list --severity critical    # filter by severity
heaven findings list --min-confidence 0.8  # filter by confidence
heaven findings show <id>                   # full evidence + curl repro
heaven findings mark <id> verified          # triage workflow
heaven findings mark <id> false_positive    # dismiss
heaven findings replay <id>                 # print curl command to re-test
```

### Reporting

```bash
# Export findings in various formats
heaven export -o report.md --format markdown
heaven export -o report.csv --format csv
heaven export -o report.json --format json
heaven export -o report.sarif --format sarif         # for GitHub code scanning
heaven export -o report.xml --format burp             # import into Burp Suite
heaven export -o history.jsonl --format proxy-jsonl  # for mitmproxy / Caido

# Compliance-mapped HTML report
heaven report --framework OWASP_TOP10 -o compliance.html
heaven report --framework NIST_CSF -o compliance.html

# MITRE ATT&CK kill chain coverage
heaven kill-chain
heaven kill-chain -o kill-chain.json
```

### Server

```bash
heaven serve                               # start API + web UI on :8443
heaven serve --host 0.0.0.0 --port 8443   # bind to all interfaces
heaven self-audit                          # security baseline check
```

### Model

```bash
heaven train-model                         # retrain CVSS predictor on NVD data
```

---

## Web UI

Start with `heaven serve`, then open `http://localhost:8443`.

| Page | Description |
|------|-------------|
| **Dashboard** | Engagement stats, severity distribution, MITRE ATT&CK coverage heat-map |
| **Scans** | Launch scans, view history, live progress with phase indicators |
| **Findings** | Full finding list — filter by severity, confidence, status, vuln type |
| **Finding Detail** | Evidence package, request/response, curl repro, triage controls, notes |
| **Kill Chain** | Cyber Kill Chain phase coverage, chained attack path summary |
| **Engagement** | Scope management, target list, configuration |
| **API Docs** | OpenAPI/Swagger interactive docs at `/docs` |

---

## API

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

## Integrations

### Nuclei (template-based scanning)

HEAVEN runs nuclei automatically when it is in PATH. Keep templates up to date:

```bash
nuclei -update-templates
which nuclei   # must be in PATH
```

### sqlmap (SQLi confirmation)

sqlmap runs automatically on findings where HEAVEN confirms a SQLi candidate at HIGH severity or above:

```bash
which sqlmap   # must be in PATH
# Install: pip install sqlmap  or  apt install sqlmap
```

### Shodan (passive recon)

```bash
export SHODAN_API_KEY="your-key"
heaven scan -t example.com -m full --i-have-authorization
# Shodan data is automatically merged into RECON results
```

### Metasploit (exploitation)

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

### Webhook alerting (Slack / Teams / custom)

```bash
export HEAVEN_WEBHOOK_URL="https://hooks.slack.com/services/..."
# Critical findings will be POSTed to this webhook automatically
```

---

## CVSS & Risk Scoring

HEAVEN computes realistic severity scores using a four-layer pipeline:

| Layer | Source | Detail |
|-------|--------|--------|
| 1 | **Vuln-type rules** | `docker_socket_exposed`→9.8, `sqli`→9.0, `xss`→6.1, etc. |
| 2 | **CVSS vector** | Parsed from finding evidence if available |
| 3 | **ML predictor** | `NVD_model.pkl` — ExtraTreesRegressor, R²=0.9925, 13 features |
| 4 | **NVD enrichment** | Real CVE CVSS score when a CVE ID is known |

The final **priority score** combines: CVSS base + EPSS percentile + KEV flag + asset exposure + attack chain potential.

Retrain the model at any time with real NVD data:
```bash
heaven train-model
```

---

## Active Directory

HEAVEN performs full AD attack-path enumeration:

```bash
heaven scan -t 192.168.1.10 -m ad --i-have-authorization
```

What it produces:
- **Kerberoastable accounts** → `$krb5tgs$` hashes, ready for hashcat
- **AS-REP roastable accounts** → `$krb5asrep$` hashes (no credentials needed)
- **Domain users / computers / groups** enumerated via impacket
- **Privilege path analysis** — who can reach Domain Admin from current position
- **Shares and ACL weaknesses** — writable shares, excessive permissions

---

## False-Positive Handling

Every confirmed or likely finding goes through a two-stage process before it reaches the report:

1. **Primary validator** — sends real payloads, checks for evidence signals (error patterns, timing delays, reflection, header injection)
2. **FP suppressor** — re-sends benign probes to establish a noise baseline, then checks whether the original signal is reproducible above the noise floor

Confidence buckets and their meaning:

| Bucket | Range | Interpretation |
|--------|-------|----------------|
| `strong` | ≥0.95 | Two independent signals confirmed |
| `high` | ≥0.80 | One confirmed signal, reproducible |
| `medium` | ≥0.60 | One signal, not fully reproducible |
| `low` | ≥0.40 | Probable FP — heavily caveated |
| `discarded` | <0.40 | Automatically suppressed, never reported |

Time-based SQLi is confirmed only when the delay is reproducible in ≥2/3 independent requests AND at least 2.5 s above the mean baseline ± 5× baseline stdev.

---

## Security

| Control | Implementation |
|---------|---------------|
| Authentication | JWT (HS256), 8-hour expiry, refresh token support |
| Brute-force protection | 5 failed attempts → 15-minute lockout |
| Audit log | HMAC-SHA256 signed, append-only, all operator actions recorded |
| Credential storage | AES-256-GCM vault, master key from environment |
| API authorization | Role-based: `vuln.read`, `vuln.create`, `scan.run`, `admin` |
| HTTP security headers | X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, CSP |
| Scope enforcement | Every scan target validated against declared engagement scope |
| Authorization gate | `--i-have-authorization` required on every scan; interactive confirm on TTY |

---

## Troubleshooting

### `heaven: command not found` after install

**Cause:** `~/.local/bin` was not yet in your PATH for the current terminal session.

**Fix:**
```bash
source ~/.bashrc      # bash users
# or
source ~/.zshrc       # zsh users
# or simply open a new terminal window
```

If that does not work, use the full path directly:
```bash
/path/to/HEAVEN-Autonomous-Penetration-Testing/venv/bin/python -m heaven.main --version
```

### `nmap: command not found`

Network scanning requires nmap. Install it:
```bash
# Linux
sudo apt install nmap        # Debian/Ubuntu
sudo dnf install nmap        # Fedora/RHEL

# macOS
brew install nmap
```

### Nuclei not finding vulnerabilities

Ensure nuclei is installed and templates are up to date:
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Web scan shows no findings

Check that:
1. The target URL is reachable: `curl -I https://target`
2. You passed `--i-have-authorization`
3. The web crawler found pages: check scan logs with `heaven status --engagement <name>`

### ImportError on startup

A dependency may have failed to install. Reinstall in the venv:
```bash
cd HEAVEN-Autonomous-Penetration-Testing
venv/bin/pip install -r requirements.txt
venv/bin/pip install -e .
```

### `HEAVEN_ADMIN_PASSWORD` not set

The API server requires this env var. Set it and restart:
```bash
export HEAVEN_ADMIN_PASSWORD="your-strong-password"
heaven serve
```

---

## Development

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

### Project Structure

```
HEAVEN-Autonomous-Penetration-Testing/
├── heaven/                 # Python package
│   ├── api/                # FastAPI server + WebSocket
│   ├── recon/              # Reconnaissance modules
│   ├── vulnscan/           # Vulnerability detection + FP suppression
│   ├── ml/                 # Risk scoring + ML pipeline
│   ├── mitre/              # ATT&CK mapping + kill chain
│   ├── devsecops/          # Reporting + alerting + compliance
│   ├── security/           # Auth, vault, audit log
│   ├── main.py             # CLI entry point (Click)
│   ├── orchestrator.py     # Async DAG scan engine
│   ├── engagement.py       # Finding + engagement storage (SQLite)
│   └── config.py           # Configuration + env vars
├── heaven-ui/              # React frontend (Vite)
│   └── dist/               # Pre-built, served by FastAPI
├── tests/                  # 112 pytest tests
├── NVD_model.pkl           # Trained CVSS predictor (13-feature ExtraTrees)
├── nvd_data/               # NVD feature names + dataset
├── install.sh              # One-command installer
├── uninstall.sh            # Clean uninstaller
├── Dockerfile              # Container support
└── docker-compose.yml      # Optional PostgreSQL stack
```

---

## Legal

> HEAVEN includes a mandatory authorization gate.
> `--i-have-authorization` is required on every scan invocation.
> Only use HEAVEN against systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal and unethical. All scan activity is HMAC-audited.

---

<div align="center">

**112 tests · MIT License · Built for real-world pen-testing engagements**

Developed by [Nisarg Chasmawala (Shroff)](https://github.com/nishu2402)

</div>
