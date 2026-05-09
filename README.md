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

HEAVEN is a real-world autonomous penetration testing platform that automates the **repetitive parts** of an engagement — reconnaissance, vulnerability detection, CVSS scoring, MITRE ATT&CK mapping, false-positive suppression, and report generation — so you can focus on what actually requires human judgment: scope decisions, business logic, exploit chaining, and client communication.

It runs as a local daemon with a **dark-themed web UI** you open in your browser. Scans can be launched from the UI or CLI. All findings are stored per-engagement with full evidence packages, triage workflow, and operator notes.

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                      HEAVEN Platform                        │
├────────────────┬────────────────────┬───────────────────────┤
│   RECON        │   VULN DETECTION   │   AI / SCORING        │
│                │                    │                       │
│ • nmap (XML)   │ • Nuclei templates │ • CVSS from severity  │
│ • web crawler  │ • JWT forging      │   + vuln type         │
│ • deep_recon   │ • SQLi / XSS       │ • Bayesian host prio  │
│ • Shodan API   │ • SSRF / XXE       │ • NVD/EPSS enrichment │
│ • DNS brute    │ • race conditions  │ • KEV tracking        │
│ • cert transp  │ • request smuggle  │ • cross-scan beliefs  │
│ • AD enum      │ • subdomain tkover │                       │
├────────────────┴────────────────────┴───────────────────────┤
│                   ORCHESTRATOR (async DAG)                  │
│   • Parallel task execution with dependency tracking        │
│   • Dynamic task injection (SSH/SMB/RDP detected services)  │
│   • Resumable scans (checkpoint per phase)                  │
│   • Stealth timing (levels 1–5)                             │
├─────────────────────────────────────────────────────────────┤
│              FastAPI + JWT RBAC + WebSocket                 │
│   • React web UI (dark matrix terminal aesthetic)           │
│   • Scan launcher with authorization gate                   │
│   • Live findings feed · Kill chain · Topology              │
│   • Manual finding entry · Operator triage workflow         │
│   • AES-256 credential vault · HMAC audit log               │
└─────────────────────────────────────────────────────────────┘
```

---

## Feature Status

| Module | Status | Notes |
|--------|--------|-------|
| **Reconnaissance** | | |
| `network_scanner.py` | ✅ Live | Real nmap execution, XML parsing, evasion timing |
| `web_crawler.py` | ✅ Live | aiohttp crawl, form/API discovery, auth_config support |
| `web_crawler.py` JS | ✅ Live | Optional Playwright backend for JS-heavy SPAs |
| `deep_recon.py` | ✅ Live | DNS brute-force, cert transparency, OSINT (wired) |
| `ad_scanner.py` | ✅ Live | AD enum, Kerberoast + AS-REP hash extraction |
| `shodan_recon.py` | ✅ Live | Passive host/domain/org lookups via Shodan API |
| `cloud_enum.py` | ✅ AWS | GCP/Azure stubs present (AWS full) |
| **Vulnerability Detection** | | |
| `nuclei_scanner.py` | ✅ Live | Real nuclei binary execution |
| `advanced_attacks.py` | ✅ Wired | JWT forging, race conditions, smuggling, default creds |
| `zeroday_engine.py` | ✅ Wired | Heuristic fuzzing (wired into scan DAG) |
| `adaptive_intel.py` | ✅ Live | WAF fingerprinting with live probes |
| **Exploitation** | | |
| `sqlmap_runner.py` | ✅ Live | Runs sqlmap on confirmed SQLi candidates |
| `msf_client.py` | ✅ Live | Metasploit RPC (requires `--enable-exploitation` + msfrpcd) |
| **AI / Scoring** | | |
| `feature_engine.py` | ✅ Fixed | CVSS derived from severity + vuln type (realistic scores) |
| `risk_model.py` | ✅ Live | CVSS prediction, NVD/EPSS enrichment, KEV flag |
| `ai_brain.py` | ✅ Live | Bayesian host prioritisation with cross-scan persistence |
| **API & UI** | | |
| `api/server.py` | ✅ Live | FastAPI + JWT RBAC + WebSocket + security headers |
| Web UI | ✅ Live | Dark matrix theme, 3D topology, kill chain, scan launcher |
| Manual findings | ✅ Live | POST `/api/engagement/findings` + UI form |
| **Security** | | |
| `security/vault.py` | ✅ Live | AES-256 credential storage |
| `security/audit.py` | ✅ Live | HMAC-signed audit log, rate limiting |
| Auth lockout | ✅ Live | Brute-force protection (5 attempts → 15 min lockout) |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing.git
cd HEAVEN-Autonomous-Penetration-Testing
chmod +x install.sh && ./install.sh
```

The installer:
- Creates a Python virtual environment
- Installs dependencies via `uv`
- Creates a global `heaven` command for your user (typically `~/.local/bin/heaven`)
- Adds the user bin directory to your PATH

Uninstall:
```bash
chmod +x uninstall.sh && ./uninstall.sh
```

Note: If you ran `install.sh` with `sudo`, make sure you open a new terminal after install (PATH changes are written to the invoking user’s shell config).



### 2. Configure

```bash
# Required
export HEAVEN_ADMIN_PASSWORD="your-strong-password"

# Optional but recommended
export HEAVEN_ENGAGEMENT="acme-webapp-q2"   # engagement name
export SHODAN_API_KEY="your-shodan-key"      # passive recon enrichment

# For Metasploit integration (optional)
export HEAVEN_MSF_HOST="127.0.0.1"
export HEAVEN_MSF_PORT="55553"
export HEAVEN_MSF_PASSWORD="msf-rpc-password"
```

### 3. Start the server

```bash
heaven serve
```

Open your browser at `http://localhost:8443` and log in with `admin` / your `HEAVEN_ADMIN_PASSWORD`.

---

## Launching Scans

### From the Web UI

1. Open **Scans** in the sidebar
2. Enter target URLs or IPs (one per line or comma-separated)
3. Choose scan mode and stealth level
4. Check the **authorization confirmation** box
5. Click **Launch Scan**

The UI polls every 8 seconds and shows live progress.

### From the CLI

```bash
# Web application scan
heaven scan -u https://app.example.com -m web \
    --engagement acme-q2 --i-have-authorization

# Network scan (entire subnet)
heaven scan -t 10.0.0.0/24 -m network \
    --engagement acme-q2 --i-have-authorization

# Full scan (web + network + AD)
heaven scan -u https://app.example.com -t 10.0.0.1 -m full \
    --engagement acme-q2 --stealth 2 --i-have-authorization

# Active Directory scan
heaven scan -t 192.168.1.10 -m ad \
    --engagement acme-q2 --i-have-authorization

# Resume interrupted scan
heaven resume --engagement acme-q2 --i-have-authorization
```

**Scan modes:**
| Mode | What it does |
|------|-------------|
| `web` | Crawl + Nuclei + JWT/SSRF/race conditions + zeroday fuzzing |
| `network` | nmap + service enum + dynamic injection (SSH/SMB/RDP bruteforce) |
| `full` | Everything: web + network + deep recon + Shodan |
| `ad` | Active Directory enum + Kerberoasting + AS-REP hashes |
| `cloud` | Cloud provider enumeration (AWS full, GCP/Azure basic) |

**Stealth levels:**
| Level | Description |
|-------|-------------|
| 1 | Ghost — very slow, maximum evasion |
| 2 | Cautious — slow, randomized timing |
| 3 | Normal — balanced speed/stealth |
| 4 | Aggressive — faster, less evasion |
| 5 | Loud — full speed, no evasion |

---

## Web UI Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Real-time engagement stats, severity distribution, MITRE coverage |
| **Scans** | Launch scans from UI, view all scan history with live progress |
| **Findings** | Full finding list with severity/status/confidence filters |
| **Finding Detail** | Evidence package, curl repro, triage workflow, operator notes |
| **Kill Chain** | Cyber kill chain coverage with chained attack path |
| **Engagement** | Scope management, target configuration |

---

## API Reference

The API runs on port 8443 (HTTPS in production, HTTP in dev mode).

```bash
# Health check (no auth)
curl http://localhost:8443/api/health

# Login
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
     -d '{"targets":["https://app.example.com"],"mode":"web","i_have_authorization":true}'

# Add manual finding
curl -X POST http://localhost:8443/api/engagement/findings \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"target":"https://app.example.com/admin","vuln_type":"idor","title":"Unauthenticated admin access","severity":"critical","confidence":0.95}'
```

Full OpenAPI docs at `http://localhost:8443/docs`.

---

## Integrations

### Shodan (passive recon)

```bash
export SHODAN_API_KEY="your-key"
heaven scan -t example.com -m full --i-have-authorization
# Shodan host data is automatically merged into RECON results
```

### sqlmap (SQLi confirmation)

sqlmap runs automatically on findings where HEAVEN detects SQLi candidates with severity ≥ HIGH. Install sqlmap and it will be picked up:

```bash
which sqlmap   # must be in PATH
```

### Metasploit (exploitation)

```bash
# Start msfrpcd first
msfrpcd -P your-password -S -f

export HEAVEN_MSF_HOST=127.0.0.1
export HEAVEN_MSF_PORT=55553
export HEAVEN_MSF_PASSWORD=your-password

# Exploitation requires explicit flag
heaven scan -t 10.0.0.1 --enable-exploitation --i-have-authorization
```

### Nuclei (template-based detection)

HEAVEN runs nuclei automatically if it's installed:

```bash
nuclei -update-templates   # keep templates current
```

---

## CVSS Scoring

HEAVEN derives realistic CVSS scores automatically:

1. **Vuln-type override** — `docker_socket_exposed` → 9.8, `sqli` → 9.0, `xss` → 6.1, etc.
2. **Severity fallback** — critical → 9.0, high → 7.5, medium → 5.5, low → 3.5
3. **NVD enrichment** — real CVE CVSS when a CVE ID is present
4. **EPSS** — exploit prediction score merged if available
5. **KEV flag** — CISA known-exploited-vulnerabilities list checked

Priority score combines CVSS + EPSS + KEV + asset exposure + chain potential.

---

## Active Directory

When scanning AD environments, HEAVEN extracts actionable attack data:

```bash
heaven scan -t 192.168.1.10 -m ad --i-have-authorization
```

What it captures:
- **Kerberoastable accounts** → `$krb5tgs$` hashes (paste to hashcat)
- **AS-REP roastable accounts** → `$krb5asrep$` hashes (no creds needed)
- **Domain users, computers, groups** enumerated via impacket
- **Privilege paths** — who can reach DA from current position

---

## Security

| Control | Implementation |
|---------|---------------|
| Auth | JWT RS256, 8-hour expiry, refresh tokens |
| Lockout | 5 failed attempts → 15-minute lockout |
| Audit log | HMAC-signed, append-only, all operator actions |
| Credential storage | AES-256-GCM vault, master key from env |
| API authorization | Role-based: `vuln.read`, `vuln.create`, `scan.run` |
| HTTP security headers | X-Frame-Options, X-Content-Type, HSTS, Referrer-Policy |
| Scope enforcement | Target validation against declared engagement scope |

---

## Development

```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest tests/ -v

# Run with hot reload
uv run uvicorn heaven.api.server:create_app --factory --reload --port 8443

# Build UI
cd heaven-ui && npm install && npm run build
```

---

## Requirements

**Python 3.11+** · **uv** (auto-installed by install.sh)

**Recommended external tools** (auto-detected, graceful fallback if missing):
- `nmap` — network scanning
- `nuclei` — template-based detection
- `sqlmap` — SQL injection confirmation
- `msfrpcd` — Metasploit RPC (exploitation mode only)

---

## Legal

> HEAVEN includes a mandatory authorization gate — you must pass `--i-have-authorization` on every scan.
> Only use against systems you own or have explicit written permission to test.
> Unauthorized use is illegal. All scan activity is HMAC-audited.

---

<div align="center">

**108 tests · MIT License · Built for real-world engagements**

</div>
