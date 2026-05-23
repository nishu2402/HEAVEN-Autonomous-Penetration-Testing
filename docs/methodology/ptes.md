# HEAVEN ↔ Penetration Testing Execution Standard (PTES)

Mapping of HEAVEN modules against the seven [PTES phases](http://www.pentest-standard.org/).

## Coverage summary

| Phase | Automated | Partial | Manual / out of scope |
|---|---|---|---|
| 1. Pre-engagement Interactions | scope mgmt, authorization gate | engagement letter | client meetings |
| 2. Intelligence Gathering | extensive | active recon | OSINT analyst work |
| 3. Threat Modeling | tactic mapping | risk scoring | business context |
| 4. Vulnerability Analysis | extensive | fingerprint correlation | manual review |
| 5. Exploitation | depth limited | sqlmap integration | targeted exploits |
| 6. Post-Exploitation | new (`heaven/postex/`) | lateral movement | data identification |
| 7. Reporting | extensive | exec summary | narrative writing |

## Detailed mapping

### Phase 1 — Pre-engagement Interactions
| PTES item | HEAVEN coverage |
|---|---|
| Scope definition | `heaven engage init`, `heaven scope add/import/list/remove` |
| Statement of Work | recorded in engagement DB on init (`--sow` flag) |
| Authorization | mandatory `--i-have-authorization`, `HEAVEN_AUTHORIZED_SCOPE` env, interactive TTY confirm — see `heaven/cli/_helpers.py::_verify_authorization` |
| Rules of engagement | (manual — operator-defined) |
| Communications | optional Slack/Discord/Teams webhook (`heaven/devsecops/alerting.py`) |

### Phase 2 — Intelligence Gathering
| PTES item | HEAVEN coverage |
|---|---|
| Target selection | scope DB |
| Passive intel | `heaven.recon.shodan_recon`, `heaven.recon.dns_recon` |
| External infrastructure | `heaven.recon.network_scanner`, `heaven.recon.cloud_enum` |
| Identifying defenses | `heaven.recon.adaptive_intel` (WAF/IDS fingerprinting), `heaven.recon.honeypot_detector` |
| Active footprinting | `heaven.recon.deep_recon`, `heaven.recon.web_crawler`, `heaven.recon.ad_scanner` |

### Phase 3 — Threat Modeling
| PTES item | HEAVEN coverage |
|---|---|
| Business asset analysis | (manual) |
| Business process analysis | (manual) |
| Threat agents/community | tactic priors in `heaven/ml/ai_brain.py` |
| Threat capability | `heaven.mitre.attack_mapper`, `heaven.mitre.kill_chain` |
| Motivation modeling | (manual) |
| Finding relevant news | (manual) |

### Phase 4 — Vulnerability Analysis
| PTES item | HEAVEN coverage |
|---|---|
| Active scanning | `heaven/vulnscan/*` — 20+ modules covering SQLi/XSS/IDOR/SSL/auth/cmdi/etc. |
| Passive scanning | response header analysis in `heaven/recon/web_crawler.py` |
| Validation | `heaven/vulnscan/safe_validator.py` (re-runs each candidate finding) |
| Research | `heaven/vulnscan/cve_mapper.py` (CVE lookup + version-range matching) |

### Phase 5 — Exploitation
| PTES item | HEAVEN coverage |
|---|---|
| Counter-defensive techniques | `heaven/recon/evasion_engine.py` (WAF bypass headers, timing variance) |
| Customised exploitation avenue | (manual + `heaven.ai.attack_chain_planner` for LLM-suggested chains) |
| Tailored exploits | `heaven/vulnscan/advanced_attacks.py` |
| Zero-day angle | `heaven/vulnscan/anomaly_probe.py` (behavioural anomalies only — NOT real 0-day discovery; see module docstring) |

### Phase 6 — Post-Exploitation
| PTES item | HEAVEN coverage |
|---|---|
| Infrastructure analysis | `heaven/postex/bloodhound_collector.py` (AD relationships) |
| Pillaging | (manual) |
| High-value target ID | `heaven/ml/risk_model.py` priority scoring |
| Persistence | (manual — out of scope for autonomous tool) |
| Cleanup | (manual) |

### Phase 7 — Reporting
| PTES item | HEAVEN coverage |
|---|---|
| Executive summary | `heaven/devsecops/compliance_report.py` (HTML report) |
| Technical report | `heaven/devsecops/pdf_report.py` (full evidence) |
| Findings export | `heaven export` — markdown, CSV, JSON, SARIF, Burp XML, mitmproxy JSONL |
| Remediation | `heaven/devsecops/ai_remediation.py` (LLM-generated patches) |
| MITRE mapping | `heaven mitre-report` (Navigator layer JSON) |
| Kill-chain coverage | `heaven kill-chain` |
