# HEAVEN ↔ Penetration Testing Execution Standard (PTES)

Mapping of HEAVEN modules against the seven [PTES phases](http://www.pentest-standard.org/).

Every technically-executable PTES item below is automated by a real HEAVEN
detector or tool feature, named explicitly. The items PTES leaves to human
judgement — business-context threat modelling, and the deliberately out-of-scope
post-exploitation actions (persistence, cleanup) an autonomous tool must never
perform — are listed per phase as **out-of-band (analyst-attested)** and are not
scored.

## Coverage summary

| Phase | HEAVEN coverage |
|---|---|
| 1. Pre-engagement Interactions | scope / SOW / authorization / RoE enforcement / comms |
| 2. Intelligence Gathering | passive + active recon, defense fingerprinting |
| 3. Threat Modeling | tactic priors + ATT&CK capability mapping |
| 4. Vulnerability Analysis | the full vulnscan suite + validation + CVE research |
| 5. Exploitation | evasion, tailored + planned exploitation, anomaly probing |
| 6. Post-Exploitation | infra analysis, pillaging (loot), high-value target scoring |
| 7. Reporting | exec + technical + export + remediation + MITRE + kill-chain |

## Detailed mapping

### Phase 1 — Pre-engagement Interactions
| PTES item | HEAVEN coverage |
|---|---|
| Scope definition | `heaven engage init`, `heaven scope add/import/list/remove` |
| Statement of Work | recorded in engagement DB on init (`--sow` flag) |
| Authorization | mandatory `--i-have-authorization`, `HEAVEN_AUTHORIZED_SCOPE` env, interactive TTY confirm — see `heaven/cli/_helpers.py::_verify_authorization` |
| Rules of engagement | `heaven/cli/_helpers.py` + `heaven.engagement` — scope boundaries are machine-enforced on every request (`is_in_scope`), so the RoE is codified and cannot be exceeded |
| Communications | optional Slack/Discord/Teams webhook (`heaven.devsecops.alerting`) |

### Phase 2 — Intelligence Gathering
| PTES item | HEAVEN coverage |
|---|---|
| Target selection | `heaven scope` (engagement scope DB) |
| Passive intel | `heaven.recon.shodan_recon`, `heaven.recon.dns_recon` |
| External infrastructure | `heaven.recon.network_scanner`, `heaven.recon.cloud_enum` |
| Identifying defenses | `heaven.recon.adaptive_intel` (WAF/IDS fingerprinting), `heaven.recon.firewall_detector` (perimeter firewall/IDS classification), `heaven.recon.honeypot_detector` |
| Active footprinting | `heaven.recon.deep_recon`, `heaven.recon.web_crawler`, `heaven.recon.ad_scanner` |

### Phase 3 — Threat Modeling
| PTES item | HEAVEN coverage |
|---|---|
| Threat agents/community | tactic priors in `heaven.ml.ai_brain` |
| Threat capability | `heaven.mitre.attack_mapper`, `heaven.mitre.kill_chain` |

**Out-of-band (analyst-attested):** business-asset analysis, business-process
analysis, motivation modelling and finding-relevant-news require organisational
context HEAVEN cannot observe by scanning; it surfaces the raw technical signals
an analyst uses to model them but does not assert the business verdict.

### Phase 4 — Vulnerability Analysis
| PTES item | HEAVEN coverage |
|---|---|
| Active scanning | `heaven.vulnscan` — 20+ modules covering SQLi/XSS/IDOR/SSL/auth/cmdi/etc. |
| Passive scanning | response header analysis in `heaven.recon.web_crawler` |
| Validation | `heaven.vulnscan.safe_validator` (re-runs each candidate finding) |
| Research | `heaven.vulnscan.cve_mapper` (CVE lookup + version-range matching) |

### Phase 5 — Exploitation
| PTES item | HEAVEN coverage |
|---|---|
| Counter-defensive techniques | `heaven.recon.evasion_engine` (WAF bypass headers, timing variance) |
| Customised exploitation avenue | `heaven.ai.attack_chain_planner` (deterministic + LLM-suggested chains) driving `heaven.vulnscan.advanced_attacks` |
| Tailored exploits | `heaven.vulnscan.advanced_attacks` |
| Zero-day angle | `heaven.vulnscan.anomaly_probe` (behavioural anomalies only — NOT real 0-day discovery; see module docstring) |

### Phase 6 — Post-Exploitation
| PTES item | HEAVEN coverage |
|---|---|
| Infrastructure analysis | `heaven.postex.bloodhound_collector` (AD relationships) |
| Pillaging | `heaven.postex` loot harvester (`heaven postex loot` — credential/config/secret harvest on an authorised session) |
| High-value target ID | `heaven.ml.risk_model` priority scoring |

**Out-of-band (analyst-attested):** persistence and cleanup are deliberately out
of scope — an autonomous scanner must never install persistence on, or tamper
with the state of, a target. These remain a human decision, never automated.

### Phase 7 — Reporting
| PTES item | HEAVEN coverage |
|---|---|
| Executive summary | `heaven.devsecops.compliance_report` (HTML report) |
| Technical report | `heaven.devsecops.pdf_report` (full evidence) |
| Findings export | `heaven export` — markdown, CSV, JSON, SARIF, Burp XML, mitmproxy JSONL |
| Remediation | `heaven.devsecops.ai_remediation` (LLM-generated patches) |
| MITRE mapping | `heaven mitre-report` (Navigator layer JSON) |
| Kill-chain coverage | `heaven kill-chain` |
