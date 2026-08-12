# HEAVEN ↔ NIST Cybersecurity Framework (CSF) 2.0

Mapping of HEAVEN's detectors against the [NIST CSF
2.0](https://www.nist.gov/cyberframework) — six Functions (**Govern**,
**Identify**, **Protect**, **Detect**, **Respond**, **Recover**), each broken
into Categories.

The CSF is an outcome-based framework spanning governance to recovery. HEAVEN
provides direct technical evidence for the outcomes that are measurable by
scanning — chiefly **Identify → Risk Assessment (ID.RA)** and **Asset Management
(ID.AM)**, and **Protect → Platform Security (PR.PS)**, **Identity &
Authentication (PR.AA)** and **Data Security (PR.DS)**. Govern, Respond and
Recover are largely `(organizational)` outcomes attested through process.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Function | HEAVEN evidence |
|---|---|
| GOVERN (GV) | organizational; supply-chain risk partial |
| IDENTIFY (ID) | extensive — asset discovery & vulnerability/risk identification |
| PROTECT (PR) | extensive — auth, transport crypto, platform hardening |
| DETECT (DE) | partial — defense fingerprinting & continuous re-scan |
| RESPOND (RS) | organizational; alert delivery partial |
| RECOVER (RC) | organizational — recovery process |

## Detailed mapping

### GOVERN (GV)
Governance outcomes — organizational context, risk-management strategy, roles,
policy and oversight — are attested through the security programme.

| Control | Description | HEAVEN coverage |
|---|---|---|
| GV.OC | Organizational context established | (organizational — governance) |
| GV.RM | Risk management strategy | (organizational — governance) |
| GV.SC | Cybersecurity supply chain risk management | `heaven.devsecops.sca_scanner` (dependency risk, partial) |

### IDENTIFY (ID)
HEAVEN's strongest CSF alignment — discovering assets and identifying the
vulnerabilities that feed risk assessment.

| Control | Description | HEAVEN coverage |
|---|---|---|
| ID.AM | Asset management (external inventory) | `heaven.recon.network_scanner` |
| ID.RA-01 | Vulnerabilities in assets are identified | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner` |
| ID.RA-05 | Threats, vulnerabilities and impacts used to determine risk | `heaven.orchestrator` (full vulnscan suite + scoring) |
| ID.IM | Improvement | (organizational — programme improvement) |

### PROTECT (PR)
| Control | Description | HEAVEN coverage |
|---|---|---|
| PR.AA | Identity management and authentication | `heaven.vulnscan.auth_scanner` |
| PR.DS | Data security (protected in transit) | `heaven.vulnscan.ssl_scanner` |
| PR.PS | Platform security (secure config & patch) | `heaven.recon.web_crawler`, `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.cve_mapper` |
| PR.IR | Technology infrastructure resilience | `heaven.recon.network_exposure`, `heaven.recon.network_scanner` |
| PR.AT | Awareness and training | (organizational — training) |

### DETECT (DE)
| Control | Description | HEAVEN coverage |
|---|---|---|
| DE.CM | Continuous monitoring | `heaven.recon.adaptive_intel` (defense fingerprint), `heaven.utils.watcher` (recurring re-scan, partial) |
| DE.AE | Adverse event analysis | (organizational — SOC / SIEM) |

### RESPOND (RS)
| Control | Description | HEAVEN coverage |
|---|---|---|
| RS.MA | Incident management | (organizational — IR process) |
| RS.CO | Incident response reporting and communication | `heaven.devsecops.alerting` (webhook/SIEM feed, partial) |

### RECOVER (RC)
| Control | Description | HEAVEN coverage |
|---|---|---|
| RC.RP | Incident recovery plan execution | (organizational — recovery process) |
| RC.CO | Incident recovery communication | (organizational — recovery process) |
