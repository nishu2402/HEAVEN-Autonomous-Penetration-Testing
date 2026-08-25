# HEAVEN ↔ NIST Cybersecurity Framework (CSF) 2.0

Mapping of HEAVEN's detectors against the [NIST CSF
2.0](https://www.nist.gov/cyberframework), six Functions (**Govern**,
**Identify**, **Protect**, **Detect**, **Respond**, **Recover**), each broken
into Categories.

The CSF is an outcome-based framework spanning governance to recovery. HEAVEN
provides direct technical evidence for every outcome that is measurable by
scanning, supply-chain risk, asset management, vulnerability/risk identification,
posture-improvement tracking, identity & authentication, transport crypto,
platform hardening, infrastructure resilience, continuous monitoring, and event
delivery, each named to a real detector or tool feature. The Govern/Respond/
Recover outcomes that are pure governance or process are listed as **out-of-band
(analyst-attested)**.

A control row is **✓ exercised** on the live Methodology page only when the
HEAVEN detector it names actually produced a finding in the active engagement.

## Coverage summary

| Function | HEAVEN evidence |
|---|---|
| GOVERN (GV) | supply-chain risk (dependencies); governance outcomes analyst-attested |
| IDENTIFY (ID) | extensive, asset discovery, vulnerability/risk ID, improvement tracking |
| PROTECT (PR) | extensive, auth, transport crypto, platform hardening, resilience |
| DETECT (DE) | continuous monitoring & defense fingerprinting |
| RESPOND (RS) | event reporting & delivery; incident-management analyst-attested |
| RECOVER (RC) | recovery process, analyst-attested |

## Detailed mapping

### GOVERN (GV)
| Control | Description | HEAVEN coverage |
|---|---|---|
| GV.SC | Cybersecurity supply chain risk management | `heaven.vulnscan.sca_scanner` (dependency / third-party component risk) |

**Out-of-band (analyst-attested):** GV.OC (organizational context) and GV.RM
(risk-management strategy), along with roles, policy and oversight, are governance
outcomes attested through the security programme.

### IDENTIFY (ID)
HEAVEN's strongest CSF alignment, discovering assets and identifying the
vulnerabilities that feed risk assessment.

| Control | Description | HEAVEN coverage |
|---|---|---|
| ID.AM | Asset management (external inventory) | `heaven.recon.network_scanner`, `heaven.devsecops.inventory` |
| ID.RA-01 | Vulnerabilities in assets are identified | `heaven.vulnscan.cve_mapper`, `heaven.vulnscan.eol_scanner` |
| ID.RA-05 | Threats, vulnerabilities and impacts used to determine risk | `heaven.orchestrator` (full vulnscan suite + scoring) |
| ID.IM | Improvement | `heaven.devsecops.retest_report`, `heaven diff` (measures remediation progress / posture change across scans) |

### PROTECT (PR)
| Control | Description | HEAVEN coverage |
|---|---|---|
| PR.AA | Identity management and authentication | `heaven.vulnscan.auth_scanner` |
| PR.DS | Data security (protected in transit) | `heaven.vulnscan.ssl_scanner` |
| PR.PS | Platform security (secure config & patch) | `heaven.recon.web_crawler`, `heaven.vulnscan.dir_fuzzer`, `heaven.vulnscan.cve_mapper` |
| PR.IR | Technology infrastructure resilience | `heaven.recon.network_exposure`, `heaven.recon.network_scanner` |

**Out-of-band (analyst-attested):** PR.AT (awareness and training) is an HR/
training outcome.

### DETECT (DE)
| Control | Description | HEAVEN coverage |
|---|---|---|
| DE.CM | Continuous monitoring | `heaven.recon.adaptive_intel` (defense fingerprint), `heaven.recon.firewall_detector` (perimeter classification), `heaven.utils.watcher` (recurring re-scan) |

**Out-of-band (analyst-attested):** DE.AE (adverse event analysis) is a SOC/SIEM
process outcome.

### RESPOND (RS)
| Control | Description | HEAVEN coverage |
|---|---|---|
| RS.CO | Incident response reporting and communication | `heaven.devsecops.alerting` (structured webhook / SIEM event delivery) |

**Out-of-band (analyst-attested):** RS.MA (incident management) is an IR-process
outcome.

### RECOVER (RC)
**Out-of-band (analyst-attested):** RC.RP (incident recovery plan execution) and
RC.CO (recovery communication) are recovery-process outcomes with no scan
footprint.
