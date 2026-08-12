# HEAVEN — Methodology & Framework Mapping

HEAVEN's scanners are mapped against the pen-testing methodologies **and** the
compliance/control frameworks a publication-grade tool is expected to address.
Every mapping is *live*: the web **Methodology Coverage** page and
`heaven methodology coverage` overlay your active engagement's real findings
onto these tables, so a control lights up **✓ exercised** only when the HEAVEN
detector it names actually produced a finding.

## Pen-test methodologies (per test ID)

| Standard | Maintainer | Doc |
|---|---|---|
| OWASP Testing Guide v4.2 | OWASP | [owasp_testing_guide.md](owasp_testing_guide.md) |
| Penetration Testing Execution Standard (PTES) | PTES Consortium | [ptes.md](ptes.md) |
| NIST SP 800-115 | NIST | [nist_800_115.md](nist_800_115.md) |

## Compliance / control frameworks (per control)

| Framework | Maintainer | Doc |
|---|---|---|
| Cyber Essentials (v3.3, "Danzell") | UK NCSC | [cyber_essentials.md](cyber_essentials.md) |
| Cyber Essentials Plus (v3.3) | UK NCSC | [cyber_essentials_plus.md](cyber_essentials_plus.md) |
| ISO/IEC 27001:2022 (Annex A, +Amd 1:2024) | ISO/IEC | [iso_27001.md](iso_27001.md) |
| PCI DSS v4.0.1 | PCI SSC | [pci_dss.md](pci_dss.md) |
| CIS Critical Security Controls v8.1 | CIS | [cis_controls_v8.md](cis_controls_v8.md) |
| NIST Cybersecurity Framework 2.0 | NIST | [nist_csf.md](nist_csf.md) |
| SOC 2 (Trust Services Criteria, 2017 / rev. 2022) | AICPA | [soc2.md](soc2.md) |

MITRE ATT&CK mapping is in code (`heaven/mitre/attack_mapper.py`) and exported
via `heaven mitre-report`.

## What "mapped" means here

Each doc contains a table of (standard control / test ID) → (HEAVEN detector
module that provides evidence for it). When HEAVEN can **not** evidence a
control from a network or credentialed scan, the row says so explicitly —
`(manual)` for endpoint/host tests, `(organizational)` for governance and
policy controls, `(physical)` for physical controls. **Coverage is never
fabricated.** This is so:

- Auditors can see coverage — and its honest limits — at a glance.
- Operators know which sections they still have to cover manually.
- Reviewers can confirm the tool isn't padding claims.

## How the live overlay works

The `## Detailed mapping` table in each doc names, in its coverage cell, the
HEAVEN detector module(s) that automate the control (e.g.
`heaven.vulnscan.cve_mapper`). `heaven/methodology.py` maps each finding's
`vuln_type` to the same detector token, so a control row is flagged
**exercised** in the current engagement iff that detector actually fired. The
summary counts are computed from the rows, so they can't drift from the detail.

## How to update

When you add a new scanner module, edit the relevant row(s) so the coverage
cell names the module's basename (the token the live overlay matches on), and —
if the detector emits a new `vuln_type` — add it to `VULN_MODULE` in
`heaven/methodology.py` so the row lights up. Control↔detector binding requires
human judgment, so the tables themselves are hand-maintained; only the summary
counts and the live overlay are automated.
