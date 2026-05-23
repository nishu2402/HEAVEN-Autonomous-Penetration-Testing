# HEAVEN — Methodology Mapping

HEAVEN's scanners are mapped against the three pen-testing standards a
publication-grade tool is expected to address:

| Standard | Maintainer | Doc |
|---|---|---|
| OWASP Testing Guide v4.2 | OWASP | [owasp_testing_guide.md](owasp_testing_guide.md) |
| Penetration Testing Execution Standard (PTES) | PTES Consortium | [ptes.md](ptes.md) |
| NIST SP 800-115 | NIST | [nist_800_115.md](nist_800_115.md) |

MITRE ATT&CK mapping is in code (`heaven/mitre/attack_mapper.py`) and
exported via `heaven mitre-report`.

## What "mapped" means here

Each doc contains a table of (standard test ID) → (HEAVEN module that
implements it). When the standard test is **not** implemented, the row
says so explicitly. This is so:

- Auditors can see coverage at a glance.
- Operators know which standard sections they still have to cover manually.
- Reviewers can confirm the tool isn't padding claims.

## How to update

When you add a new scanner module, edit the relevant row(s) in each of
the three docs. The mapping is hand-maintained — there's no automation
keeping it in sync because the binding between a scanner and a standard
test ID requires human judgment.
