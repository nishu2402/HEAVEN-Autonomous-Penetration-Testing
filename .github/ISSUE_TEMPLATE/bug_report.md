---
name: 🐛 Bug report
about: Something HEAVEN does that it shouldn't
title: "[BUG] "
labels: bug
assignees: ''
---

<!--
SECURITY VULNERABILITIES: do NOT file here. See SECURITY.md.
-->

## What happened

A clear, one-paragraph description of the bug.

## Reproduction

The smallest possible command + environment that triggers it:

```bash
heaven scan -u https://example.com --i-have-authorization
# → ...
```

## Expected behavior

What you thought would happen.

## Actual behavior

What did happen. Include the full error message + stack trace if any.

## Environment

- HEAVEN version: `heaven --version` → ...
- Python version: `python --version` → ...
- OS: macOS 14 / Ubuntu 22.04 / Windows 11
- Install method: `./install.sh` / Docker / `pip install -e .`
- Optional dependencies installed: nmap, nuclei, sqlmap, semgrep (delete those not present)

## Engagement context

- Target type: web app / network / AD / cloud
- Authorization confirmed for the target? `[ ] yes`

## Logs

```
Paste relevant log lines from data/audit/ or stdout.
Redact secrets before pasting.
```

## Anything else?

Screenshots, scan IDs, related issues, etc.
