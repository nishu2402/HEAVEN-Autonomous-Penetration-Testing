# Getting help with HEAVEN

HEAVEN is maintained by one person, so routing your request to the right place
gets you an answer faster and keeps the issue tracker focused on real bugs.

## Start here

Most setup and usage questions are already answered:

- [docs/QUICKSTART.md](docs/QUICKSTART.md) -- a 5-minute walkthrough from install to first scan.
- [docs/FAQ.md](docs/FAQ.md) -- common errors, missing optional tools (nmap / nuclei / sqlmap / semgrep), API-key setup, and troubleshooting.
- `heaven doctor` -- checks your install and reports what is missing or misconfigured.
- `heaven --help` and `heaven <command> --help` -- the full CLI surface.

## Where to take each kind of request

| I want to... | Go to |
|---|---|
| Ask a question, get setup help, or troubleshoot | [GitHub Discussions](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/discussions) |
| Report a reproducible bug | [Open a bug report](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/issues/new?template=bug_report.md) |
| Suggest a feature | [Open a feature request](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/issues/new?template=feature_request.md) |
| Report a security vulnerability | **Not a public issue.** Follow [SECURITY.md](SECURITY.md) |
| Ask something private | DM the maintainer on [LinkedIn](https://www.linkedin.com/in/nisarg-chasmawala) |

## Before you open an issue

- Search [existing issues](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/issues) and [Discussions](https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing/discussions) first; duplicates get closed.
- Include your `heaven --version`, Python version, OS, and install method.
- Give the smallest command that reproduces the problem, with secrets redacted.

The bug report template walks you through exactly what to include.

## What counts as a security issue

Anything that could let someone bypass an authorization gate, leak operator
credentials or captured secrets, tamper with the audit log, or compromise the
API or the engagement database. When in doubt, treat it as security and report
it privately through [SECURITY.md](SECURITY.md) rather than a public issue.

## What to expect

HEAVEN is a solo, best-effort project. Security reports come first and follow
the timeline in [SECURITY.md](SECURITY.md) (acknowledgment within 5 business
days). Bugs are next; questions and feature requests are handled as time allows.
