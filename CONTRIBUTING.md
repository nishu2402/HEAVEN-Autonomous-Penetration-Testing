# Contributing to HEAVEN

Thanks for considering a contribution. HEAVEN is an offensive-security
tool, so the bar for what gets merged is intentionally high. Bugs in a
pen-test tool become bugs in real engagements.

## Before you start

1. **Read `SECURITY.md`** if you're reporting a security issue. Do NOT
   open a public issue for security bugs.
2. **Read `LICENSE`.** The ethical-use notice is not legally binding
   but it's the maintainer's stance. Contributions that materially
   enable misuse (e.g., bundling stolen credentials, removing the
   `--i-have-authorization` gate) won't be accepted.
3. **Check the issue tracker** before opening a new one; duplicates
   get closed.

## Development setup

```bash
git clone https://github.com/nishu2402/HEAVEN-Autonomous-Penetration-Testing
cd HEAVEN-Autonomous-Penetration-Testing
./scripts/install.sh         # creates venv, installs deps, builds React UI

# OR a minimal Python-only setup for backend work:
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pip install pyyaml semgrep    # optional, for benchmark suite + SAST
```

## CI lanes: all must be green before review

Run these locally before pushing:

```bash
# Lint
ruff check heaven/ tests/

# Type-check
mypy --ignore-missing-imports --no-strict-optional heaven/

# Tests
pytest tests/                 # full suite

# Security audit (informational, exits 0 even on findings)
bandit -r heaven/ -ll

# HEAVEN's self-audit (should grade A)
heaven self-audit
```

GitHub Actions runs the same lanes plus pip-audit on every push.

**Optional:** enable the repo's pre-commit hook so the README's decorative test
counts stay in sync automatically (CI never blocks on a stale count, but this
keeps it tidy):

```bash
git config core.hooksPath .githooks
```

Run it manually any time with `python scripts/sync_test_count.py`.

## What we look for in a PR

| Area | Standard |
|---|---|
| **Tests** | Every new feature ships with at least one test. Bug fixes ship with a regression test. We use pytest + hypothesis. |
| **Type hints** | Public functions are fully annotated. `Optional`/`Any` are fine when truly needed. |
| **Docstrings** | Module-level docstring explaining *why* the file exists. Public functions: one-line summary + args/returns if non-obvious. |
| **Authorization gates** | Every new destructive action requires `authorized=True` at the function level AND respects `--i-have-authorization` at the CLI level. |
| **Honest naming** | If a module does behavioural heuristics, don't name it `zero_day_discovery_engine`. Reviewers will dunk on it. |
| **No silent secrets** | Credentials never go to logs unredacted. The LLM gateway has a redaction layer, so use it. |
| **No vendor lock-in** | New AI features should go through `heaven.ai.LLMGateway` so swapping providers doesn't require code changes. |

## Code style

- **Python**: `ruff` enforces. `from __future__ import annotations` at the
  top of every file. Dataclasses for value types; classes for behaviour.
- **JavaScript/JSX**: match the existing dark-matrix style in
  `heaven-ui/src/`. No new component libraries; pure React + CSS.
- **Commit messages**: imperative mood, ≤72 char subject, body explains
  the *why* not the *what*. `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
  prefixes match the existing history.

## Writing style (docs and user-facing copy)

All prose in the project, in the documentation and in the copy the tool shows
its users, should read as if a person wrote it. Follow these rules by default.
Don't add a changelog entry about wording.

**What to do:**

- Don't use em dashes or en dashes. Recast the sentence instead: a period for a
  new clause, a comma for a short aside, a colon before an explanation, or
  parentheses for a true aside. Between numbers, write "3 to 5" or use a hyphen.
- Use straight quotes (`"` and `'`), never curly ones.
- Drop the AI-tell vocabulary and promotional filler: "vibrant", "seamless",
  "robust", "leverage", "delve", "testament to", "underscores", "boasts",
  "in the realm of", and similar. State the fact plainly.
- Avoid forced groups of three, stacked present-participle clauses
  ("...ing, ...ing"), copula avoidance ("serves as", "stands as"), and negative
  parallelisms ("not only... but also"). Vary sentence length.
- Keep every fact, number, name, date, and citation exactly as it is. Never
  invent detail to sound more specific. If a claim has no source, cut it rather
  than dress it up.

**What to leave alone:**

- Code, identifiers, config keys, CLI flags, link targets, and data.
- Markdown table structure, badges, banners, ASCII diagrams, and the middot
  (`·`) and arrow (`->`, shown as →) separators used as house style.
- The brand emojis in README section headings.
- Lines the tooling generates or parses: the count numbers in `README.md` and
  the poster SVGs (owned by `scripts/sync_test_count.py`), and the headings,
  control IDs, test IDs, and coverage-cell values in `docs/methodology/*.md`
  (parsed by `heaven/methodology.py`).
- Strings that tests assert on. When in doubt, run the suite.

## Adding a new scanner / detection module

1. Place it under `heaven/recon/` (passive) or `heaven/vulnscan/` (active).
2. Wire it into `heaven/orchestrator.py::build_full_scan()` with a clear
   phase (`RECON` / `VULN_SCAN` / `EXPLOIT_PROOF` / `POST_EX`).
3. Add its name to the Feature Status table in `README.md`.
4. Add a CLI command if the operator needs to invoke it independently.
5. Map it to OWASP / NIST / PTES in `docs/methodology/`.
6. If it changes detection behaviour, run the benchmark suite and report
   the before/after numbers in the PR description.

## Adding a new AI capability

1. Goes under `heaven/ai/` (NOT `heaven/ml/`, which is reserved for
   supervised models like the NVD CVSS predictor).
2. Uses `LLMGateway`; do not call provider SDKs directly.
3. Gracefully degrades when no LLM API key is set (return a fallback,
   don't raise).
4. Logs every LLM call via the gateway's audit hook.

## Pull-request checklist

Copy this into your PR description:

```
- [ ] All CI lanes green (ruff, mypy, pytest, bandit, self-audit)
- [ ] New code has tests
- [ ] Docstrings + type hints on public surface
- [ ] README updated if user-facing
- [ ] CHANGELOG updated under `[Unreleased]`
- [ ] No new dependencies without justification in the PR description
- [ ] If introducing a destructive action: authorization gate verified
```

## Questions

Open a Discussion (not an Issue) for design questions, or DM the
maintainer on LinkedIn (see README authors section).
