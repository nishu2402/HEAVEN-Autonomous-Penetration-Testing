# SCA benchmark corpus (intentionally vulnerable — do NOT install)

This directory holds HEAVEN's Software Composition Analysis (SCA) benchmark
fixtures: two small, multi-ecosystem sets of **known-vulnerable** dependency
pins (`vulnerable/`) and the versions that fixed them (`patched/`). They are
inert manifest text — nothing here is ever installed or executed. The scorer
(`tests/benchmarks/sca_benchmark.py`) reads them and audits the pins live
against OSV.dev to prove the scanner's recall and its precision control.

## Why the `.fixture` suffix

The manifests are named `requirements.txt.fixture` and `package.json.fixture`,
**not** `requirements.txt` / `package.json`, on purpose:

- GitHub's dependency graph parses any file literally named `requirements.txt`
  or `package.json` anywhere in the repo and treats its pins as real project
  dependencies. That made Dependabot raise 100+ security alerts and open bump
  PRs against these deliberately-vulnerable fixtures — noise, since the project
  never depends on them. The real dependencies live in `/pyproject.toml`,
  `/requirements.txt`, and `/heaven-ui/package.json`.
- The `.fixture` suffix makes GitHub ignore these files while the benchmark
  still reads them and parses each under its logical manifest name, so the audit
  is byte-for-byte identical to scanning the real file.

**Do not rename these back to `requirements.txt` / `package.json`** — that would
re-introduce the false Dependabot alerts. If you add a fixture for another
ecosystem, give it the same `<manifest-name>.fixture` form (e.g.
`go.mod.fixture`); the scorer auto-discovers every `*.fixture` file here.
