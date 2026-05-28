## Summary

<!-- One sentence: what does this PR do and why? -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (CLI flag rename, API contract change, schema migration)
- [ ] Docs / refactor only

## CI checklist

- [ ] `ruff check heaven/ tests/` — all green
- [ ] `mypy --ignore-missing-imports --no-strict-optional heaven/` — all green
- [ ] `pytest tests/` — all green
- [ ] `bandit -r heaven/ -ll` — no new high-severity findings
- [ ] `heaven self-audit` — still grade A

## Test plan

<!-- How did you verify this works? Include real command output if it
     touches CLI behaviour. -->

```bash
$ heaven <command> ...
# expected output:
```

## Documentation

- [ ] README updated (if user-facing)
- [ ] CHANGELOG updated under `[Unreleased]`
- [ ] New CLI commands have `--help` output
- [ ] New API endpoints documented in the README API table

## Authorization gate

<!-- Required for any new active / destructive action -->

- [ ] N/A — this PR is read-only / passive
- [ ] New action requires `--i-have-authorization` at the CLI
- [ ] New API endpoint requires `vuln.validate` or `config.modify` permission

## Related issues

Fixes #
