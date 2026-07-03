# HEAVEN — FAQ & Troubleshooting

Short answers to the questions that come up most. If something here doesn't fix
it, run `heaven doctor` (or open **System Health** in the web UI) — it shows
exactly what's configured vs. missing — and then open an issue.

---

## Getting started

### What's the fastest way to see HEAVEN working?

```bash
heaven demo      # loads a realistic sample engagement — nothing is scanned
heaven serve     # open http://localhost:8443, the dashboard is now full
```

Or, in the web UI, click **Load sample data** on the dashboard.

### How do I log in to the web UI?

On a fresh install the account is `admin` / `admin` and you're forced to set a
new password on first login. To skip that, set a password up front:

```bash
heaven init                                   # wizard (recommended)
# or
heaven config set HEAVEN_ADMIN_PASSWORD       # prompts securely
```

A password you change in the web UI is saved to `.env`, so it survives restarts.

### Where are my API keys / settings stored?

In `.env` in the working directory. Set them three ways — they all write the
same file: the web UI **Settings** page, `heaven config set <KEY>`, or
`heaven init`. `.env` is auto-loaded on every command and is git-ignored.

---

## Scanning

### A scan finds nothing / errors immediately.

- **Authorization:** active scans require `--i-have-authorization`. Without it
  HEAVEN refuses to run (by design).
- **Tooling:** install hints for missing tools are shown by `heaven doctor` /
  **System Health**. `nmap` is the main hard dependency; `nuclei` / `sqlmap` /
  `ffuf` / `searchsploit` are optional and the matching capability is skipped
  (with a message) when absent.
- **Scope:** the target must be in scope. `heaven scope add <target>`.

### Authenticated web scans don't reach pages behind login.

Pass a session so the crawler/scanners authenticate:

```bash
heaven scan -u https://app.example.com \
  --auth "url=/login,user=USER,pass=PASS" --i-have-authorization
# or a saved cookie jar:
heaven scan -u https://app.example.com --cookie-file cookies.txt --i-have-authorization
```

### Output is noisy / I want to script HEAVEN.

Use `--quiet` to silence informational logs and a command's `--format json` for
machine-readable output:

```bash
heaven --quiet findings --format json | jq '.[] | select(.severity=="critical")'
```

---

## AI / LLM features

### Do I need an API key?

No. Every AI feature (autonomous loop, AI attack plans, LLM false-positive
review) falls back to a deterministic heuristic, or pass `--no-llm`. Add a key
only to enable the LLM path — Gemini has a free tier
(<https://aistudio.google.com/apikey>).

### I set a key but the LLM still isn't used.

Check it's detected: web UI **Settings → Test LLM connection**, or
`heaven doctor`. Common causes: the provider SDK isn't installed
(`pip install -e ".[gemini]"` / `".[anthropic]"` / `".[openai]"`), or a stale
shell `export` shadowing `.env` (HEAVEN loads `.env` with override, so prefer
editing `.env`).

---

## Install

### `./scripts/install.sh` reported some optional packs were skipped.

That's fine — the core install is complete and those features degrade
gracefully. Install a pack later with `pip install -e ".[recon]"` (or
`[reports]` / `[lateral]` / `[mitre]` / `[deploy]` / `[scheduling]`). For the
leanest footprint, run the installer with `HEAVEN_CORE_ONLY=1`.

### PDF reports fail with a missing-dependency error.

PDF rendering needs `reportlab` (pure Python, no system libraries):
`pip install reportlab` or `pip install -e ".[reports]"`. Tip: the **HTML report
needs no extra packages** — open it and use your browser's *Print → Save as PDF*
for the same professional layout. All other formats (HTML, Markdown, CSV, JSON,
SARIF, Burp XML, proxy-JSONL) work without any extra dependency.

### `heaven: command not found` after install.

Either `source` the shell RC line the installer printed, open a new terminal, or
run it via the venv: `./venv/bin/heaven`. With pipx: `pipx ensurepath`.

---

## Web UI

### The dashboard is blank.

There's no data yet. Run a scan, or click **Load sample data** / `heaven demo`.
If you ran a scan via the CLI and the UI is still empty, confirm both point at
the same engagement store — by default the dashboard reads
`<data_dir>/engagements/default.db` (`data_dir` defaults to `./data`).

### `heaven serve` shows a placeholder page, not the app.

The web UI wasn't built. Re-run `./scripts/install.sh`, or build it manually:
`cd heaven-ui && npm install --legacy-peer-deps && npm run build`.

---

## Security & safety

- HEAVEN is for **authorized** testing only — every destructive action is gated
  behind `--i-have-authorization`, and all activity is written to an
  HMAC-signed audit log.
- Secrets live in `.env` (git-ignored) and the AES-256-GCM vault; the web UI
  only ever shows masked previews of stored keys.
- Run `heaven self-audit` to score your own installation and surface
  misconfigurations (default passwords, debug mode, CORS, etc.).
