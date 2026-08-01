# Regenerating the README screenshots

Everything in [`docs/screenshots/`](../../docs/screenshots) is generated from the
**live application**, so the images stay truthful across releases (the version
string, module list, and UI are whatever the code currently produces — nothing is
mocked up in an image editor).

There are two kinds of image and one command that produces all of them.

| Image | Source |
|-------|--------|
| `Heaven_Autonomous_Penetration_Testing_Platform.png` | real startup banner (`heaven.utils.logger.print_banner`) |
| `Heaven_cli.png` | real CLI dashboard (`heaven.cli._dashboard.show_dashboard`) |
| `web-app_dashboard.png`, `findings_dashboard.png`, `kill_chain_dashboard.png`, `scanning_dashboard.png`, `reports_dashboard.png` | the live web UI, demo-seeded |

## One command

```bash
./scripts/screenshots/regenerate.sh
```

This runs entirely against an **isolated, throwaway data dir and a random admin
password** — it never touches your real `./data` or `./.env`. It builds the web
UI, seeds demo data, starts a local backend, captures all seven images straight
into `docs/screenshots/`, and tears the backend down on exit.

## Requirements

- The project virtualenv at `./venv` (or set `VENV_PY` / `HEAVEN_BIN`).
- Node.js. The first run does `npm install` here to fetch `puppeteer-core`
  (dev-only; kept out of the app and the web-UI build).
- A local Chrome or Chromium. Auto-detected on macOS/Linux; override with
  `CHROME=/path/to/chrome`.

## How it works (and the gotchas it encodes)

- **Terminal captures** render the real Rich output to an SVG
  (`capture_terminal.py`), then rasterise it with headless Chrome
  (`svg2png.mjs`). A `Menlo` monospace fallback is injected so the box-drawing
  characters stay aligned even if the Fira Code webfont can't be fetched.
- **Web captures** (`capture_web.mjs`) log in by setting each field through the
  **native value setter** (the inputs are React-controlled, so `page.type` drops
  characters) and navigate **client-side** by clicking sidebar links (the JWT is
  in memory, so a full `page.goto` would log the session out). The 3D dashboard
  gets extra settle time and WebGL flags (`swiftshader`) for headless rendering.

To run a single stage manually, see the env vars at the top of each script.
