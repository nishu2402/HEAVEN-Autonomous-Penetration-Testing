#!/usr/bin/env bash
# Regenerate every image in docs/screenshots/ from the LIVE app — the two terminal
# captures (startup banner + CLI dashboard) and the five web-UI pages — so they
# always reflect the current version string and UI. One command:
#
#     ./scripts/screenshots/regenerate.sh
#
# It runs entirely against an ISOLATED, throwaway data dir and a random admin
# password (never your real ./data or ./.env). Requirements: the project venv,
# Node.js, and a local Chrome/Chromium (override with CHROME=<path>).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PORT="${PORT:-8443}"
VENV_PY="${VENV_PY:-$REPO/venv/bin/python}"
HEAVEN_BIN="${HEAVEN_BIN:-$REPO/venv/bin/heaven}"
OUT="$REPO/docs/screenshots"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/heaven-shots.XXXXXX")"
export HEAVEN_DATA_DIR="$WORK/hdata"
export HEAVEN_ADMIN_PASSWORD="shots-$(date +%s)-$RANDOM"   # throwaway, isolated
mkdir -p "$HEAVEN_DATA_DIR"

SERVE_PID=""
cleanup() {
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Building the web UI (dist must match current source)"
npm --prefix "$REPO/heaven-ui" run build >/dev/null

echo "==> Installing capture deps (puppeteer-core)"
npm --prefix "$HERE" install --silent --no-audit --no-fund

echo "==> Seeding demo data into $HEAVEN_DATA_DIR"
( cd "$WORK" && "$HEAVEN_BIN" demo >/dev/null )

echo "==> Starting isolated backend on 127.0.0.1:$PORT"
# exec so SERVE_PID is the real uvicorn process (not a subshell wrapper that
# would orphan it on kill).
( cd "$WORK" && exec "$HEAVEN_BIN" serve --host 127.0.0.1 --port "$PORT" --no-open >"$WORK/serve.log" 2>&1 ) &
SERVE_PID=$!
for i in $(seq 1 30); do
  curl -s "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
  sleep 1
done
( cd "$WORK" && "$HEAVEN_BIN" use demo >/dev/null )

echo "==> Capturing terminal banner + dashboard"
OUT="$WORK" "$VENV_PY" "$HERE/capture_terminal.py"
node "$HERE/svg2png.mjs" "$WORK/banner.svg"    "$OUT/Heaven_Autonomous_Penetration_Testing_Platform.png"
node "$HERE/svg2png.mjs" "$WORK/dashboard.svg" "$OUT/Heaven_cli.png"

echo "==> Capturing web UI pages"
BASE="http://127.0.0.1:$PORT" PASS="$HEAVEN_ADMIN_PASSWORD" OUT="$OUT" \
  node "$HERE/capture_web.mjs"

echo "==> Done. Regenerated:"
ls -1 "$OUT"/*.png
