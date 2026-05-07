#!/usr/bin/env bash
# ==============================================================================
#  HEAVEN — Autonomous Penetration Testing Framework
#  Installer v2.1
# ==============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║    ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗    ║${NC}"
echo -e "${CYAN}${BOLD}║    ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║    ║${NC}"
echo -e "${CYAN}${BOLD}║    ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║    ║${NC}"
echo -e "${CYAN}${BOLD}║    ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║    ║${NC}"
echo -e "${CYAN}${BOLD}║    ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║    ║${NC}"
echo -e "${CYAN}${BOLD}║    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝    ║${NC}"
echo -e "${CYAN}${BOLD}║         Autonomous Penetration Testing Framework          ║${NC}"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

# ── Resolve install directory ──────────────────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Install directory: $INSTALL_DIR"

# ── 1. Python check ───────────────────────────────────────────────────────────
info "Checking Python version..."

if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    fail "Python 3 is not installed. Install Python 3.11 or higher."
fi

PY_OK=$($PYTHON_CMD -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
PY_VER=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')

if [ "$PY_OK" != "1" ]; then
    fail "Python 3.11+ required. Found: $PY_VER"
fi
ok "Python $PY_VER"

# ── 2. Virtual environment ────────────────────────────────────────────────────
info "Setting up virtual environment..."
if [ ! -d "$INSTALL_DIR/venv" ]; then
    $PYTHON_CMD -m venv "$INSTALL_DIR/venv"
    ok "venv created at $INSTALL_DIR/venv"
else
    ok "venv already exists — reusing"
fi

VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
VENV_PIP="$INSTALL_DIR/venv/bin/pip"

# ── 3. Pip toolchain ──────────────────────────────────────────────────────────
info "Upgrading pip toolchain..."
"$VENV_PIP" install --upgrade pip setuptools wheel -q
ok "Toolchain ready"

# ── 4. Install HEAVEN ─────────────────────────────────────────────────────────
info "Installing HEAVEN and dependencies..."

if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$VENV_PIP" install -r "$INSTALL_DIR/requirements.txt" -q || warn "Some optional deps failed — continuing"
fi
"$VENV_PIP" install -e "$INSTALL_DIR" -q
ok "HEAVEN installed"

# ── 5. Install global wrapper (works without venv activation) ──────────────────
echo ""
info "Installing global 'heaven' command..."

WRAPPER_CONTENT="#!/usr/bin/env bash
# HEAVEN global wrapper — no venv activation needed
exec \"$INSTALL_DIR/venv/bin/python\" -m heaven.main \"\$@\"
"

WRAPPER_INSTALLED=0

# Try ~/.local/bin first (no sudo, XDG standard)
if [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    echo "$WRAPPER_CONTENT" > "$HOME/.local/bin/heaven"
    chmod +x "$HOME/.local/bin/heaven"
    ok "Global command installed: ~/.local/bin/heaven"
    WRAPPER_INSTALLED=1
fi

# Also try the venv's own heaven binary directly — symlink it to ~/.local/bin
if [ -f "$INSTALL_DIR/venv/bin/heaven" ]; then
    # Patch the shebang inside the venv script to use absolute path
    # (already absolute since venv was created with absolute path)
    ln -sf "$INSTALL_DIR/venv/bin/heaven" "$HOME/.local/bin/heaven" 2>/dev/null || true
    ok "Linked $INSTALL_DIR/venv/bin/heaven → ~/.local/bin/heaven"
fi

# Detect shell and add ~/.local/bin to PATH if missing
SHELL_RC=""
case "$SHELL" in
    */zsh)  SHELL_RC="$HOME/.zshrc" ;;
    */bash) SHELL_RC="$HOME/.bashrc" ;;
    */fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
    *)      SHELL_RC="$HOME/.profile" ;;
esac

PATH_EXPORT='export PATH="$HOME/.local/bin:$PATH"'
if [ -n "$SHELL_RC" ] && ! grep -q "\.local/bin" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# HEAVEN — added by install.sh" >> "$SHELL_RC"
    echo "$PATH_EXPORT" >> "$SHELL_RC"
    ok "Added ~/.local/bin to PATH in $SHELL_RC"
    warn "Run: source $SHELL_RC  (or open a new terminal) to use 'heaven' immediately"
fi

# Also try /usr/local/bin with sudo if ~/.local/bin didn't work
if [ "$WRAPPER_INSTALLED" = "0" ]; then
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$INSTALL_DIR/venv/bin/heaven" /usr/local/bin/heaven
        ok "Global command installed: /usr/local/bin/heaven"
    else
        sudo ln -sf "$INSTALL_DIR/venv/bin/heaven" /usr/local/bin/heaven 2>/dev/null \
            && ok "Global command installed: /usr/local/bin/heaven (sudo)" \
            || warn "Could not install global command — add to PATH manually"
    fi
fi

# ── 6. External tools check (optional) ───────────────────────────────────────
echo ""
echo -e "${BOLD}External tool availability:${NC}"

check_tool() {
    local name="$1"; local cmd="$2"; local install_hint="$3"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$name found: $(command -v "$cmd")"
    else
        warn "$name not found — $install_hint"
    fi
}

check_tool "nmap"    "nmap"    "apt install nmap  /  brew install nmap"
check_tool "nuclei"  "nuclei"  "https://github.com/projectdiscovery/nuclei/releases"
check_tool "sqlmap"  "sqlmap"  "pip install sqlmap  /  apt install sqlmap"

# ── 7. Frontend (optional) ────────────────────────────────────────────────────
echo ""
if [ -d "$INSTALL_DIR/heaven-ui" ]; then
    info "Building frontend UI..."
    if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found — skipping frontend build"
        echo -e "  ${DIM}Install Node.js 18+ then run: cd heaven-ui && npm install --legacy-peer-deps && npm run build${NC}"
    else
        NODE_VER=$(node --version 2>/dev/null || echo "?")
        info "Node $NODE_VER detected"
        ( cd "$INSTALL_DIR/heaven-ui" && npm install --legacy-peer-deps -q && npm run build ) \
            && ok "Frontend built → heaven-ui/dist/" \
            || warn "Frontend build failed — UI unavailable but CLI works fine"
    fi
fi

# ── 8. PostgreSQL (FULLY OPTIONAL) ───────────────────────────────────────────
echo ""
echo -e "${BOLD}PostgreSQL setup (optional — HEAVEN uses SQLite by default):${NC}"
echo -e "${DIM}  HEAVEN's core workflow stores engagement data in local SQLite files.${NC}"
echo -e "${DIM}  PostgreSQL is only needed for multi-operator centralized mode.${NC}"
echo ""

if [ -z "${HEAVEN_DB_PASSWORD:-}" ]; then
    HEAVEN_DB_PASSWORD=$($PYTHON_CMD -c 'import secrets; print(secrets.token_urlsafe(24))')
    warn "HEAVEN_DB_PASSWORD not set — generated a temporary one"
    echo -e "  To enable PostgreSQL mode, add to your shell profile:"
    echo -e "  ${CYAN}export HEAVEN_DB_PASSWORD='$HEAVEN_DB_PASSWORD'${NC}"
    export HEAVEN_DB_PASSWORD
fi

POSTGRES_STARTED=0
if command -v docker-compose >/dev/null 2>&1; then
    info "Attempting PostgreSQL via docker-compose..."
    POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker-compose up -d postgres 2>/dev/null \
        && { sleep 4; POSTGRES_STARTED=1; ok "PostgreSQL started via docker-compose"; } \
        || warn "docker-compose up failed — skipping PostgreSQL (core features unaffected)"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    info "Attempting PostgreSQL via docker compose..."
    POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker compose up -d postgres 2>/dev/null \
        && { sleep 4; POSTGRES_STARTED=1; ok "PostgreSQL started"; } \
        || warn "docker compose up failed — skipping PostgreSQL"
elif command -v psql >/dev/null 2>&1; then
    info "Native PostgreSQL detected — configuring..."
    command -v systemctl >/dev/null 2>&1 && sudo systemctl start postgresql 2>/dev/null || true
    sudo -u postgres psql -c "CREATE USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null \
        || sudo -u postgres psql -c "ALTER USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE heaven OWNER heaven;" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE heaven TO heaven;" 2>/dev/null || true
    POSTGRES_STARTED=1
    ok "Native PostgreSQL configured"
else
    warn "PostgreSQL / Docker not found — skipping (HEAVEN works fine without it)"
fi

if [ "$POSTGRES_STARTED" = "1" ]; then
    info "Initialising database schema..."
    "$INSTALL_DIR/venv/bin/heaven" init-db \
        && ok "Schema initialised" \
        || warn "Schema init failed — run 'heaven init-db' after setting HEAVEN_DB_PASSWORD"
fi

# ── 9. Quick smoke test ───────────────────────────────────────────────────────
echo ""
info "Running smoke test..."
if "$INSTALL_DIR/venv/bin/heaven" --version >/dev/null 2>&1; then
    ok "HEAVEN CLI is working"
else
    warn "CLI smoke test failed — check installation logs above"
fi

# ── 10. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    INSTALLATION COMPLETE                  ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}The 'heaven' command is now available globally.${NC}"
echo -e "${DIM}  No need to activate a virtualenv — just type 'heaven' in any terminal.${NC}"
echo ""
echo -e "${BOLD}Required environment variable:${NC}"
echo -e "  ${CYAN}export HEAVEN_ADMIN_PASSWORD='<strong-password>'${NC}   # API / UI login"
echo -e "  ${DIM}Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.)${NC}"
echo ""
echo -e "${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}heaven --version${NC}                   # confirm it works"
echo -e "  ${CYAN}heaven self-audit${NC}                  # security baseline"
echo -e "  ${CYAN}heaven engage init my-eng${NC}          # create an engagement"
echo -e "  ${CYAN}heaven scan -u https://target --i-have-authorization${NC}"
echo -e "  ${CYAN}heaven serve${NC}                       # web UI → http://localhost:8443"
echo ""
echo -e "${DIM}Tip: open a new terminal (or run: source $SHELL_RC) for PATH to take effect${NC}"
echo ""
