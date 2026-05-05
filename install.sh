#!/usr/bin/env bash
# ==============================================================================
#  HEAVEN — Autonomous Penetration Testing Framework
#  Installer v2.0
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
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║   ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗   ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║   ║${NC}"
echo -e "${CYAN}${BOLD}║   ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║   ║${NC}"
echo -e "${CYAN}${BOLD}║   ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║   ║${NC}"
echo -e "${CYAN}${BOLD}║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ║${NC}"
echo -e "${CYAN}${BOLD}║            Autonomous Penetration Testing Framework       ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

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
if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
    ok "venv created"
else
    ok "venv already exists — reusing"
fi

# shellcheck source=/dev/null
source venv/bin/activate

# ── 3. Pip toolchain ──────────────────────────────────────────────────────────
info "Upgrading pip toolchain..."
pip install --upgrade pip setuptools wheel -q
ok "Toolchain ready"

# ── 4. Install HEAVEN ─────────────────────────────────────────────────────────
info "Installing HEAVEN and dependencies..."

# Use requirements.txt if present, else fall back to pyproject extras
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt -q || warn "Some optional deps failed — continuing"
fi
pip install -e . -q
ok "HEAVEN installed"

# ── 5. External tools check (optional) ───────────────────────────────────────
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

check_tool "nmap"    "nmap"    "install with: brew install nmap  /  apt install nmap"
check_tool "nuclei"  "nuclei"  "install from: https://github.com/projectdiscovery/nuclei"
check_tool "sqlmap"  "sqlmap"  "install with: pip install sqlmap  /  apt install sqlmap"

# ── 6. Frontend (optional) ────────────────────────────────────────────────────
echo ""
if [ -d "heaven-ui" ]; then
    info "Building frontend UI..."
    if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found — skipping frontend build"
        echo -e "  ${DIM}Install Node.js 18+ and run: cd heaven-ui && npm install && npm run build${NC}"
    else
        NODE_VER=$(node --version 2>/dev/null || echo "?")
        info "Node $NODE_VER detected"
        ( cd heaven-ui && npm install --legacy-peer-deps -q && npm run build ) \
            && ok "Frontend built → heaven-ui/dist/" \
            || warn "Frontend build failed — UI won't be served (core CLI still works)"
    fi
fi

# ── 7. PostgreSQL (FULLY OPTIONAL) ───────────────────────────────────────────
echo ""
echo -e "${BOLD}PostgreSQL setup (optional — HEAVEN uses SQLite by default):${NC}"
echo -e "${DIM}  HEAVEN's core workflow stores engagement data in local SQLite files.${NC}"
echo -e "${DIM}  PostgreSQL is only needed for multi-operator centralized mode.${NC}"
echo ""

if [ -z "${HEAVEN_DB_PASSWORD:-}" ]; then
    HEAVEN_DB_PASSWORD=$($PYTHON_CMD -c 'import secrets; print(secrets.token_urlsafe(24))')
    warn "HEAVEN_DB_PASSWORD not set — generated: ${CYAN}${HEAVEN_DB_PASSWORD:0:8}...${NC}"
    echo -e "  Save to your shell profile: ${CYAN}export HEAVEN_DB_PASSWORD='$HEAVEN_DB_PASSWORD'${NC}"
    export HEAVEN_DB_PASSWORD
fi

POSTGRES_STARTED=0
if command -v docker-compose >/dev/null 2>&1; then
    info "Starting PostgreSQL via docker-compose..."
    if POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker-compose up -d postgres 2>/dev/null; then
        sleep 4
        POSTGRES_STARTED=1
        ok "PostgreSQL started via docker-compose"
    else
        warn "docker-compose up failed — skipping PostgreSQL"
    fi
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    info "Starting PostgreSQL via docker compose..."
    if POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker compose up -d postgres 2>/dev/null; then
        sleep 4
        POSTGRES_STARTED=1
        ok "PostgreSQL started via docker compose"
    else
        warn "docker compose up failed — skipping PostgreSQL"
    fi
elif command -v psql >/dev/null 2>&1; then
    info "Native PostgreSQL detected — configuring..."
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl start postgresql 2>/dev/null || true
    fi
    sudo -u postgres psql -c "CREATE USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null \
        || sudo -u postgres psql -c "ALTER USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null \
        || true
    sudo -u postgres psql -c "CREATE DATABASE heaven OWNER heaven;" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE heaven TO heaven;" 2>/dev/null || true
    POSTGRES_STARTED=1
    ok "Native PostgreSQL configured"
else
    warn "PostgreSQL / Docker not found — skipping (HEAVEN works fine without it)"
fi

# ── 8. Init schema (only if PostgreSQL started) ───────────────────────────────
if [ "$POSTGRES_STARTED" = "1" ]; then
    info "Initialising database schema..."
    heaven init-db && ok "Schema initialised" \
        || warn "Schema init failed — run 'heaven init-db' after setting HEAVEN_DB_PASSWORD"
fi

# ── 9. Quick smoke test ───────────────────────────────────────────────────────
echo ""
info "Running smoke test..."
if heaven --version >/dev/null 2>&1; then
    ok "HEAVEN CLI is working"
else
    warn "CLI smoke test failed — check installation"
fi

# ── 10. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    INSTALLATION COMPLETE                  ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo -e "  ${CYAN}source venv/bin/activate${NC}          # activate the environment"
echo ""
echo -e "${BOLD}Required environment variables:${NC}"
echo -e "  ${CYAN}export HEAVEN_ADMIN_PASSWORD='<strong-password>'${NC}   # API admin login"
echo -e "  ${DIM}(HEAVEN_DB_PASSWORD only needed for PostgreSQL mode)${NC}"
echo ""
echo -e "${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}heaven --version${NC}                  # version check"
echo -e "  ${CYAN}heaven self-audit${NC}                 # security baseline"
echo -e "  ${CYAN}heaven engage init my-engagement${NC}  # create an engagement"
echo -e "  ${CYAN}heaven scan -u https://target.example --i-have-authorization${NC}"
echo -e "  ${CYAN}heaven serve${NC}                      # start web UI at http://localhost:8443"
echo ""
echo -e "${DIM}Documentation: README.md | Full API: heaven serve → /api/docs${NC}"
echo ""
