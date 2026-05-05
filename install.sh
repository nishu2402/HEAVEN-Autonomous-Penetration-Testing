#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# HEAVEN v1.0 — Installer
# ==============================================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}   HEAVEN v1.0 — Installation Setup                  ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo ""

# ─── 1. Python version check (no `bc` dependency) ──────────────────
echo -e "[*] Checking Python version..."
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo -e "${RED}[!] Python 3 is not installed. Install Python 3.11 or higher.${NC}"
    exit 1
fi

PY_OK=$($PYTHON_CMD -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
PY_VER=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
if [ "$PY_OK" != "1" ]; then
    echo -e "${RED}[!] Python 3.11+ required. Found: $PY_VER${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Found Python $PY_VER${NC}"

# ─── 2. Virtual environment ────────────────────────────────────────
echo -e "\n[*] Creating virtual environment (venv)..."
if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
    echo -e "${GREEN}[+] venv created${NC}"
else
    echo -e "${GREEN}[+] venv already exists, reusing${NC}"
fi

# ─── 3. Activate venv ──────────────────────────────────────────────
# shellcheck source=/dev/null
source venv/bin/activate

# ─── 4. Upgrade pip toolchain ──────────────────────────────────────
echo -e "\n[*] Upgrading pip, setuptools, wheel..."
pip install --upgrade pip setuptools wheel >/dev/null
echo -e "${GREEN}[+] Toolchain upgraded${NC}"

# ─── 5. Install HEAVEN ─────────────────────────────────────────────
echo -e "\n[*] Installing HEAVEN dependencies..."
pip install -r requirements.txt
pip install -e .
echo -e "${GREEN}[+] HEAVEN installed${NC}"

# ─── 5.5 Frontend (optional) ───────────────────────────────────────
if [ -d "heaven-ui" ]; then
    echo -e "\n[*] Building frontend UI..."
    if ! command -v npm >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] npm not found. Skipping frontend build.${NC}"
        echo "    Install Node.js 18+ to build the UI later: cd heaven-ui && npm install && npm run build"
    else
        ( cd heaven-ui && npm install && npm run build )
        echo -e "${GREEN}[+] Frontend built${NC}"
    fi
fi

# ─── 6. Database setup ─────────────────────────────────────────────
echo -e "\n[*] Setting up PostgreSQL..."

# Generate a DB password if the user hasn't provided one
if [ -z "${HEAVEN_DB_PASSWORD:-}" ]; then
    HEAVEN_DB_PASSWORD=$($PYTHON_CMD -c 'import secrets; print(secrets.token_urlsafe(24))')
    echo -e "${YELLOW}[!] HEAVEN_DB_PASSWORD not set in environment.${NC}"
    echo -e "    Generated one for this install. Save it: ${CYAN}$HEAVEN_DB_PASSWORD${NC}"
    echo "    Add to your shell profile: export HEAVEN_DB_PASSWORD='$HEAVEN_DB_PASSWORD'"
    export HEAVEN_DB_PASSWORD
fi

if command -v docker-compose >/dev/null 2>&1; then
    POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker-compose up -d postgres
    sleep 5
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    POSTGRES_PASSWORD="$HEAVEN_DB_PASSWORD" docker compose up -d postgres
    sleep 5
elif command -v psql >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Using native PostgreSQL${NC}"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl start postgresql 2>/dev/null || true
    fi
    sudo -u postgres psql -c "CREATE USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null || \
        sudo -u postgres psql -c "ALTER USER heaven WITH PASSWORD '$HEAVEN_DB_PASSWORD';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE heaven OWNER heaven;" 2>/dev/null || true
    # Note: we are NOT giving SUPERUSER. Restrict privileges per principle of least privilege.
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE heaven TO heaven;" 2>/dev/null || true
else
    echo -e "${YELLOW}[!] Neither Docker nor native PostgreSQL found.${NC}"
    echo "    Install one of them, then run: heaven init-db"
fi

# ─── 7. Init schema ────────────────────────────────────────────────
echo -e "\n[*] Initialising database schema..."
heaven init-db || echo -e "${YELLOW}[!] Database init failed. Make sure PostgreSQL is running and HEAVEN_DB_PASSWORD is set.${NC}"

# ─── 8. Optional: global symlink (no sudo by default) ──────────────
echo -e "\n[*] Setup notes:"
echo -e "    - Activate the venv: ${CYAN}source venv/bin/activate${NC}"
echo -e "    - Run the CLI:        ${CYAN}heaven --help${NC}"
echo -e "    - Start the server:   ${CYAN}heaven serve${NC}"
echo -e "    - Required env vars to set:"
echo -e "        ${CYAN}HEAVEN_DB_PASSWORD${NC}      (set: ${HEAVEN_DB_PASSWORD:0:6}...)"
echo -e "        ${CYAN}HEAVEN_ADMIN_PASSWORD${NC}   (for the API admin user)"
echo ""

if [ "${HEAVEN_INSTALL_GLOBAL:-0}" = "1" ]; then
    HEAVEN_BIN="$(pwd)/venv/bin/heaven"
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$HEAVEN_BIN" /usr/local/bin/heaven
        echo -e "${GREEN}[+] Global 'heaven' command installed${NC}"
    else
        sudo ln -sf "$HEAVEN_BIN" /usr/local/bin/heaven && \
            echo -e "${GREEN}[+] Global 'heaven' command installed${NC}" || \
            echo -e "${YELLOW}[!] Could not install global symlink (sudo declined)${NC}"
    fi
fi

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}Setup complete.${NC}"
echo -e "${CYAN}======================================================${NC}"
