#!/usr/bin/env bash
# ==============================================================================
#  HEAVEN — Autonomous Penetration Testing Framework
#  Installer v2.2
# ==============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step() { echo -e "${BOLD}${CYAN}[→]${NC}${BOLD} $*${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║   ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗    ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║    ║${NC}"
echo -e "${CYAN}${BOLD}║   ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║    ║${NC}"
echo -e "${CYAN}${BOLD}║   ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║    ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║    ║${NC}"
echo -e "${CYAN}${BOLD}║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝    ║${NC}"
echo -e "${CYAN}${BOLD}║        Autonomous Penetration Testing Framework          ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

# ── Resolve install directory ──────────────────────────────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Install directory: ${BOLD}$INSTALL_DIR${NC}"

# ── Detect target user (handle sudo correctly) ────────────────────────────────
TARGET_USER="${SUDO_USER:-$USER}"
if [ -n "${SUDO_USER:-}" ] && command -v getent >/dev/null 2>&1; then
    TARGET_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || eval echo "~${SUDO_USER}")"
else
    TARGET_HOME="$HOME"
fi
[ -d "$TARGET_HOME" ] || fail "Cannot determine home directory (TARGET_HOME='$TARGET_HOME')"

# ── 1. Python check ───────────────────────────────────────────────────────────
step "Step 1/8 — Checking Python..."

if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    fail "Python 3 is not installed. Install Python 3.11 or higher and re-run."
fi

PY_OK=$($PYTHON_CMD -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
PY_VER=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')

if [ "$PY_OK" != "1" ]; then
    fail "Python 3.11+ required. Found: $PY_VER. Please upgrade Python."
fi
ok "Python $PY_VER"

# ── 2. Virtual environment ────────────────────────────────────────────────────
step "Step 2/8 — Setting up virtual environment..."
if [ ! -d "$INSTALL_DIR/venv" ]; then
    $PYTHON_CMD -m venv "$INSTALL_DIR/venv"
    ok "Created venv at $INSTALL_DIR/venv"
else
    ok "Reusing existing venv at $INSTALL_DIR/venv"
fi

VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
VENV_PIP="$INSTALL_DIR/venv/bin/pip"

# Verify venv python works
"$VENV_PYTHON" -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null \
    || fail "venv Python is broken. Delete '$INSTALL_DIR/venv' and re-run."

# ── 3. Pip toolchain ──────────────────────────────────────────────────────────
step "Step 3/8 — Upgrading pip toolchain..."
"$VENV_PIP" install --upgrade pip setuptools wheel -q
ok "pip / setuptools / wheel up to date"

# ── 4. Install HEAVEN ─────────────────────────────────────────────────────────
step "Step 4/8 — Installing HEAVEN and dependencies..."

if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$VENV_PIP" install -r "$INSTALL_DIR/requirements.txt" -q \
        || warn "Some optional dependencies failed to install — core features unaffected"
fi
"$VENV_PIP" install -e "$INSTALL_DIR" -q
ok "HEAVEN installed (editable mode)"

# ── 5. Install global 'heaven' command ────────────────────────────────────────
step "Step 5/8 — Installing global 'heaven' command..."

# After 'pip install -e .' the venv already has a working heaven script.
VENV_HEAVEN="$INSTALL_DIR/venv/bin/heaven"
WRAPPER_PATH=""
ADDED_RC=""

if [ ! -f "$VENV_HEAVEN" ]; then
    fail "venv/bin/heaven not found — did step 4 succeed? Check errors above."
fi

# ── Try 1: direct write to /usr/local/bin (already writable = running as root) ─
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    if ln -sf "$VENV_HEAVEN" /usr/local/bin/heaven 2>/dev/null; then
        WRAPPER_PATH="/usr/local/bin/heaven"
        ok "Installed: /usr/local/bin/heaven"
    fi
fi

# ── Try 2: sudo ln -sf (two plain commands, no heredoc, no escaping issues) ────
if [ -z "$WRAPPER_PATH" ] && command -v sudo >/dev/null 2>&1; then
    info "sudo needed to install system-wide (you may be asked for your password):"
    if sudo mkdir -p /usr/local/bin 2>/dev/null \
    && sudo ln -sf "$VENV_HEAVEN" /usr/local/bin/heaven 2>/dev/null; then
        WRAPPER_PATH="/usr/local/bin/heaven"
        ok "Installed: /usr/local/bin/heaven"
    else
        warn "sudo failed — using PATH fallback instead"
    fi
fi

# ── Try 3: add venv/bin to PATH in shell RC (no root needed) ──────────────────
# heaven already exists at venv/bin/heaven — just make PATH include it.
if [ -z "$WRAPPER_PATH" ]; then
    VENV_BIN="$INSTALL_DIR/venv/bin"
    WRAPPER_PATH="$VENV_HEAVEN"

    # Pick the shell RC file
    case "${SHELL:-/bin/bash}" in
        */zsh)  RC_FILE="$TARGET_HOME/.zshrc"   ;;
        */fish) RC_FILE="$TARGET_HOME/.config/fish/config.fish"
                mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null || true ;;
        *)      RC_FILE="$TARGET_HOME/.bashrc"  ;;
    esac
    # Create RC file if it doesn't exist
    touch "$RC_FILE" 2>/dev/null || RC_FILE="$TARGET_HOME/.profile"
    touch "$RC_FILE" 2>/dev/null || true

    # Inject PATH line (idempotent — skip if already present)
    if ! grep -q "HEAVEN_BIN" "$RC_FILE" 2>/dev/null; then
        printf '\n# HEAVEN_BIN\nexport PATH="%s:$PATH"\n' "$VENV_BIN" >> "$RC_FILE"
        ok "Added $VENV_BIN to PATH in $RC_FILE"
    else
        ok "$VENV_BIN already in $RC_FILE"
    fi
    ADDED_RC="$RC_FILE"
fi

ok "heaven command: $WRAPPER_PATH"

# ── 6. External tools check ───────────────────────────────────────────────────
echo ""
step "Step 6/8 — Checking external tools..."
echo ""

check_tool() {
    local name="$1"; local cmd="$2"; local install_hint="$3"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$name → $(command -v "$cmd")"
    else
        warn "$name not found  ($install_hint)"
    fi
}

check_tool "nmap"    "nmap"    "apt install nmap  |  brew install nmap"
check_tool "nuclei"  "nuclei"  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
check_tool "sqlmap"  "sqlmap"  "pip install sqlmap  |  apt install sqlmap"

# ── 7. Frontend build ─────────────────────────────────────────────────────────
echo ""
step "Step 7/8 — Building web UI..."

# Attempt to install Node.js via the system package manager when it is missing.
# Without a built UI, 'heaven serve' only exposes the API + a placeholder page.
install_nodejs() {
    if command -v apt-get >/dev/null 2>&1; then
        info "Installing Node.js via apt-get..."
        sudo apt-get update -qq && sudo apt-get install -y nodejs npm >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        info "Installing Node.js via dnf..."
        sudo dnf install -y nodejs npm >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        info "Installing Node.js via pacman..."
        sudo pacman -Sy --noconfirm nodejs npm >/dev/null 2>&1
    elif command -v brew >/dev/null 2>&1; then
        info "Installing Node.js via Homebrew..."
        brew install node >/dev/null 2>&1
    else
        return 1
    fi
}

if [ ! -d "$INSTALL_DIR/heaven-ui" ]; then
    warn "heaven-ui directory not found — skipping frontend build"
else
    # Ensure npm is available — try to auto-install if not.
    if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found — attempting to install Node.js automatically..."
        if install_nodejs && command -v npm >/dev/null 2>&1; then
            ok "Node.js installed"
        else
            warn "Could not auto-install Node.js — skipping frontend build"
            echo -e "  ${DIM}Install Node.js 18+ manually, then:${NC}"
            echo -e "  ${DIM}cd heaven-ui && npm install --legacy-peer-deps && npm run build${NC}"
            echo -e "  ${DIM}The CLI works fully without the UI; 'heaven serve' shows a${NC}"
            echo -e "  ${DIM}placeholder page until the UI is built.${NC}"
        fi
    fi

    if command -v npm >/dev/null 2>&1; then
        NODE_VER=$(node --version 2>/dev/null || echo "?")
        NODE_MAJOR=$(echo "$NODE_VER" | sed 's/[^0-9.]//g' | cut -d. -f1)
        info "Node $NODE_VER detected"
        if [ -n "$NODE_MAJOR" ] && [ "$NODE_MAJOR" -lt 18 ] 2>/dev/null; then
            warn "Node.js $NODE_VER is too old — version 18+ recommended. Build may fail."
        fi
        # Build with errors visible in a log so a failure is diagnosable
        # (the old version hid every error behind 2>/dev/null).
        BUILD_LOG="$INSTALL_DIR/heaven-ui/build.log"
        if ( cd "$INSTALL_DIR/heaven-ui" \
             && npm install --legacy-peer-deps >"$BUILD_LOG" 2>&1 \
             && npm run build >>"$BUILD_LOG" 2>&1 ) \
           && [ -f "$INSTALL_DIR/heaven-ui/dist/index.html" ]; then
            ok "Frontend built → heaven-ui/dist/"
            rm -f "$BUILD_LOG"
        else
            warn "Frontend build failed — see $BUILD_LOG"
            echo -e "  ${DIM}UI unavailable but the CLI and API work fine.${NC}"
            echo -e "  ${DIM}Retry: cd heaven-ui && npm install --legacy-peer-deps && npm run build${NC}"
        fi
    fi
fi

# ── 8. Smoke test ─────────────────────────────────────────────────────────────
echo ""
step "Step 8/8 — Smoke test..."

if "$VENV_PYTHON" -m heaven.main --version >/dev/null 2>&1; then
    HEAVEN_VER=$("$VENV_PYTHON" -m heaven.main --version 2>&1 | head -1)
    ok "CLI smoke test passed: $HEAVEN_VER"
else
    warn "CLI smoke test failed — check errors above"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    INSTALLATION COMPLETE                     ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Activation notice (only when venv/bin fallback was used) ─────────────────
if [ -n "${ADDED_RC:-}" ]; then
    echo -e "${YELLOW}${BOLD}Run this ONE command to activate 'heaven' right now:${NC}"
    echo -e "  ${CYAN}source ${ADDED_RC}${NC}"
    echo -e "${DIM}  (New terminals will have 'heaven' automatically — this is a one-time step.)${NC}"
    echo ""
fi

# ── Required config ───────────────────────────────────────────────────────────
echo -e "${BOLD}Set your admin password (required for web UI / API):${NC}"
echo -e "  ${CYAN}export HEAVEN_ADMIN_PASSWORD='your-strong-password'${NC}"
echo -e "  ${DIM}Add to ~/.bashrc or ~/.zshrc to persist across sessions.${NC}"
echo ""

# ── Quick start ───────────────────────────────────────────────────────────────
echo -e "${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}heaven --version${NC}                                   # confirm install"
echo -e "  ${CYAN}heaven engage init my-engagement${NC}                   # create engagement"
echo -e "  ${CYAN}heaven scan -u https://target --i-have-authorization${NC}"
echo -e "  ${CYAN}heaven serve${NC}                                       # web UI → http://localhost:8443"
echo ""
