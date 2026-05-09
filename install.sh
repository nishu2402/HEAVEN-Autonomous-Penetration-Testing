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
echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║   ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗     ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║     ║${NC}"
echo -e "${CYAN}${BOLD}║   ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║     ║${NC}"
echo -e "${CYAN}${BOLD}║   ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║     ║${NC}"
echo -e "${CYAN}${BOLD}║   ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║     ║${NC}"
echo -e "${CYAN}${BOLD}║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ║${NC}"
echo -e "${CYAN}${BOLD}║        Autonomous Penetration Testing Framework            ║${NC}"
echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
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

# ── 5. Write global 'heaven' wrapper ──────────────────────────────────────────
step "Step 5/8 — Installing global 'heaven' command..."

# Resolve the exact python binary used by this venv (no symlinks)
VENV_PYTHON_REAL="$("$VENV_PYTHON" -c "import sys; print(sys.executable)")"

# _write_wrapper <dest>  — writes the wrapper; returns 1 on any failure.
# All call sites use  if _write_wrapper ...; then  so set -e never fires.
_write_wrapper() {
    local dest="$1"
    [ -d "$(dirname "$dest")" ] || return 1
    printf '#!/usr/bin/env bash\nexec "%s" -m heaven.main "$@"\n' \
        "$VENV_PYTHON_REAL" > "$dest" 2>/dev/null || return 1
    chmod +x "$dest" 2>/dev/null || return 1
}

WRAPPER_PATH=""
ADDED_RC=""

# ── Strategy A: any writable directory already in the user's PATH ─────────────
# This is the zero-config path: if ANY directory the shell already knows about
# is writable (e.g. ~/bin, ~/.local/bin, /usr/local/bin as root), we use it.
# heaven works immediately — no sudo, no sourcing, no new terminal needed.
_path_writable_dir() {
    local IFS=':'
    local preferred="/usr/local/bin $HOME/.local/bin $HOME/bin"
    # Preferred well-known dirs first
    for d in $preferred; do
        case ":$PATH:" in *":$d:"*)
            if [ -d "$d" ] && [ -w "$d" ]; then echo "$d"; return 0; fi
        esac
    done
    # Any other writable PATH dir
    for d in $PATH; do
        if [ -d "$d" ] && [ -w "$d" ]; then echo "$d"; return 0; fi
    done
    return 1
}

if WRITABLE_DIR="$(_path_writable_dir 2>/dev/null)"; then
    if _write_wrapper "$WRITABLE_DIR/heaven"; then
        WRAPPER_PATH="$WRITABLE_DIR/heaven"
        ok "Global command installed: $WRAPPER_PATH"
    fi
fi

# ── Strategy B: sudo to /usr/local/bin ───────────────────────────────────────
# Prompts for the sudo password — same as apt, homebrew, etc.
# /usr/local/bin is always in PATH so heaven works in every terminal immediately.
if [ -z "$WRAPPER_PATH" ] && command -v sudo >/dev/null 2>&1; then
    info "Need sudo to install system-wide (will prompt for password)..."
    _PYR="$VENV_PYTHON_REAL"   # capture before sudo subshell
    if sudo bash -c "
        mkdir -p /usr/local/bin || exit 1
        printf '#!/usr/bin/env bash\nexec \"%s\" -m heaven.main \"\$@\"\n' '$_PYR' \
            > /usr/local/bin/heaven 2>/dev/null || exit 1
        chmod +x /usr/local/bin/heaven
    "; then
        WRAPPER_PATH="/usr/local/bin/heaven"
        ok "Global command installed: /usr/local/bin/heaven"
    else
        warn "sudo install to /usr/local/bin failed — trying user-local fallback"
    fi
fi

# ── Strategy C: ~/.local/bin — create + add to PATH in shell RC ───────────────
# Last resort. heaven will work after opening a new terminal (PATH is updated
# in the shell RC so every future session includes ~/.local/bin automatically).
if [ -z "$WRAPPER_PATH" ]; then
    LOCAL_BIN="$TARGET_HOME/.local/bin"
    mkdir -p "$LOCAL_BIN" 2>/dev/null || true
    if [ -d "$LOCAL_BIN" ] && _write_wrapper "$LOCAL_BIN/heaven"; then
        WRAPPER_PATH="$LOCAL_BIN/heaven"
        ok "User command installed: $LOCAL_BIN/heaven"

        # Idempotently inject PATH update into the user's shell RC
        _add_to_path() {
            local rc="$1"
            [ -f "$rc" ] || return 1
            grep -q "# HEAVEN PATH" "$rc" 2>/dev/null && return 0
            {
                printf '\n# HEAVEN PATH\n'
                printf 'if [ -d "$HOME/.local/bin" ]; then\n'
                printf '  case ":$PATH:" in\n'
                printf '    *":$HOME/.local/bin:"*) ;;\n'
                printf '    *) export PATH="$HOME/.local/bin:$PATH" ;;\n'
                printf '  esac\n'
                printf 'fi\n'
            } >> "$rc" 2>/dev/null && ok "PATH updated in $rc"
        }

        case "${SHELL:-/bin/bash}" in
            */zsh)
                _add_to_path "$TARGET_HOME/.zshrc"    && ADDED_RC="$TARGET_HOME/.zshrc"  ;;
            */fish)
                FISH_CFG="$TARGET_HOME/.config/fish/config.fish"
                mkdir -p "$(dirname "$FISH_CFG")" 2>/dev/null || true
                _add_to_path "$FISH_CFG"              && ADDED_RC="$FISH_CFG"  ;;
            *)
                _add_to_path "$TARGET_HOME/.bashrc"   && ADDED_RC="$TARGET_HOME/.bashrc"
                [ -z "$ADDED_RC" ] && \
                _add_to_path "$TARGET_HOME/.profile"  && ADDED_RC="$TARGET_HOME/.profile"  ;;
        esac
    fi
fi

if [ -z "$WRAPPER_PATH" ]; then
    warn "Could not write heaven wrapper to any location."
    warn "Run directly: $VENV_PYTHON_REAL -m heaven.main <command>"
fi

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

# ── 7. Frontend build (optional) ──────────────────────────────────────────────
echo ""
step "Step 7/8 — Building web UI..."

if [ -d "$INSTALL_DIR/heaven-ui" ]; then
    if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found — skipping frontend build"
        echo -e "  ${DIM}Install Node.js 18+ then: cd heaven-ui && npm install --legacy-peer-deps && npm run build${NC}"
    else
        NODE_VER=$(node --version 2>/dev/null || echo "?")
        info "Node $NODE_VER detected"
        if ( cd "$INSTALL_DIR/heaven-ui" && npm install --legacy-peer-deps -q 2>/dev/null && npm run build -q 2>/dev/null ); then
            ok "Frontend built → heaven-ui/dist/"
        else
            warn "Frontend build failed — UI unavailable but CLI works fine"
        fi
    fi
else
    warn "heaven-ui directory not found — skipping frontend build"
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

# ── Show where heaven landed and what to do next ─────────────────────────────
if [ -n "$WRAPPER_PATH" ]; then
    ok "heaven command: $WRAPPER_PATH"
    echo ""
    # Only need to source if we used ~/.local/bin (not already in this session's PATH)
    if [[ "$WRAPPER_PATH" == *"/.local/bin/"* ]] || [[ "$WRAPPER_PATH" == *"/home/"*"/bin/"* ]]; then
        echo -e "${YELLOW}${BOLD}One-time setup — run this in your current terminal:${NC}"
        if [ -n "${ADDED_RC:-}" ]; then
            echo -e "  ${CYAN}source ${ADDED_RC}${NC}"
        else
            echo -e "  ${CYAN}export PATH=\"\$(dirname '$WRAPPER_PATH'):\$PATH\"${NC}"
        fi
        echo -e "${DIM}  (Every new terminal after this will have 'heaven' automatically.)${NC}"
        echo ""
    fi
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
