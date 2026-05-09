#!/usr/bin/env bash
# ==============================================================================
#  HEAVEN — Autonomous Penetration Testing Framework
#  Uninstaller v1.0
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Install directory: $INSTALL_DIR"

# Determine target user home similar to install.sh (supports sudo)
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME="${SUDO_HOME:-${HOME}}"
if [ -n "${SUDO_USER:-}" ] && [ "$TARGET_HOME" = "/root" ]; then
  if getent passwd "$SUDO_USER" >/dev/null 2>&1; then
    TARGET_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  else
    TARGET_HOME="$(eval echo ~${SUDO_USER} 2>/dev/null || true)"
  fi
fi

if [ -z "$TARGET_HOME" ] || [ ! -d "$TARGET_HOME" ]; then
  warn "Could not determine TARGET_HOME reliably; using current $HOME"
  TARGET_HOME="$HOME"
fi

WRAPPER_PATH="$TARGET_HOME/.local/bin/heaven"

info "Removing global wrapper (if present)..."
if [ -L "$WRAPPER_PATH" ] || [ -f "$WRAPPER_PATH" ]; then
  rm -f "$WRAPPER_PATH" 2>/dev/null || true
  ok "Removed $WRAPPER_PATH"
else
  warn "Wrapper not found at $WRAPPER_PATH"
fi

# Also try /usr/local/bin
if [ -L "/usr/local/bin/heaven" ] || [ -f "/usr/local/bin/heaven" ]; then
  # Only remove if it looks like a link to this repo's venv
  TARGET="$(readlink "/usr/local/bin/heaven" 2>/dev/null || true)"
  if [ -n "$TARGET" ] && echo "$TARGET" | grep -q "${INSTALL_DIR}/venv"; then
    rm -f "/usr/local/bin/heaven" 2>/dev/null || true
    ok "Removed /usr/local/bin/heaven"
  fi
fi

info "Removing virtual environment (if present)..."
if [ -d "$INSTALL_DIR/venv" ]; then
  rm -rf "$INSTALL_DIR/venv" 2>/dev/null || true
  ok "Removed $INSTALL_DIR/venv"
else
  warn "venv not found at $INSTALL_DIR/venv"
fi

# Optionally remove PATH export line added by installer
SHELL_RC=""
case "${SHELL:-}" in
  */zsh)  SHELL_RC="$TARGET_HOME/.zshrc" ;;
  */bash) SHELL_RC="$TARGET_HOME/.bashrc" ;;
  */fish) SHELL_RC="$TARGET_HOME/.config/fish/config.fish" ;;
  *)      SHELL_RC="$TARGET_HOME/.profile" ;;
esac

if [ -n "$SHELL_RC" ] && [ -f "$SHELL_RC" ]; then
  if grep -q "HEAVEN — added by install.sh" "$SHELL_RC" 2>/dev/null; then
    # delete the block containing the marker comment and the export line
    # (simple line-based delete)
    sed -i.bak '/HEAVEN — added by install\.sh/d' "$SHELL_RC" 2>/dev/null || true
    sed -i.bak '/export PATH="\$HOME\/\.local\/bin:\$PATH"/d' "$SHELL_RC" 2>/dev/null || true
    ok "Removed PATH export marker from $SHELL_RC (backup: $SHELL_RC.bak)"
  fi
fi

echo ""
info "Uninstall complete."

