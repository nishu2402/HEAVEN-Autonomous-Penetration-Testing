#!/usr/bin/env bash
# ==============================================================================
#  HEAVEN — Autonomous Penetration Testing Framework
#  Uninstaller v2.0
#
#  Removes: venv, CLI symlinks, shell RC PATH entries, egg-info, __pycache__
#  Keeps:   source code, scan data (unless empty), engagement DBs, config
#
#  Usage: ./uninstall.sh
#         sudo ./uninstall.sh   (if heaven was installed to /usr/local/bin)
# ==============================================================================

set -uo pipefail   # -u: catch undefined vars; no -e so all cleanup steps run

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; }

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                    HEAVEN Uninstaller v1.3.0                   ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Project directory: ${BOLD}${INSTALL_DIR}${NC}"
echo ""

# ── Resolve target user home (handle sudo correctly) ──────────────────────────
TARGET_USER="${SUDO_USER:-${USER:-$(whoami)}}"
TARGET_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ]; then
    if command -v getent >/dev/null 2>&1; then
        _gh="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)" || true
        [ -d "${_gh:-}" ] && TARGET_HOME="$_gh"
    fi
    if [ ! -d "$TARGET_HOME" ] || [ "$TARGET_HOME" = "/root" ]; then
        _gh="$(eval echo "~${SUDO_USER}" 2>/dev/null)" || true
        [ -d "${_gh:-}" ] && TARGET_HOME="$_gh"
    fi
fi
[ -d "$TARGET_HOME" ] || { fail "Cannot resolve home dir — aborting"; exit 1; }

# ── Portable sed in-place ─────────────────────────────────────────────────────
# GNU sed (Linux): sed -i 'expr' file
# BSD sed (macOS): sed -i '' 'expr' file
_sed_i() {
    local pattern="$1"; local file="$2"
    if sed --version >/dev/null 2>&1; then
        sed -i "$pattern" "$file" 2>/dev/null || true     # GNU / Linux
    else
        sed -i "" "$pattern" "$file" 2>/dev/null || true  # BSD / macOS
    fi
}

# ── Step 1: Remove CLI symlinks / wrapper files ───────────────────────────────
echo ""
info "Step 1/5 — Removing CLI wrappers..."

_removed_wrapper=0
for wrapper_path in \
    "$TARGET_HOME/.local/bin/heaven" \
    "/usr/local/bin/heaven" \
    "/usr/bin/heaven"
do
    if [ -L "$wrapper_path" ] || [ -f "$wrapper_path" ]; then
        link_target="$(readlink "$wrapper_path" 2>/dev/null || true)"
        # Only remove if it was installed by THIS repo (or is unlinked / dangling)
        if [ -z "$link_target" ] || echo "$link_target" | grep -qF "$INSTALL_DIR"; then
            if rm -f "$wrapper_path" 2>/dev/null; then
                ok "Removed: $wrapper_path"
            else
                warn "Permission denied: $wrapper_path  (re-run with sudo to remove)"
            fi
            _removed_wrapper=1
        else
            warn "Skipping: $wrapper_path  →  $link_target  (different install)"
        fi
    fi
done

[ "$_removed_wrapper" -eq 0 ] && warn "No CLI wrapper found (already removed or never installed)"

# ── Step 2: Remove PATH export from shell RC files ────────────────────────────
echo ""
info "Step 2/5 — Removing PATH entries from shell configs..."

# install.sh writes these two lines (# HEAVEN_BIN marker + export):
#   # HEAVEN_BIN
#   export PATH="/path/to/venv/bin:$PATH"
#
# Earlier installer versions used: # HEAVEN — added by install.sh

_cleaned_rc=0
for rc in \
    "$TARGET_HOME/.zshrc" \
    "$TARGET_HOME/.bashrc" \
    "$TARGET_HOME/.bash_profile" \
    "$TARGET_HOME/.profile" \
    "$TARGET_HOME/.config/fish/config.fish"
do
    [ -f "$rc" ] || continue
    _hit=0
    grep -q "HEAVEN_BIN"             "$rc" 2>/dev/null && _hit=1
    grep -q "HEAVEN.*added by"       "$rc" 2>/dev/null && _hit=1
    grep -q "venv/bin.*HEAVEN"       "$rc" 2>/dev/null && _hit=1
    echo "$rc" | grep -qF "$INSTALL_DIR" && _hit=1

    if [ "$_hit" -eq 1 ]; then
        # Remove the marker comment
        _sed_i '/^# HEAVEN_BIN$/d' "$rc"
        # Remove the venv/bin export line placed by this repo's installer
        _sed_i "\|export PATH=\"${INSTALL_DIR}/venv/bin:\\\$PATH\"|d" "$rc"
        # Legacy: export with $HOME/.local/bin added by old installer
        _sed_i '/export PATH="\$HOME\/\.local\/bin:\$PATH"/d' "$rc"
        # Remove any old-style HEAVEN marker comment
        _sed_i '/# HEAVEN.*added by install\.sh/d' "$rc"
        ok "Cleaned: $rc"
        _cleaned_rc=1
    fi
done

[ "$_cleaned_rc" -eq 0 ] && warn "No HEAVEN PATH entries found in shell configs"

# ── Step 3: Remove virtual environment ───────────────────────────────────────
echo ""
info "Step 3/5 — Removing virtual environment..."

if [ -d "$INSTALL_DIR/venv" ]; then
    rm -rf "$INSTALL_DIR/venv"
    ok "Removed: $INSTALL_DIR/venv"
else
    warn "venv not found (already removed)"
fi

# ── Step 4: Remove Python build artifacts ────────────────────────────────────
echo ""
info "Step 4/5 — Removing Python build artifacts..."

# egg-info (created by pip install -e .)
for ei in "$INSTALL_DIR"/heaven.egg-info "$INSTALL_DIR"/heaven_pentest.egg-info; do
    if [ -d "$ei" ]; then
        rm -rf "$ei" && ok "Removed: $(basename "$ei")"
    fi
done

# __pycache__ directories (anywhere in the project, skip .git)
_cache_count=0
while IFS= read -r -d '' cache_dir; do
    rm -rf "$cache_dir" 2>/dev/null && _cache_count=$((_cache_count + 1))
done < <(find "$INSTALL_DIR" \
            -not -path "*/.git/*" \
            -not -path "*/venv/*" \
            -name "__pycache__" -type d \
            -print0 2>/dev/null)
[ "$_cache_count" -gt 0 ] && ok "Removed ${_cache_count} __pycache__ dir(s)"

# Stray .pyc files
find "$INSTALL_DIR" \
    -not -path "*/.git/*" \
    -not -path "*/venv/*" \
    -name "*.pyc" -delete 2>/dev/null || true

# Any .bak files left by previous uninstaller runs
find "$INSTALL_DIR" \
    -not -path "*/.git/*" \
    -maxdepth 2 \
    -name "*.bak" -delete 2>/dev/null || true

ok "Build artifacts cleaned"

# ── Step 5: Report on scan / engagement data ─────────────────────────────────
echo ""
info "Step 5/5 — Checking runtime data directories..."

_has_data=0
for dir in \
    "$INSTALL_DIR/data/scans" \
    "$INSTALL_DIR/data/reports" \
    "$INSTALL_DIR/data/cache" \
    "$INSTALL_DIR/data/audit" \
    "$INSTALL_DIR/data/engagements" \
    "$INSTALL_DIR/engagements"
do
    [ -d "$dir" ] || continue
    if [ -z "$(ls -A "$dir" 2>/dev/null)" ]; then
        rmdir "$dir" 2>/dev/null && ok "Removed empty: $dir" || true
    else
        warn "Keeping non-empty: $dir"
        warn "  → Remove manually with: rm -rf \"$dir\""
        _has_data=1
    fi
done

[ "$_has_data" -eq 0 ] && ok "No residual scan data found"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║              HEAVEN uninstalled successfully                 ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Source code kept at: ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  To delete entirely:  ${CYAN}rm -rf \"${INSTALL_DIR}\"${NC}"
echo ""

if [ "$_cleaned_rc" -eq 1 ]; then
    echo -e "  ${YELLOW}${BOLD}Open a new terminal (or run: source ~/.zshrc) to clear PATH changes.${NC}"
    echo ""
fi

echo -e "  Re-install any time:  ${CYAN}cd \"${INSTALL_DIR}\" && ./install.sh${NC}"
echo ""
