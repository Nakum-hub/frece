#!/usr/bin/env bash
#
# FRECE — one-command installer
# ------------------------------
# Installs the system forensic tools FRECE depends on AND the FRECE CLI itself
# into an isolated environment, so a single command gives you a working `frece`.
#
# This installer is designed for "externally managed" Python environments
# (Kali, Debian 12+, Ubuntu 23.04+ — PEP 668). It does NOT touch the
# system Python; it uses pipx (preferred) or a dedicated virtualenv instead,
# so you will never see the `error: externally-managed-environment` message.
#
# Usage:
#   # straight from GitHub (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/Nakum-hub/frece/main/install.sh | sudo bash
#
#   # or from a local clone:
#   git clone https://github.com/Nakum-hub/frece.git && cd frece
#   sudo ./install.sh
#
# Environment overrides:
#   FRECE_SOURCE   Install source (default: auto-detect local clone, else the
#                  GitHub repo). May be a path or a pip/pipx spec.
#   SKIP_SYSTEM    If set to 1, skip installing the apt/dnf/pacman system tools.
#
set -euo pipefail

REPO_URL="https://github.com/Nakum-hub/frece.git"
GIT_SPEC="git+${REPO_URL}"

# ---- pretty output -----------------------------------------------------------
if [ -t 1 ]; then
    B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
else
    B=""; G=""; Y=""; R=""; C=""; N=""
fi
info()  { printf '%s==>%s %s\n' "$C" "$N" "$*"; }
ok()    { printf '%s ✓ %s%s\n' "$G" "$*" "$N"; }
warn()  { printf '%s ! %s%s\n' "$Y" "$*" "$N"; }
die()   { printf '%s ✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

# ---- privilege helper (for installing system packages) -----------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

# ---- who should own the FRECE install? --------------------------------------
# When invoked as `sudo ./install.sh`, system packages need root, but the CLI
# should belong to the human user so it lands on *their* PATH (not root's).
TARGET_USER="$(id -un)"
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    TARGET_USER="$SUDO_USER"
fi
TARGET_HOME="$(eval echo "~${TARGET_USER}")"

# Run a command as the target user (drops root when we were sudo'd in).
as_user() {
    if [ "$TARGET_USER" != "$(id -un)" ]; then
        sudo -u "$TARGET_USER" -H "$@"
    else
        "$@"
    fi
}

# ---- detect the install source ----------------------------------------------
# If this script lives next to a FRECE checkout, install from that checkout.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "${FRECE_SOURCE:-}" ]; then
    SOURCE="$FRECE_SOURCE"
elif [ -n "$SCRIPT_DIR" ] && grep -qs '^name = "frece"' "$SCRIPT_DIR/pyproject.toml" 2>/dev/null; then
    SOURCE="$SCRIPT_DIR"
else
    SOURCE="$GIT_SPEC"
fi

# ---- step 1: system prerequisites -------------------------------------------
install_system_deps() {
    if [ "${SKIP_SYSTEM:-0}" = "1" ]; then
        warn "SKIP_SYSTEM=1 — skipping system tool installation"
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Installing system tools via apt (Sleuth Kit, ewf-tools, libmagic, YARA, pipx)…"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y --no-install-recommends \
            sleuthkit ewf-tools libmagic1 yara \
            python3 python3-venv python3-pip pipx git \
            || warn "Some apt packages could not be installed — continuing"
    elif command -v dnf >/dev/null 2>&1; then
        info "Installing system tools via dnf…"
        $SUDO dnf install -y sleuthkit libewf-tools file-libs yara \
            python3 python3-pip pipx git || warn "Some dnf packages could not be installed"
    elif command -v pacman >/dev/null 2>&1; then
        info "Installing system tools via pacman…"
        $SUDO pacman -Sy --noconfirm sleuthkit libewf file yara \
            python python-pip python-pipx git || warn "Some pacman packages could not be installed"
    elif command -v brew >/dev/null 2>&1; then
        info "Installing system tools via Homebrew…"
        brew install sleuthkit libewf libmagic yara python pipx git || warn "Some brew packages could not be installed"
    else
        warn "No supported package manager found (apt/dnf/pacman/brew)."
        warn "Install these manually: sleuthkit, ewf-tools, libmagic, yara, python3, pipx."
    fi
}

# ---- step 2: install FRECE (PEP 668 safe, owned by the target user) ---------
install_with_pipx() {
    if ! as_user bash -c 'command -v pipx >/dev/null 2>&1'; then
        return 1
    fi
    info "Installing FRECE with pipx for user '${TARGET_USER}' from: ${SOURCE}"
    as_user pipx install --force "$SOURCE"
    as_user pipx ensurepath >/dev/null 2>&1 || true
}

install_with_venv() {
    info "Falling back to a dedicated virtualenv installation…"
    local venv="${TARGET_HOME}/.local/share/frece/venv"
    local bindir="${TARGET_HOME}/.local/bin"
    as_user mkdir -p "$(dirname "$venv")" "$bindir"
    as_user python3 -m venv "$venv"
    as_user "$venv/bin/pip" install --quiet --upgrade pip
    as_user "$venv/bin/pip" install --quiet "$SOURCE"
    as_user ln -sf "$venv/bin/frece" "$bindir/frece"
    warn "Ensure ${bindir} is on your PATH:  export PATH=\"${bindir}:\$PATH\""
}

# ---- run ---------------------------------------------------------------------
printf '%s\nFRECE installer%s\n\n' "$B" "$N"
install_system_deps

if ! install_with_pipx; then
    warn "pipx installation unavailable — using virtualenv fallback."
    install_with_venv
fi

# ---- verify ------------------------------------------------------------------
echo
if as_user bash -lc 'command -v frece >/dev/null 2>&1'; then
    ok "FRECE installed: $(as_user bash -lc 'frece --version' 2>/dev/null || echo unknown)"
    info "Verifying external forensic tools:"
    as_user bash -lc 'frece tool-status' || true
    echo
    ok "Done. Open a new shell (or run 'hash -r') if 'frece' is not yet on your PATH."
else
    warn "FRECE was installed but 'frece' is not on the PATH yet."
    warn "Start a new terminal, or run:  export PATH=\"${TARGET_HOME}/.local/bin:\$PATH\""
fi
