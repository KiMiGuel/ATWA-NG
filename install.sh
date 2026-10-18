#!/usr/bin/env bash
# ATWA-NG one-line installer.
# Usage: curl -fsSL https://indepentest.pro/install.sh | bash
#        (or: bash install.sh [--dry-run])
#
# Installs system dependencies, creates a venv, and installs ATWA-NG from PyPI.

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

# --- distro check -----------------------------------------------------------
if ! command -v apt-get >/dev/null 2>&1; then
    echo "error: this installer targets Debian/Ubuntu/Kali (apt-get not found)." >&2
    echo "       install manually: pip install atwa  (plus: iw iproute2 ethtool procps)" >&2
    exit 1
fi

# --- system dependencies -----------------------------------------------------
echo "==> Installing system dependencies (iw, iproute2, ethtool, procps, python3)..."
run sudo apt-get update
run sudo apt-get install -y iw iproute2 ethtool procps python3 python3-venv python3-pip

# --- venv -------------------------------------------------------------------
VENV_DIR="${ATWA_VENV_DIR:-/opt/atwa}"
echo "==> Setting up venv at $VENV_DIR..."
if [ "$DRY_RUN" -eq 0 ]; then
    sudo mkdir -p "$VENV_DIR"
    sudo chown "$(id -u):$(id -g)" "$VENV_DIR"
fi
if [ ! -x "$VENV_DIR/bin/python" ]; then
    run python3 -m venv "$VENV_DIR"
fi

# --- install / upgrade ATWA-NG from PyPI ------------------------------------
echo "==> Installing ATWA-NG from PyPI..."
run "$VENV_DIR/bin/pip" install --upgrade pip
run "$VENV_DIR/bin/pip" install --upgrade atwa

# --- symlink ----------------------------------------------------------------
BIN_LINK="${ATWA_BIN_LINK:-/usr/local/bin/atwa}"
echo "==> Linking $BIN_LINK -> $VENV_DIR/bin/atwa..."
if [ "$DRY_RUN" -eq 0 ]; then
    sudo ln -sf "$VENV_DIR/bin/atwa" "$BIN_LINK"
fi

# --- verify -----------------------------------------------------------------
if [ "$DRY_RUN" -eq 0 ]; then
    echo "==> Installed: $($VENV_DIR/bin/atwa --version)"
    echo ""
    echo "Run 'atwa --help' to get started. (Requires root for monitor mode.)"
else
    echo "[dry-run] would run: $VENV_DIR/bin/atwa --version"
fi