#!/usr/bin/env bash
# install.sh — Download and install p2pvpn on Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Auchrio/p2pvpn/main/install.sh | sudo bash
#
# What it does:
#   1. Detects the CPU architecture (x64, arm64, arm, x86).
#   2. Downloads the latest release binary from GitHub.
#   3. Installs it to /usr/local/bin/p2pvpn.
#   4. Runs "p2pvpn setup" which creates a systemd service and starts the
#      daemon in setup mode.
#   5. You then open http://<machine-ip>:8080 to configure your network.

set -euo pipefail

REPO="Auchrio/p2pvpn"
INSTALL_PATH="/usr/local/bin/p2pvpn"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ── helpers ────────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m➜\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m✓\033[0m  %s\n' "$*"; }
err()   { printf '\033[1;31m✗\033[0m  %s\n' "$*" >&2; }

need() {
  if ! command -v "$1" &>/dev/null; then
    err "Required command '$1' not found. Please install it first."
    exit 1
  fi
}

# ── check privileges ──────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root (sudo)."
  exit 1
fi

# ── detect architecture ───────────────────────────────────────────────────────

detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)      echo "linux-x64"   ;;
    aarch64|arm64)      echo "linux-arm64" ;;
    armv7*|armhf|arm*)  echo "linux-arm"   ;;
    i?86|x86)           echo "linux-x86"   ;;
    *)
      err "Unsupported architecture: $arch"
      exit 1
      ;;
  esac
}

LABEL=$(detect_arch)
BINARY_NAME="p2pvpn-${LABEL}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}"

info "Architecture: ${LABEL}"
info "Download URL: ${DOWNLOAD_URL}"

# ── download ──────────────────────────────────────────────────────────────────

need curl

info "Downloading ${BINARY_NAME}..."
if ! curl -fSL -o "${TMP_DIR}/p2pvpn" "${DOWNLOAD_URL}"; then
  err "Download failed. Check that a release exists at:"
  err "  ${DOWNLOAD_URL}"
  exit 1
fi
chmod +x "${TMP_DIR}/p2pvpn"
ok "Downloaded successfully."

# ── install ───────────────────────────────────────────────────────────────────

info "Installing to ${INSTALL_PATH}..."
mv -f "${TMP_DIR}/p2pvpn" "${INSTALL_PATH}"
ok "Binary installed."

# ── setup (systemd service) ──────────────────────────────────────────────────

info "Running 'p2pvpn setup' to register the system service..."
"${INSTALL_PATH}" setup

echo ""
ok "Installation complete!"
echo ""
echo "   Open  http://<this-machine-ip>:8080  in a browser to configure your network."
echo ""
echo "   Useful commands:"
echo "     systemctl status p2pvpn     — check service status"
echo "     journalctl -u p2pvpn -f     — follow logs"
echo "     sudo p2pvpn setup --remove  — uninstall"
echo ""
