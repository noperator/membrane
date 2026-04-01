#!/usr/bin/env bash
# install-macos.sh
# Sets up a dedicated Colima VM for membrane, then runs install-linux.sh inside it.
# Usage: bash install-macos.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_SCRIPT="$SCRIPT_DIR/install-linux.sh"

COLIMA_PROFILE="membrane"
DOCKER_CONTEXT_NAME="colima-${COLIMA_PROFILE}"
COLIMA_CONFIG="${HOME}/.config/colima/${COLIMA_PROFILE}/colima.yaml"

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() {
    echo -e "${RED}[✗]${NC} $*" >&2
    exit 1
}

# -------------------------------------------------------
# Platform check
# -------------------------------------------------------
[[ "$(uname)" == "Darwin" ]] || error "This script is macOS only."
[[ -f "$LINUX_SCRIPT" ]] || error "install-linux.sh not found at $LINUX_SCRIPT"

# -------------------------------------------------------
# Homebrew dependencies
# -------------------------------------------------------
command -v brew &>/dev/null || error "Homebrew not found. Install from https://brew.sh first."

info "Ensuring colima and docker CLI are installed..."
for pkg in colima docker; do
    if brew list "$pkg" &>/dev/null; then
        info "  $pkg already installed"
    else
        brew install "$pkg"
    fi
done

# -------------------------------------------------------
# Colima VM (dedicated 'membrane' profile)
#
# --activate=false prevents Colima from switching the active
# Docker context, leaving the user's existing context intact.
#
# CPU/memory/disk can be overridden via environment:
#   COLIMA_CPU=6 COLIMA_MEMORY=8 COLIMA_DISK=60 bash install-macos.sh
#
# Disk size can only be increased after creation, never decreased.
# -------------------------------------------------------
COLIMA_CPU="${COLIMA_CPU:-4}"
COLIMA_MEMORY="${COLIMA_MEMORY:-4}"
COLIMA_DISK="${COLIMA_DISK:-40}"

if colima status --profile "$COLIMA_PROFILE" 2>/dev/null | grep -q "colima is running"; then
    info "Colima '$COLIMA_PROFILE' profile is already running — using existing instance."
    warn "  To recreate: colima stop --profile $COLIMA_PROFILE && colima delete -f -d --profile $COLIMA_PROFILE && bash $0"
elif colima list 2>/dev/null | grep -q "^${COLIMA_PROFILE}"; then
    info "Colima '$COLIMA_PROFILE' profile exists but is stopped — starting it..."
    colima start --profile "$COLIMA_PROFILE" --activate=false
else
    info "Creating Colima '$COLIMA_PROFILE' VM (cpu=${COLIMA_CPU}, memory=${COLIMA_MEMORY}GB, disk=${COLIMA_DISK}GB)..."
    colima start \
        --profile "$COLIMA_PROFILE" \
        --activate=false \
        --cpu "$COLIMA_CPU" \
        --memory "$COLIMA_MEMORY" \
        --disk "$COLIMA_DISK" \
        --vm-type vz \
        --mount-type virtiofs \
        --arch aarch64
fi

# -------------------------------------------------------
# Register sysbox-runc in Colima's docker config so it
# persists across VM restarts. Colima regenerates daemon.json
# from colima.yaml on every start, so we patch colima.yaml
# on the host rather than daemon.json inside the VM.
#
# We replace `docker: {}` with inline JSON (valid YAML) that
# adds the sysbox-runc runtime entry. The grep ensures this
# is idempotent — if already patched, nothing happens.
# A restart applies the config before install-linux.sh runs.
# -------------------------------------------------------
if grep -q '^docker: {}$' "$COLIMA_CONFIG" 2>/dev/null; then
    info "Registering sysbox-runc in Colima docker config..."
    sed -i '' \
        's|^docker: {}$|docker: {"runtimes": {"sysbox-runc": {"path": "/usr/bin/sysbox-runc"}}}|' \
        "$COLIMA_CONFIG"
    info "Restarting Colima to apply docker runtime config..."
    colima stop --profile "$COLIMA_PROFILE"
    colima start --profile "$COLIMA_PROFILE" --activate=false
fi

# -------------------------------------------------------
# Run Linux install script inside the VM.
# bash -s reads the script from stdin; install-linux.sh does not
# read from stdin itself so there is no conflict.
# -------------------------------------------------------
info "Copying install-linux.sh into VM and running..."
colima ssh --profile "$COLIMA_PROFILE" -- bash -s <"$LINUX_SCRIPT"

# -------------------------------------------------------
# Verify from host — run a sysbox container to confirm end-to-end
# (sysbox-runc does not appear in 'docker info' from the host,
# so we verify by actually running a container with the runtime)
# -------------------------------------------------------
echo ""
info "Verifying sysbox from host..."
if DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker run --rm --runtime=sysbox-runc alpine:3.21 echo "sysbox ok"; then
    info "Sysbox verified — ready to use."
else
    error "Sysbox runtime not working from host. Try: colima restart --profile $COLIMA_PROFILE"
fi

echo ""
info "Done. Run 'membrane' from any workspace to start."
