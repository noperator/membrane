#!/usr/bin/env bash
# install-linux.sh
# Configures BPF LSM and installs persistent Sysbox services on Ubuntu.
# Idempotent — safe to run multiple times.
# Usage: bash install-linux.sh

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

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

enable_sysbox() {
    # Sysbox CE 0.6.7 supplies these three enableable units. The wrapper binds
    # both components and is WantedBy=multi-user.target; components are
    # WantedBy=sysbox.service. Inspect the installed units, never guess a fallback.
    local unit state
    for unit in sysbox.service sysbox-mgr.service sysbox-fs.service; do
        systemctl cat "$unit" >/dev/null 2>&1 || error "Sysbox package unit $unit is missing; reinstall the supported Sysbox package."
    done
    for unit in sysbox-mgr.service sysbox-fs.service sysbox.service; do
        state=$(systemctl is-enabled "$unit" 2>/dev/null) || true
        case "$state" in
        enabled) sudo systemctl start "$unit" ;;
        disabled | enabled-runtime | linked | linked-runtime) sudo systemctl enable --now "$unit" ;;
        *) error "Cannot persist $unit (state: $state); inspect the installed package's systemd units." ;;
        esac
        systemctl is-active --quiet "$unit" || error "sysbox-runc is installed but its backing service $unit is not active."
        [[ "$(systemctl is-enabled "$unit")" == enabled ]] || error "$unit is not enabled across reboot."
        info "$unit: active and enabled"
    done
}

configure_colima_sysbox() {
    [[ "${MEMBRANE_COLIMA:-0}" == 1 ]] || return 0
    # Colima starts Docker after VM provisioning. Pull Sysbox into that start
    # transaction even when the earlier multi-user boot did not start it.
    local dropin=/etc/systemd/system/docker.service.d/membrane-sysbox.conf
    local settings='[Unit]
Wants=sysbox.service
After=sysbox.service'
    systemctl cat --no-pager docker.service >/dev/null 2>&1 || error "Docker's systemd unit is missing."
    if ! sudo cmp -s "$dropin" - <<<"$settings"; then
        sudo test ! -e "$dropin" || error "$dropin has different contents; inspect it before running setup."
        sudo mkdir -p /etc/systemd/system/docker.service.d
        sudo tee "$dropin" >/dev/null <<<"$settings"
        sudo systemctl daemon-reload
    fi
    info "Colima Docker startup pulls in Sysbox before starting containers."
}

# Allow the setup helpers to be exercised against fixture commands without
# running package installation or smoke tests.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return; fi

# -------------------------------------------------------
# Platform check
# -------------------------------------------------------
[[ "$(uname)" == "Linux" ]] || error "This script is Linux only."
command -v apt-get &>/dev/null || error "apt-get not found — Ubuntu/Debian required."
command -v docker &>/dev/null || error "Docker not found. Install Docker first."
command -v systemctl &>/dev/null || error "systemd is required on the Docker host."
[[ -d /run/systemd/system ]] || error "systemd must be running on the Docker host."
command -v python3 &>/dev/null || error "python3 is required for kernel/boot configuration checks."

ARCH=$(dpkg --print-architecture) # amd64 or arm64

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo env MEMBRANE_CONFIGURE_BPF_LSM="${MEMBRANE_CONFIGURE_BPF_LSM:-0}" \
    python3 "$SCRIPT_DIR/setup-bpf-lsm.py"

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
wait_for_docker() {
    local timeout="${1:-30}"
    local elapsed=0
    until docker info &>/dev/null; do
        sleep 2
        elapsed=$((elapsed + 2))
        [[ $elapsed -lt $timeout ]] || error "Docker did not become ready after ${timeout}s."
    done
}

runtime_registered() {
    docker info --format '{{json .Runtimes}}' 2>/dev/null |
        python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if '$1' in d else 1)" 2>/dev/null
}

# -------------------------------------------------------
# Sysbox
# -------------------------------------------------------
if [ -x /usr/bin/sysbox-runc ] && runtime_registered "sysbox-runc"; then
    info "Sysbox already installed and registered — skipping install."
elif [ -x /usr/bin/sysbox-runc ]; then
    info "Sysbox binary present but not registered with Docker — merging /etc/docker/daemon.json..."

    command -v jq &>/dev/null || sudo apt-get install -y -qq jq

    tmp=$(mktemp)
    if ! (sudo test -f /etc/docker/daemon.json && sudo cat /etc/docker/daemon.json || echo '{}') |
        jq '.runtimes["sysbox-runc"].path = "/usr/bin/sysbox-runc"' >"$tmp"; then
        rm -f "$tmp"
        error "Failed to merge sysbox-runc runtime into /etc/docker/daemon.json."
    fi

    sudo mv "$tmp" /etc/docker/daemon.json
    sudo chmod 644 /etc/docker/daemon.json

    info "Reloading Docker daemon..."
    sudo systemctl reload docker || error "Failed to reload Docker daemon."

    runtime_registered "sysbox-runc" || error "Sysbox binary present but not registered with Docker after daemon.json merge."
    info "Sysbox registered: $(sysbox-runc --version 2>&1 | head -1)"
else
    info "Updating apt cache..."
    sudo apt-get update -qq

    info "Installing Sysbox prerequisites..."
    sudo apt-get install -y -qq jq rsync wget

    SYSBOX_VER=0.6.7
    SYSBOX_URL="https://github.com/nestybox/sysbox/releases/download/v${SYSBOX_VER}/sysbox-ce_${SYSBOX_VER}.linux_${ARCH}.deb"

    info "Downloading Sysbox..."
    wget -q -O /tmp/sysbox.deb "$SYSBOX_URL"

    # Sysbox requires Docker to be stopped before installation
    info "Stopping Docker..."
    sudo systemctl stop docker docker.socket containerd 2>/dev/null || true

    info "Installing Sysbox..."
    sudo apt-get install -y /tmp/sysbox.deb
    rm -f /tmp/sysbox.deb

    enable_sysbox

    info "Starting Docker..."
    sudo systemctl start docker
    wait_for_docker 30

    runtime_registered "sysbox-runc" || error "Sysbox installed but not registered with Docker."
    info "Sysbox installed: $(sysbox-runc --version 2>&1 | head -1)"
fi

# -------------------------------------------------------
# Smoke tests
# -------------------------------------------------------
# An already installed Sysbox still needs its services after a VM restart.
enable_sysbox
configure_colima_sysbox
runtime_registered "sysbox-runc" || error "Sysbox services are active but sysbox-runc is not registered with Docker."
info "Running smoke tests..."

# Test 1: basic startup
info "Test 1: basic startup..."
if KERNEL=$(docker run --rm --runtime=sysbox-runc alpine:3.21 uname -r 2>&1); then
    info "  kernel: $KERNEL — OK"
else
    warn "  basic startup FAILED: $KERNEL"
    sudo systemctl status --no-pager sysbox.service sysbox-mgr.service sysbox-fs.service >&2 || true
    warn "  Runtime registration alone is insufficient; check the backing Sysbox daemons and their sockets above."
    exit 1
fi

# Test 2: user namespace isolation — check uid_map directly.
# Sysbox maps container UID 0 → host UID 100000+ via user namespaces.
# Note: bind-mounted directories bypass UID remapping (intentional Sysbox behavior),
# so we check /proc/self/uid_map instead of file ownership on a mount.
info "Test 2: user namespace isolation..."
UID_MAP=$(docker run --rm --runtime=sysbox-runc alpine:3.21 cat /proc/self/uid_map 2>&1)
HOST_UID=$(echo "$UID_MAP" | awk '{print $2}')
if [[ -z "$HOST_UID" || "$HOST_UID" -eq 0 ]]; then
    warn "  userns: uid_map shows no remapping — isolation may not be working"
    warn "  uid_map: $UID_MAP"
else
    info "  userns: container UID 0 maps to host UID $HOST_UID — isolated OK"
fi

# Test 3: nftables egress filtering (membrane relies on this)
info "Test 3: nftables egress filtering..."
if docker run --rm --runtime=sysbox-runc --cap-add NET_ADMIN alpine:3.21 sh -c '
    if ! ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
        echo "SKIP: 1.1.1.1 not reachable (no internet?)"
        exit 0
    fi
    apk add --quiet nftables 2>/dev/null
    nft add table ip membrane
    nft add chain ip membrane output { type filter hook output priority 0 \; policy accept \; }
    nft add rule ip membrane output ip daddr 1.1.1.1 drop
    if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
        echo "FAIL: ping succeeded despite drop rule"
        exit 1
    fi
    nft delete table ip membrane
    if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL: ping failed after removing rule"
        exit 1
    fi
'; then
    info "  nftables: OK"
else
    warn "  nftables: FAILED"
fi

echo ""
info "Done. Sysbox is ready."
