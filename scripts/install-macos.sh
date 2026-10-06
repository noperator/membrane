#!/usr/bin/env bash
# install-macos.sh
# Sets up a dedicated Colima VM for membrane, then runs install-linux.sh inside it.
# Usage: bash install-macos.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_SCRIPT="$SCRIPT_DIR/install-linux.sh"

COLIMA_PROFILE="membrane"
DOCKER_CONTEXT_NAME="colima-${COLIMA_PROFILE}"
BPF_SCRIPT="$SCRIPT_DIR/setup-bpf-lsm.py"

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
[[ -f "$BPF_SCRIPT" ]] || error "setup-bpf-lsm.py not found at $BPF_SCRIPT"

# -------------------------------------------------------
# Homebrew dependencies
# -------------------------------------------------------
command -v brew &>/dev/null || error "Homebrew not found. Install from https://brew.sh first."

info "Ensuring colima, docker CLI, and yq are installed..."
for pkg in colima docker yq; do
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

if colima status --profile "$COLIMA_PROFILE" >/dev/null 2>&1; then
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

# Colima prefers COLIMA_HOME, then an existing ~/.colima, then XDG config.
# Resolve after starting/creating the profile so its config directory exists.
if [[ -n "${COLIMA_HOME:-}" && -d "$COLIMA_HOME" ]]; then
    COLIMA_CONFIG="$COLIMA_HOME/$COLIMA_PROFILE/colima.yaml"
elif [[ -d "$HOME/.colima" ]]; then
    COLIMA_CONFIG="$HOME/.colima/$COLIMA_PROFILE/colima.yaml"
else
    COLIMA_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/colima/$COLIMA_PROFILE/colima.yaml"
fi
[[ -f "$COLIMA_CONFIG" ]] || error "Cannot find the membrane profile config at $COLIMA_CONFIG."

# Colima regenerates daemon.json at boot. Merge only this runtime's path,
# preserving other runtimes, daemon settings, and profile settings.
YQ="$(brew --prefix yq)/bin/yq"
restart_required=0
runtime_path=$("$YQ" -r '.docker.runtimes."sysbox-runc".path // ""' "$COLIMA_CONFIG")
if [[ "$runtime_path" != /usr/bin/sysbox-runc ]]; then
    info "Registering persistent sysbox-runc runtime in $COLIMA_CONFIG..."
    "$YQ" -i '.docker.runtimes."sysbox-runc".path = "/usr/bin/sysbox-runc"' "$COLIMA_CONFIG"
    restart_required=1
fi

# Copy both setup files so Linux uses the same kernel checks on both platforms.
copy_vm_setup() {
    VM_SETUP=$(colima ssh --profile "$COLIMA_PROFILE" -- mktemp -d /tmp/membrane-setup.XXXXXX)
    [[ "$VM_SETUP" =~ ^/tmp/membrane-setup\.[[:alnum:]]+$ ]] || error "Invalid VM setup directory."
    colima ssh --profile "$COLIMA_PROFILE" -- tee "$VM_SETUP/install-linux.sh" <"$LINUX_SCRIPT" >/dev/null
    colima ssh --profile "$COLIMA_PROFILE" -- tee "$VM_SETUP/setup-bpf-lsm.py" <"$BPF_SCRIPT" >/dev/null
}
cleanup_vm_setup() {
    colima ssh --profile "$COLIMA_PROFILE" -- rm -rf -- "$VM_SETUP" >/dev/null 2>&1 || true
}
copy_vm_setup
trap cleanup_vm_setup EXIT

info "Configuring the dedicated membrane VM..."
# Colima may turn a remote exit 75 into exit 1. Capture the status inside this
# invocation's private directory; never infer reboot readiness from a stale
# host-wide marker left by an earlier failed setup.
colima ssh --profile "$COLIMA_PROFILE" -- sh -s -- "$VM_SETUP" <<'EOF'
set -eu
status=0
MEMBRANE_COLIMA=1 MEMBRANE_CONFIGURE_BPF_LSM=1 bash "$1/install-linux.sh" || status=$?
printf '%s\n' "$status" > "$1/status"
EOF
setup_status=$(colima ssh --profile "$COLIMA_PROFILE" -- cat "$VM_SETUP/status")
case "$setup_status" in
0) ;;
75) restart_required=1 ;;
*) error "Linux setup failed (exit $setup_status); the VM was not restarted." ;;
esac

if [[ "$restart_required" == 1 ]]; then
    info "Restarting only the membrane VM to apply its boot/runtime configuration..."
    cleanup_vm_setup
    colima stop --profile "$COLIMA_PROFILE"
    colima start --profile "$COLIMA_PROFILE" --activate=false
    colima ssh --profile "$COLIMA_PROFILE" -- sudo cat /sys/kernel/security/lsm |
        tr ',' '\n' | grep -qx bpf || error "BPF LSM is still inactive after restart; check the VM boot arguments."
    # /tmp may be cleared by boot. Recopy before continuing Linux setup.
    copy_vm_setup
    colima ssh --profile "$COLIMA_PROFILE" -- env MEMBRANE_COLIMA=1 bash "$VM_SETUP/install-linux.sh"
fi

info "Verifying Docker-host prerequisites..."
colima ssh --profile "$COLIMA_PROFILE" -- sudo cat /sys/kernel/security/lsm |
    tr ',' '\n' | grep -qx bpf || error "BPF LSM is not active."
for unit in sysbox.service sysbox-mgr.service sysbox-fs.service; do
    colima ssh --profile "$COLIMA_PROFILE" -- systemctl is-active --quiet "$unit" || error "Registered Sysbox runtime has an inactive backing service: $unit."
    [[ "$(colima ssh --profile "$COLIMA_PROFILE" -- systemctl is-enabled "$unit")" == enabled ]] || error "$unit is not enabled across VM restarts."
done
DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker info --format '{{json .Runtimes}}'
info "Verifying Sysbox container startup from the host..."
if DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker run --rm --runtime=sysbox-runc alpine:3.21 echo "sysbox ok"; then
    info "Sysbox verified — ready to use."
else
    error "Sysbox container startup failed; inspect sysbox-mgr.service and sysbox-fs.service logs and sockets inside the membrane VM."
fi

echo ""
info "Done. Run 'membrane' from any workspace to start."
