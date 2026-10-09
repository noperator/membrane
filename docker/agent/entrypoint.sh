#!/bin/bash
set -e

# Set default route through handler gateway
ip route replace default via "$MEMBRANE_GATEWAY" 2>/dev/null || true

# Point DNS at handler gateway (dns-proxy runs there)
echo "nameserver $MEMBRANE_GATEWAY" >/etc/resolv.conf

# Fix MTU
ip link set dev eth0 mtu 1200 2>/dev/null || true

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# Install handler CA cert (must be present — handler signals ready only after writing it)
[ -f /membrane-ca/ca.crt ] || {
    echo "ERROR: CA cert not found"
    exit 1
}
cp /membrane-ca/ca.crt /usr/local/share/ca-certificates/membrane-ca.crt
update-ca-certificates >/dev/null 2>&1

# Start Docker daemon if running in Sysbox
if [ "$MEMBRANE_DIND" = "1" ] && command -v dockerd >/dev/null 2>&1; then
    dockerd --add-runtime=crun=/usr/bin/crun --default-runtime=crun \
        >/var/log/dockerd.log 2>&1 &
    for _ in $(seq 1 30); do
        [ -S /var/run/docker.sock ] && break
        sleep 1
    done
    [ -S /var/run/docker.sock ] || echo "Warning: Docker daemon failed to start" >&2
fi

# Update agent user to match workspace ownership
WORKSPACE_UID=$(stat -c '%u' .)
WORKSPACE_GID=$(stat -c '%g' .)
usermod -u "$WORKSPACE_UID" agent >/dev/null 2>&1 || true
groupmod -g "$WORKSPACE_GID" agent >/dev/null 2>&1 || true

if [ -n "$MEMBRANE_TITLE" ]; then
    { echo -ne "\e]2;${MEMBRANE_TITLE}\007" >/dev/tty; } 2>/dev/null || true
fi

# shellcheck disable=SC2016
exec capsh --drop=cap_net_admin,cap_net_raw,cap_setpcap,cap_setfcap \
    -- -c 'exec gosu agent "${@:-bash}"' -- "$@"
