#!/bin/bash
set -e

bnd=$(grep '^CapBnd:' /proc/self/status | awk '{print $2}')
if (( 16#$bnd & (1 << 12) )); then

    # -------------------------------------------------------------------------
    # Pre-drop phase — CAP_NET_ADMIN is present
    # -------------------------------------------------------------------------

    # Fix DNS
    echo "nameserver $MEMBRANE_RESOLVER" >/etc/resolv.conf

    # Fix MTU
    ip link set dev eth0 mtu 1200 2>/dev/null || true

    # Disable IPv6
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

    # Start DNS logging
    DNS_LOG="/var/log/dns-queries.log"
    touch "$DNS_LOG" && chmod 644 "$DNS_LOG"
    tcpdump -i any -ln port 53 2>/dev/null >> "$DNS_LOG" &

    # Run firewall setup (also starts updater loop in background)
    /usr/local/bin/firewall.sh /usr/local/etc/hostnames.txt

    # Drop CAP_NET_ADMIN and CAP_NET_RAW, then re-exec — will enter post-drop phase
    exec capsh --drop=cap_net_admin,cap_net_raw,cap_setpcap,cap_setfcap -- -c 'exec /usr/local/bin/entrypoint.sh "$@"' -- "$@"

fi

# -------------------------------------------------------------------------
# Post-drop phase — CAP_NET_ADMIN is absent
# -------------------------------------------------------------------------

# Start Docker daemon if running in Sysbox
if [ "$MEMBRANE_DIND" = "1" ] && command -v dockerd >/dev/null 2>&1; then
    dockerd --add-runtime=crun=/usr/bin/crun --default-runtime=crun >/var/log/dockerd.log 2>&1 &

    for i in $(seq 1 30); do
        if [ -S /var/run/docker.sock ]; then
            break
        fi
        sleep 1
    done

    if [ ! -S /var/run/docker.sock ]; then
        echo "Warning: Docker daemon failed to start" >&2
    fi
fi

# Update agent user to match workspace ownership
WORKSPACE_UID=$(stat -c '%u' /workspace)
WORKSPACE_GID=$(stat -c '%g' /workspace)
usermod -u "$WORKSPACE_UID" agent >/dev/null 2>&1 || true
groupmod -g "$WORKSPACE_GID" agent >/dev/null 2>&1 || true

if [ -n "$MEMBRANE_TITLE" ]; then
    echo -ne "\e]2;${MEMBRANE_TITLE}\007" > /dev/tty 2>/dev/null || true
fi

cd /workspace
exec gosu agent "${@:-bash}"
