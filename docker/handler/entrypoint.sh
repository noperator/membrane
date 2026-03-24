#!/usr/bin/env bash
set -euo pipefail

# Wait for both interfaces
for i in $(seq 1 15); do
    [ "$(ls /sys/class/net/ | grep -v lo | wc -l)" -ge 2 ] && break
    sleep 1
done
[ "$(ls /sys/class/net/ | grep -v lo | wc -l)" -ge 2 ] \
    || { echo "ERROR: timed out waiting for second network interface"; exit 1; }

# Identify internal vs external interface
DEFAULT_GW_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)
INTERNAL_IF=""
for iface in $(ls /sys/class/net/ | grep -v lo); do
    [ "$iface" != "$DEFAULT_GW_IF" ] && INTERNAL_IF="$iface"
done
[ -n "$INTERNAL_IF" ] || { echo "ERROR: could not identify internal interface"; exit 1; }
echo "Interfaces: external=$DEFAULT_GW_IF internal=$INTERNAL_IF"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Resolve allowed hostnames in parallel
HOSTNAMES_FILE="${MEMBRANE_HOSTNAMES_FILE:-/etc/membrane/hostnames.txt}"
DNS_RESOLVER="${MEMBRANE_DNS_RESOLVER:-1.1.1.1}"

IP_LIST=$(mktemp)

if [ -f "$HOSTNAMES_FILE" ]; then
    grep -vE '^#|^\s*$' "$HOSTNAMES_FILE" | xargs -P 20 -I {} sh -c \
        'dig +short "{}" A @'"$DNS_RESOLVER"' 2>/dev/null' \
        | grep -E '^[1-9][0-9]*\.[0-9]+\.[0-9]+\.[0-9]+$' \
        | sed 's/$/\/32/' >> "$IP_LIST"
fi

# Add user-specified CIDRs
if [ -n "${MEMBRANE_CIDRS:-}" ]; then
    echo "$MEMBRANE_CIDRS" | tr ',' '\n' | while read -r cidr; do
        [[ "$cidr" == */* ]] || cidr="${cidr}/32"
        echo "$cidr"
    done >> "$IP_LIST"
fi

ALL_IPS=$(sort -u "$IP_LIST" | tr '\n' ',' | sed 's/,$//')
rm -f "$IP_LIST"

[ -n "$ALL_IPS" ] || { echo "ERROR: no IPs resolved — check hostnames file"; exit 1; }

# Set up nftables
nft -f - <<EOF
table ip membrane
delete table ip membrane
table ip membrane {
    set allowed {
        type ipv4_addr
        flags interval
        elements = { $ALL_IPS }
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$DEFAULT_GW_IF" masquerade
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        tcp flags syn tcp option maxseg size set rt mtu
        iifname "$INTERNAL_IF" ip daddr "$DNS_RESOLVER" udp dport 53 accept
        iifname "$INTERNAL_IF" ip daddr @allowed accept
        iifname "$INTERNAL_IF" log prefix "[membrane BLOCKED] " limit rate 5/second
        iifname "$INTERNAL_IF" reject with icmp admin-prohibited
    }
}
EOF

echo "Firewall rules loaded ($(echo "$ALL_IPS" | tr ',' '\n' | wc -l) ranges)."

# Signal ready
touch /tmp/handler-ready
echo "Handler ready."

sleep infinity
