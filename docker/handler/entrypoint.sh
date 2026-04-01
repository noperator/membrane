#!/usr/bin/env bash
set -euo pipefail

# Count non-loopback interfaces using a glob (avoids ls|grep)
nonlo_count() {
    local n=0
    for _f in /sys/class/net/*; do
        [ "${_f##*/}" != "lo" ] && n=$((n + 1))
    done
    echo "$n"
}

# Wait for both interfaces
for i in $(seq 1 15); do
    [ "$(nonlo_count)" -ge 2 ] && break
    sleep 1
done
[ "$(nonlo_count)" -ge 2 ] ||
    {
        echo "ERROR: timed out waiting for second network interface"
        exit 1
    }

# Identify internal vs external interface
DEFAULT_GW_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)
INTERNAL_IF=""
for _f in /sys/class/net/*; do
    iface="${_f##*/}"
    [ "$iface" = "lo" ] && continue
    [ "$iface" != "$DEFAULT_GW_IF" ] && INTERNAL_IF="$iface"
done
[ -n "$INTERNAL_IF" ] || {
    echo "ERROR: could not identify internal interface"
    exit 1
}
echo "Interfaces: external=$DEFAULT_GW_IF internal=$INTERNAL_IF"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

DNS_RESOLVER="${MEMBRANE_DNS_RESOLVER:-1.1.1.1}"
ALLOW_FILE="${MEMBRANE_ALLOW_FILE:-/etc/membrane/allow.json}"

# Extract CIDRs from allow file for initial nftables population
# Hostnames are resolved dynamically by dns-proxy at query time
CIDRS=$(python3 -c "
import json, sys
with open('$ALLOW_FILE') as f:
    rules = json.load(f)
for r in rules:
    if r.get('type') == 'cidr' and r.get('cidr'):
        print(r['cidr'])
" 2>/dev/null)

ALL_IPS=$(echo "$CIDRS" | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//' || true)

[ -n "$ALL_IPS" ] || ALL_IPS="127.0.0.2/32"

MITMPROXY_PORT=8080

# Build elements clause conditionally (nftables requires non-empty elements list)
ANY_PORT_ELEMENTS="elements = { $ALL_IPS }"

# Set up nftables
nft -f - <<EOF
table ip membrane
delete table ip membrane
table ip membrane {
    set allowed {
        type ipv4_addr . inet_service
    }

    set allowed-any-port {
        type ipv4_addr
        flags interval
        $ANY_PORT_ELEMENTS
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "$INTERNAL_IF" ip daddr @allowed-any-port tcp dport { 80, 443 } redirect to :$MITMPROXY_PORT
        iifname "$INTERNAL_IF" ip daddr . tcp dport @allowed redirect to :$MITMPROXY_PORT
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$DEFAULT_GW_IF" masquerade
    }

    chain input {
        type filter hook input priority filter; policy accept;
        iifname "$INTERNAL_IF" udp dport 53 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        tcp flags syn tcp option maxseg size set rt mtu
        iifname "$INTERNAL_IF" ip daddr @allowed-any-port accept
        iifname "$INTERNAL_IF" ip daddr . tcp dport @allowed accept
        iifname "$INTERNAL_IF" log prefix "[membrane BLOCKED] " limit rate 5/second
        iifname "$INTERNAL_IF" reject with icmp admin-prohibited
    }
}
EOF

echo "Firewall rules loaded."

# Start DNS proxy (updates nftables sets on resolution)
MEMBRANE_DNS_RESOLVER="$DNS_RESOLVER" MEMBRANE_ALLOW_FILE="$ALLOW_FILE" dns-proxy &
DNS_PROXY_PID=$!
echo "DNS proxy started (PID $DNS_PROXY_PID)."

# Generate ephemeral CA keypair
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /tmp/ca.key -out /membrane-ca/ca.crt \
    -days 1 -nodes -subj "/CN=membrane-ca" 2>/dev/null

# Place CA into mitmproxy confdir
mkdir -p /tmp/mitmproxy
cat /tmp/ca.key /membrane-ca/ca.crt >/tmp/mitmproxy/mitmproxy-ca.pem
echo "CA cert generated."

# Start mitmproxy in transparent mode
mitmdump \
    --mode transparent \
    --listen-port "$MITMPROXY_PORT" \
    --set confdir=/tmp/mitmproxy \
    --ssl-insecure \
    -s /addon.py \
    &

# Wait for mitmproxy to bind its port (timeout 15s)
for i in $(seq 1 15); do
    (echo >/dev/tcp/localhost/$MITMPROXY_PORT) 2>/dev/null && break
    if [ "$i" -eq 15 ]; then
        echo "ERROR: mitmproxy did not bind within 15s"
        exit 1
    fi
    sleep 1
done
echo "mitmproxy ready."

# Signal ready
touch /tmp/handler-ready
echo "Handler ready."

sleep infinity
