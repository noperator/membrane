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

# Extract CIDRs from allow file for initial nftables population.
# CIDRs without ports → @allowed-any-port (TCP only via forward rule).
# CIDRs with ports → @allowed (ip . proto . port).
# Hostnames are resolved dynamically by dns-proxy at query time.
read -r -d '' _EXTRACT_RULES <<'PYEOF' || true
import json, sys
with open(sys.argv[1]) as f:
    rules = json.load(f)
any_port = []
port_constrained = []
any_host = False
any_host_tcp_ports = []
any_host_udp_ports = []
for r in rules:
    if r.get('type') == 'cidr' and r.get('cidr'):
        ports = r.get('ports') or []
        if not ports:
            any_port.append(r['cidr'])
        else:
            for p in ports:
                port_constrained.append(f"{r['cidr']} . {p['proto']} . {p['port']}")
    elif r.get('type') == 'any':
        any_host = True
        ports = r.get('ports') or []
        if not ports:
            # No ports = any port; clear lists to signal "any"
            any_host_tcp_ports = None
            any_host_udp_ports = None
        elif any_host_tcp_ports is not None:
            for p in ports:
                if p['proto'] == 'tcp' and p['port'] not in any_host_tcp_ports:
                    any_host_tcp_ports.append(p['port'])
                elif p['proto'] == 'udp' and any_host_udp_ports is not None and p['port'] not in any_host_udp_ports:
                    any_host_udp_ports.append(p['port'])
print('ANY_PORT=' + ','.join(any_port))
print('PORT_CONSTRAINED=' + ','.join(port_constrained))
print('ANY_HOST=' + ('1' if any_host else ''))
print('ANY_HOST_TCP_PORTS=' + (','.join(str(p) for p in any_host_tcp_ports) if any_host_tcp_ports else ''))
print('ANY_HOST_UDP_PORTS=' + (','.join(str(p) for p in any_host_udp_ports) if any_host_udp_ports else ''))
PYEOF
_EXTRACT_OUTPUT=$(python3 -c "$_EXTRACT_RULES" "$ALLOW_FILE" 2>/dev/null)
ANY_PORT=$(echo "$_EXTRACT_OUTPUT" | grep '^ANY_PORT=' | cut -d= -f2-)
PORT_CONSTRAINED=$(echo "$_EXTRACT_OUTPUT" | grep '^PORT_CONSTRAINED=' | cut -d= -f2-)
ANY_HOST=$(echo "$_EXTRACT_OUTPUT" | grep '^ANY_HOST=' | cut -d= -f2-)
ANY_HOST_TCP_PORTS=$(echo "$_EXTRACT_OUTPUT" | grep '^ANY_HOST_TCP_PORTS=' | cut -d= -f2-)
ANY_HOST_UDP_PORTS=$(echo "$_EXTRACT_OUTPUT" | grep '^ANY_HOST_UDP_PORTS=' | cut -d= -f2-)

[ -n "$ANY_PORT" ] || ANY_PORT="127.0.0.2/32"

MITMPROXY_PORT=8080

SSL_INSECURE_FLAG=""
if [ "${MEMBRANE_SSL_INSECURE:-false}" = "true" ]; then
    SSL_INSECURE_FLAG="--ssl-insecure"
fi

# Build elements clauses (nftables requires non-empty elements list)
ANY_PORT_ELEMENTS="elements = { $ANY_PORT }"
if [ -n "$PORT_CONSTRAINED" ]; then
    ALLOWED_ELEMENTS="elements = { $PORT_CONSTRAINED }"
else
    ALLOWED_ELEMENTS=""
fi

# Set up nftables
nft -f - <<EOF
table ip membrane
delete table ip membrane
table ip membrane {
    set allowed {
        type ipv4_addr . inet_proto . inet_service
        flags interval
        $ALLOWED_ELEMENTS
    }

    set allowed-any-port {
        type ipv4_addr
        flags interval
        $ANY_PORT_ELEMENTS
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "$INTERNAL_IF" ip daddr @allowed-any-port meta l4proto tcp redirect to :$MITMPROXY_PORT
        iifname "$INTERNAL_IF" ip daddr . meta l4proto . th dport @allowed meta l4proto tcp redirect to :$MITMPROXY_PORT
        iifname "$INTERNAL_IF" ip daddr . meta l4proto . th dport @allowed meta l4proto udp accept
        $(if [ "$ANY_HOST" = "1" ]; then
    if [ -z "$ANY_HOST_TCP_PORTS" ]; then
        echo "iifname \"$INTERNAL_IF\" meta l4proto tcp redirect to :$MITMPROXY_PORT"
    else
        IFS=',' read -ra _ports <<<"$ANY_HOST_TCP_PORTS"
        for _p in "${_ports[@]}"; do
            echo "iifname \"$INTERNAL_IF\" tcp dport $_p redirect to :$MITMPROXY_PORT"
        done
    fi
fi)
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
        iifname "$INTERNAL_IF" ip daddr @allowed-any-port meta l4proto tcp accept
        iifname "$INTERNAL_IF" ip daddr . meta l4proto . th dport @allowed accept
        $(if [ "$ANY_HOST" = "1" ]; then
    if [ -z "$ANY_HOST_TCP_PORTS" ]; then
        echo "iifname \"$INTERNAL_IF\" meta l4proto tcp accept"
    else
        IFS=',' read -ra _ports <<<"$ANY_HOST_TCP_PORTS"
        for _p in "${_ports[@]}"; do
            echo "iifname \"$INTERNAL_IF\" tcp dport $_p accept"
        done
    fi
    if [ -n "$ANY_HOST_UDP_PORTS" ]; then
        IFS=',' read -ra _uports <<<"$ANY_HOST_UDP_PORTS"
        for _u in "${_uports[@]}"; do
            echo "iifname \"$INTERNAL_IF\" udp dport $_u accept"
        done
    fi
fi)
        iifname "$INTERNAL_IF" log prefix "[membrane BLOCKED] " limit rate 5/second
        iifname "$INTERNAL_IF" reject with icmp admin-prohibited
    }
}
EOF

echo "Firewall rules loaded."

# Block all IPv6 forwarding as a safety net — all nftables rules are
# IPv4 only so any IPv6 traffic would otherwise be unfiltered.
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

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
PYTHONUNBUFFERED=1 mitmdump \
    --mode transparent \
    --listen-port "$MITMPROXY_PORT" \
    --set confdir=/tmp/mitmproxy \
    $SSL_INSECURE_FLAG \
    --set rawtcp=true \
    -s /addon.py \
    &

# Wait for mitmproxy to bind its port AND finish loading the addon
# (timeout 15s). The port-bind alone is insufficient — mitmproxy
# accepts connections at the kernel level before the addon's
# _load_rules() and module initialization complete.
for i in $(seq 1 15); do
    if (echo >/dev/tcp/localhost/$MITMPROXY_PORT) 2>/dev/null &&
        [ -f /tmp/mitmproxy-addon-loaded ]; then
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo "ERROR: mitmproxy did not become ready within 15s"
        exit 1
    fi
    sleep 1
done
echo "mitmproxy ready."

# Signal ready
touch /tmp/handler-ready
echo "Handler ready."

sleep infinity
