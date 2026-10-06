#!/usr/bin/env bash
# Sourced by entrypoint.sh. Children stay in the foreground and are direct
# children of the handler, so wait observes their actual process lifetime.
CRITICAL_PIDS=()
declare -A CRITICAL_NAMES=()

supervise() {
    CRITICAL_PIDS+=("$2")
    CRITICAL_NAMES[$2]="$1"
}

check_children() {
    local pid
    for pid in "${CRITICAL_PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: ${CRITICAL_NAMES[$pid]} exited before handler readiness" >&2
            return 1
        fi
    done
}

drain_workload() {
    local cgroup=${MEMBRANE_TARGET_CGROUP:?workload cgroup is required}
    echo 1 > "$cgroup/cgroup.kill" || return 1
    local deadline=$((SECONDS + 30))
    while ! grep -qx 'populated 0' "$cgroup/cgroup.events"; do
        [ -r "$cgroup/cgroup.events" ] && [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.05
    done
    echo "Workload cgroup drained (populated 0)."
}

shutdown_handler() {
    local status=$? pid
    trap - EXIT
    trap '' TERM INT HUP
    rm -f /tmp/handler-ready
    # Also drain on an intentional signal. The host normally drained already,
    # but direct handler termination must not release live workload enforcement.
    if ! drain_workload; then
        echo "ERROR: cannot kill and drain workload cgroup; host cleanup required" >&2
        status=1
    fi
    for pid in "${CRITICAL_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${CRITICAL_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    exit "$status"
}

wait_for_critical_exit() {
    local exited="" status=0
    check_children || return 1
    wait -n -p exited "${CRITICAL_PIDS[@]}" || status=$?
    echo "ERROR: ${CRITICAL_NAMES[${exited:-0}]:-critical child} exited unexpectedly (status $status)" >&2
    return 1
}

trap shutdown_handler EXIT
trap 'exit 0' TERM INT HUP
