#!/usr/bin/env bash
#
# Helper launcher for the local nginx+xrootd test environment.
#
# Manages:
#   - nginx test instance (ports 11094/11095/11099/8443 from /tmp/xrd-test/conf/nginx.conf)
#   - reference xrootd instance used by conformance tests (port 11096)
#
# Usage:
#   tests/manage_test_servers.sh start
#   tests/manage_test_servers.sh stop
#   tests/manage_test_servers.sh force-stop
#   tests/manage_test_servers.sh restart
#   tests/manage_test_servers.sh status
#
# Optional subcommands:
#   tests/manage_test_servers.sh start nginx
#   tests/manage_test_servers.sh start ref
#
set -euo pipefail

NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
NGINX_PREFIX="${NGINX_PREFIX:-/tmp/xrd-test}"
NGINX_CONF_REL="${NGINX_CONF_REL:-conf/nginx.conf}"
NGINX_PORT="${NGINX_PORT:-11094}"

REF_BIN="${REF_BIN:-xrootd}"
REF_DIR="${REF_DIR:-/tmp/xrd-ref}"
REF_CFG="${REF_CFG:-${REF_DIR}/conformance.cfg}"
REF_LOG="${REF_LOG:-${REF_DIR}/conformance.log}"
REF_PID_FILE="${REF_PID_FILE:-${REF_DIR}/run-conf/xrootd.pid}"
REF_PORT="${REF_PORT:-11096}"
DATA_DIR="${DATA_DIR:-/tmp/xrd-test/data}"

usage() {
    cat <<'EOF'
Usage:
    tests/manage_test_servers.sh <start|stop|force-stop|restart|status> [all|nginx|ref]

Examples:
  tests/manage_test_servers.sh start
    tests/manage_test_servers.sh force-stop ref
  tests/manage_test_servers.sh restart nginx
  tests/manage_test_servers.sh status ref
EOF
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

pids_on_port() {
    local port="$1"

    if have_cmd ss; then
        ss -ltnp "( sport = :${port} )" 2>/dev/null \
            | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' \
            | sort -u
        return 0
    fi

    if have_cmd lsof; then
        lsof -t -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | sort -u
        return 0
    fi

    return 0
}

kill_pid_list() {
    local pids="$1"
    local pid

    if [[ -z "$pids" ]]; then
        return 0
    fi

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        kill "$pid" >/dev/null 2>&1 || true
    done <<<"$pids"

    sleep 0.3

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
    done <<<"$pids"
}

wait_ready_xrdfs() {
    local url="$1"
    local tries="${2:-30}"
    local sleep_s="${3:-0.5}"
    local i

    if ! have_cmd xrdfs; then
        return 0
    fi

    for ((i = 0; i < tries; i++)); do
        if have_cmd timeout; then
            if timeout 2s xrdfs "$url" ls / >/dev/null 2>&1; then
                return 0
            fi
        elif xrdfs "$url" ls / >/dev/null 2>&1; then
            return 0
        fi
        sleep "$sleep_s"
    done
    return 1
}

start_nginx() {
    if [[ ! -x "$NGINX_BIN" ]]; then
        echo "ERROR: nginx binary not found/executable: $NGINX_BIN" >&2
        return 1
    fi

    if [[ ! -f "${NGINX_PREFIX}/${NGINX_CONF_REL}" ]]; then
        echo "ERROR: nginx config not found: ${NGINX_PREFIX}/${NGINX_CONF_REL}" >&2
        return 1
    fi

    mkdir -p "${NGINX_PREFIX}/logs"

    if [[ -f "${NGINX_PREFIX}/logs/nginx.pid" ]]; then
        local pid
        pid="$(cat "${NGINX_PREFIX}/logs/nginx.pid" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "nginx already running (pid=$pid)"
            return 0
        fi
    fi

    "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL"

    if wait_ready_xrdfs "root://localhost:${NGINX_PORT}"; then
        echo "nginx started and ready on ${NGINX_PORT}"
    else
        echo "WARNING: nginx started but readiness probe failed on ${NGINX_PORT}" >&2
    fi
}

stop_nginx() {
    if [[ ! -x "$NGINX_BIN" ]]; then
        echo "nginx binary not found: $NGINX_BIN"
        return 0
    fi

    "$NGINX_BIN" -p "$NGINX_PREFIX" -c "$NGINX_CONF_REL" -s stop >/dev/null 2>&1 || true

    local pid_file="${NGINX_PREFIX}/logs/nginx.pid"
    if [[ -f "$pid_file" ]]; then
        sleep 0.2
    fi

    echo "nginx stopped"
}

force_stop_nginx() {
    stop_nginx

    local pid_file="${NGINX_PREFIX}/logs/nginx.pid"
    local pids=""
    if [[ -f "$pid_file" ]]; then
        pids="$(cat "$pid_file" 2>/dev/null || true)"
        kill_pid_list "$pids"
    fi

    # Extra safety net: kill listeners on known nginx test ports.
    pids="$(
        {
            pids_on_port 11094
            pids_on_port 11095
            pids_on_port 11099
            pids_on_port 8443
            pids_on_port 9100
        } | sort -u
    )"
    kill_pid_list "$pids"

    rm -f "$pid_file"
    echo "nginx force-stopped"
}

write_ref_cfg() {
    mkdir -p "${REF_DIR}/admin-conf" "${REF_DIR}/run-conf"

    cat >"$REF_CFG" <<EOF
xrd.port ${REF_PORT}
oss.localroot ${DATA_DIR}
all.export /
all.adminpath ${REF_DIR}/admin-conf
all.pidpath   ${REF_DIR}/run-conf
xrd.trace off
EOF
}

start_ref() {
    if ! have_cmd "$REF_BIN"; then
        echo "ERROR: xrootd binary not found on PATH" >&2
        return 1
    fi

    if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
        echo "reference xrootd already running on ${REF_PORT}"
        return 0
    fi

    write_ref_cfg
    rm -f "$REF_PID_FILE"

    "$REF_BIN" -c "$REF_CFG" -l "$REF_LOG" -b >/dev/null 2>&1

    for _ in {1..20}; do
        if [[ -f "$REF_PID_FILE" ]]; then
            break
        fi
        sleep 0.1
    done

    if wait_ready_xrdfs "root://localhost:${REF_PORT}"; then
        echo "reference xrootd started and ready on ${REF_PORT}"
    else
        echo "WARNING: reference xrootd started but readiness probe failed on ${REF_PORT}" >&2
    fi
}

stop_ref() {
    local pid=""
    if [[ -f "$REF_PID_FILE" ]]; then
        pid="$(cat "$REF_PID_FILE" 2>/dev/null || true)"
    fi

    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
        kill "$pid" >/dev/null 2>&1 || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" >/dev/null 2>&1; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
        fi
        rm -f "$REF_PID_FILE"
        echo "reference xrootd stopped"
        return 0
    fi

    if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
        echo "WARNING: reference xrootd appears to be running on ${REF_PORT} but is unmanaged by this script" >&2
        return 0
    fi

    rm -f "$REF_PID_FILE"
    echo "reference xrootd not running"
}

force_stop_ref() {
    stop_ref

    local pids=""

    # Kill any process listening on the reference xrootd test port.
    pids="$(pids_on_port "$REF_PORT")"
    kill_pid_list "$pids"

    # Also kill xrootd daemons started with this specific config path.
    if have_cmd pgrep; then
        pids="$(pgrep -f "xrootd.*${REF_CFG}" 2>/dev/null || true)"
        kill_pid_list "$pids"
    fi

    rm -f "$REF_PID_FILE"
    echo "reference xrootd force-stopped"
}

status_nginx() {
    local pid_file="${NGINX_PREFIX}/logs/nginx.pid"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "nginx: running (pid=$pid, port=${NGINX_PORT})"
            return 0
        fi
    fi
    echo "nginx: stopped"
}

status_ref() {
    if [[ -f "$REF_PID_FILE" ]]; then
        local pid
        pid="$(cat "$REF_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            echo "ref xrootd: running (pid=$pid, port=${REF_PORT})"
            return 0
        fi
    fi

    if wait_ready_xrdfs "root://localhost:${REF_PORT}" 1 0.1; then
        echo "ref xrootd: running (port=${REF_PORT}, unmanaged)"
        return 0
    fi

    echo "ref xrootd: stopped"
}

ACTION="${1:-}"
TARGET="${2:-all}"

if [[ -z "$ACTION" ]]; then
    usage
    exit 1
fi

case "$ACTION" in
    start)
        case "$TARGET" in
            all) start_nginx; start_ref ;;
            nginx) start_nginx ;;
            ref) start_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    stop)
        case "$TARGET" in
            all) stop_ref; stop_nginx ;;
            nginx) stop_nginx ;;
            ref) stop_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    force-stop)
        case "$TARGET" in
            all) force_stop_ref; force_stop_nginx ;;
            nginx) force_stop_nginx ;;
            ref) force_stop_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    restart)
        case "$TARGET" in
            all) stop_ref; stop_nginx; start_nginx; start_ref ;;
            nginx) stop_nginx; start_nginx ;;
            ref) stop_ref; start_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    status)
        case "$TARGET" in
            all) status_nginx; status_ref ;;
            nginx) status_nginx ;;
            ref) status_ref ;;
            *) usage; exit 1 ;;
        esac
        ;;
    *)
        usage
        exit 1
        ;;
esac
