#!/usr/bin/env bash
# run_load_test.sh — start servers, run load tests, stop servers
#
# Usage:
#   ./tests/run_load_test.sh [nginx|xrootd|both] [--file load_1g.bin] [--concurrency 1,8,32,64,128,200]
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 128 --suite root-gsi
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 500 --suite root-gsi --read-sink devnull
#
# Requires:
#   • nginx built with nginx-xrootd module (./nginx -v should show the module)
#   • xrootd 5.x installed (/usr/bin/xrootd)
#   • Test PKI already generated under /tmp/xrd-test/pki/
#   • Python 3 with XRootD python bindings (from xrootd package)
#
# The script:
#   1. Creates /tmp/xrd-perf-test/  (nginx work dir)
#      Creates /tmp/xrd-perf-xrd/   (xrootd work dir)
#   2. Starts the selected server(s)
#   3. Waits for them to be ready
#   4. Runs load_test.py
#   5. Stops the servers
#   6. Prints a summary and optionally saves JSON

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

TARGET="${1:-nginx}"
shift || true

# Optional args forwarded to load_test.py
EXTRA_ARGS=("$@")

NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
XROOTD_BIN="${XROOTD_BIN:-/usr/bin/xrootd}"
AUTHDB_FILE="/tmp/xrd-perf-xrd/authdb"

NGINX_PERF_DIR="/tmp/xrd-perf-test"
XRD_PERF_DIR="/tmp/xrd-perf-xrd"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo "  [run_load_test] $*" >&2; }

wait_port() {
    local host="${1}" port="${2}" label="${3}" retries=30
    while ! nc -z "$host" "$port" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            log "ERROR: $label did not come up on $host:$port"
            return 1
        fi
        sleep 0.5
    done
    log "$label ready on port $port"
}

# ---------------------------------------------------------------------------
# nginx-xrootd
# ---------------------------------------------------------------------------

start_nginx() {
    log "Starting nginx-xrootd (perf config)..."
    mkdir -p "$NGINX_PERF_DIR"/{logs,tmp}

    # Substitute the template vars into the perf config
    "$NGINX_BIN" -c "$SCRIPT_DIR/nginx.perf.conf" \
                 -p "$NGINX_PERF_DIR" \
                 -t 2>&1 | grep -v "^$" >&2 || {
        log "nginx config test failed — is the module built?"
        return 1
    }

    "$NGINX_BIN" -c "$SCRIPT_DIR/nginx.perf.conf" \
                 -p "$NGINX_PERF_DIR"

    wait_port localhost 11095 "nginx XRootD+GSI"
    wait_port localhost 11096 "nginx XRootD+TLS"
    wait_port localhost 8443  "nginx WebDAV+GSI"
    log "nginx-xrootd started (pid: $(cat $NGINX_PERF_DIR/logs/nginx.pid))"
}

stop_nginx() {
    local pidfile="$NGINX_PERF_DIR/logs/nginx.pid"
    if [[ -f "$pidfile" ]]; then
        log "Stopping nginx..."
        "$NGINX_BIN" -c "$SCRIPT_DIR/nginx.perf.conf" \
                     -p "$NGINX_PERF_DIR" -s quit
        sleep 2
    fi
}

# ---------------------------------------------------------------------------
# Official xrootd
# ---------------------------------------------------------------------------

start_xrootd() {
    log "Starting official xrootd (perf config)..."
    mkdir -p "$XRD_PERF_DIR"/{logs,data,admin,run}

    # Symlink the test data into the xrootd data dir
    [[ -d "$XRD_PERF_DIR/data/xrd-test" ]] || \
        ln -sf /tmp/xrd-test/data "$XRD_PERF_DIR/data/xrd-test"

    # Minimal authdb: allow authenticated users r/w on /
    cat > "$AUTHDB_FILE" <<'AUTHDB'
all.allow host any
u * / rl
AUTHDB

    "$XROOTD_BIN" -c "$SCRIPT_DIR/xrootd.perf.conf" \
                  -l "$XRD_PERF_DIR/logs/xrootd.log" \
                  -n perf -b

    wait_port localhost 12094 "xrootd GSI"
    wait_port localhost 12443 "xrootd HTTPS/WebDAV"
    log "xrootd started"
}

stop_xrootd() {
    local pidfile
    pidfile="$(find "$XRD_PERF_DIR/logs" -name "*.pid" 2>/dev/null | head -1)"
    if [[ -n "$pidfile" && -f "$pidfile" ]]; then
        pid="$(cat "$pidfile")"
        log "Stopping xrootd (pid $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
    else
        pkill -f "xrootd.*perf" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------

cleanup() {
    [[ "$TARGET" == nginx || "$TARGET" == both ]] && stop_nginx  || true
    [[ "$TARGET" == xrootd || "$TARGET" == both ]] && stop_xrootd || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log "Target: $TARGET"
log "Extra args: ${EXTRA_ARGS[*]:-none}"

[[ "$TARGET" == nginx || "$TARGET" == both ]]   && start_nginx
[[ "$TARGET" == xrootd || "$TARGET" == both ]]  && start_xrootd

log "Running load_test.py ..."
python3 "$SCRIPT_DIR/load_test.py" \
    --target "$TARGET" \
    --json "/tmp/load_test_results.json" \
    "${EXTRA_ARGS[@]}"

log "Load test complete. Results at /tmp/load_test_results.json"
