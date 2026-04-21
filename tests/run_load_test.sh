#!/usr/bin/env bash
# run_load_test.sh — start servers, run load tests, stop servers
#
# Usage:
#   ./tests/run_load_test.sh [nginx|xrootd|both] [--file load_1g.bin] [--concurrency 1,8,32,64,128,200]
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 128 --suite root-gsi
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 200 --suite root-gsi --read-sink devnull
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
set -x
setup_pki() {
    log "Generating test PKI under /tmp/xrd-test/pki ..."
    local CADIR=/tmp/xrd-test/pki/ca
    local SERVERDIR=/tmp/xrd-test/pki/server
    local USERDIR=/tmp/xrd-test/pki/user
    # Wipe any existing test PKI to ensure a fresh, self-contained run.
    rm -rf /tmp/xrd-test/pki || true
    mkdir -p "$CADIR" "$SERVERDIR" "$USERDIR"

    # CA key/cert (fresh)
    openssl genrsa -out "$CADIR/ca.key" 2048
    chmod 400 "$CADIR/ca.key"
    openssl req -x509 -new -nodes -key "$CADIR/ca.key" -sha256 -days 3650 \
        -subj "/C=XX/O=Test/CN=Test CA" -out "$CADIR/ca.pem"

    # Always generate a signing-policy file for the CA
    local CA_SUBJ="/C=XX/O=Test/CN=Test CA"
    cat > "$CADIR/signing-policy" <<EOF
access_id_CA   X509   '$CA_SUBJ'
pos_rights     globus CA:sign
cond_subjects  globus  '*'
EOF
    chmod 644 "$CADIR/signing-policy"

    # Create both new and old-style OpenSSL subject hash symlinks
    local NEW_HASH
    local OLD_HASH
    NEW_HASH=$(openssl x509 -in "$CADIR/ca.pem" -noout -subject_hash)
    OLD_HASH=$(openssl x509 -in "$CADIR/ca.pem" -noout -subject_hash_old 2>/dev/null || true)
    ln -sf "$CADIR/ca.pem" "$CADIR/${NEW_HASH}.0"
    ln -sf "$CADIR/signing-policy" "$CADIR/${NEW_HASH}.signing_policy"
    if [[ -n "$OLD_HASH" ]]; then
        ln -sf "$CADIR/ca.pem" "$CADIR/${OLD_HASH}.0"
        ln -sf "$CADIR/signing-policy" "$CADIR/${OLD_HASH}.signing_policy"
    fi

    # Server key/cert (fresh)
    openssl genrsa -out "$SERVERDIR/host.key" 2048
    openssl req -new -key "$SERVERDIR/host.key" -subj "/C=XX/O=Test/CN=localhost" -out "$SERVERDIR/host.csr"
    openssl x509 -req -in "$SERVERDIR/host.csr" -CA "$CADIR/ca.pem" -CAkey "$CADIR/ca.key" -CAcreateserial \
        -out "$SERVERDIR/hostcert.pem" -days 3650 -sha256
    ln -sf "$SERVERDIR/host.key" "$SERVERDIR/hostkey.pem"

    # User key/cert (fresh)
    openssl genrsa -out "$USERDIR/user.key" 2048
    openssl req -new -key "$USERDIR/user.key" -subj "/C=XX/O=Test/CN=Test User" -out "$USERDIR/user.csr"
    openssl x509 -req -in "$USERDIR/user.csr" -CA "$CADIR/ca.pem" -CAkey "$CADIR/ca.key" -CAcreateserial \
        -out "$USERDIR/usercert.pem" -days 3650 -sha256

    # User proxy (RFC3820, proper chain, no passphrase)
    openssl genrsa -out "$USERDIR/proxy.key" 2048
    openssl req -new -key "$USERDIR/proxy.key" -subj "/C=XX/O=Test/CN=Test User/CN=proxy" -out "$USERDIR/proxy.csr"
    openssl x509 -req -in "$USERDIR/proxy.csr" -CA "$USERDIR/usercert.pem" -CAkey "$USERDIR/user.key" -CAcreateserial \
        -out "$USERDIR/proxy_cert.pem" -days 365 -sha256 -extfile <(printf "[proxy]\nbasicConstraints=CA:FALSE\nproxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:1\n") -extensions proxy

    # Concatenate proxy cert, proxy key, EEC cert, EEC key (no passphrase)
    cat "$USERDIR/proxy_cert.pem" "$USERDIR/proxy.key" "$USERDIR/usercert.pem" "$USERDIR/user.key" > "$USERDIR/proxy_std.pem"
    chmod 400 "$USERDIR/proxy_std.pem"

    # Generate a CRL that revokes the test user cert so CRL-based tests can run.
    if command -v python3 >/dev/null 2>&1 && [[ -f "$ROOT_DIR/utils/make_crl.py" ]]; then
        log "Generating CRL via utils/make_crl.py"
        python3 "$ROOT_DIR/utils/make_crl.py" "/tmp/xrd-test/pki" || log "make_crl.py failed"
    else
        log "utils/make_crl.py not found or python3 missing; skipping CRL generation"
    fi
}

setup_test_data() {
    # Create data and PKI directories
    mkdir -p /tmp/xrd-test/data
    mkdir -p /tmp/xrd-test/pki
    mkdir -p /tmp/xrd-test/pki/ca
    mkdir -p /tmp/xrd-test/pki/user
    mkdir -p /tmp/xrd-test/pki/server
    mkdir -p /tmp/xrd-test/tokens

    # Generate 1GB test file if missing
    if [[ ! -f /tmp/xrd-test/data/load_1g.bin ]]; then
        log "Generating 1GB test file at /tmp/xrd-test/data/load_1g.bin ..."
        dd if=/dev/urandom of=/tmp/xrd-test/data/load_1g.bin bs=1M count=1024 status=progress
    else
        log "1GB test file already exists."
    fi

    # Always regenerate PKI/CA/CRL to keep the test run self-contained
    log "Regenerating test PKI and CRL for a clean test run..."
    setup_pki
}

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
    # Pre-launch checks
    if [[ ! -x "$XROOTD_BIN" ]]; then
        log "ERROR: xrootd binary not found or not executable at $XROOTD_BIN"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_DIR/xrootd.perf.conf" ]]; then
        log "ERROR: xrootd config $SCRIPT_DIR/xrootd.perf.conf missing"
        exit 1
    fi
    mkdir -p "$XRD_PERF_DIR"/{logs,data,admin,run}
    if [[ ! -d /tmp/xrd-test/data ]]; then
        log "ERROR: Test data directory /tmp/xrd-test/data missing"
        exit 1
    fi
    if [[ ! -d /tmp/xrd-test/pki/ca ]]; then
        log "ERROR: CA directory /tmp/xrd-test/pki/ca missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-test/pki/ca/ca.pem ]]; then
        log "ERROR: CA certificate /tmp/xrd-test/pki/ca/ca.pem missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-test/pki/user/usercert.pem ]]; then
        log "ERROR: User certificate /tmp/xrd-test/pki/user/usercert.pem missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-test/pki/user/user.key ]]; then
        log "ERROR: User key /tmp/xrd-test/pki/user/user.key missing"
        exit 1
    fi
    # Symlink the test data into the xrootd data dir
    [[ -d "$XRD_PERF_DIR/data/xrd-test" ]] || \
        ln -sf /tmp/xrd-test/data "$XRD_PERF_DIR/data/xrd-test"

    # Minimal authdb: allow authenticated users r/w on /
    cat > "$AUTHDB_FILE" <<'AUTHDB'
all.allow host any
u * / rl
AUTHDB

    local xrd_cmd=("$XROOTD_BIN" -c "$SCRIPT_DIR/xrootd.perf.conf" -l "$XRD_PERF_DIR/logs/xrootd.log" -n perf -b)
    log "xrootd launch command: ${xrd_cmd[*]}"
    # Capture stdout/stderr for debug
    "${xrd_cmd[@]}" > "$XRD_PERF_DIR/logs/xrootd.debug.log" 2>&1 &
    sleep 1
    if ! ps aux | grep -v grep | grep -q "$XROOTD_BIN"; then
        log "ERROR: xrootd failed to start. See $XRD_PERF_DIR/logs/xrootd.debug.log for details."
        cat "$XRD_PERF_DIR/logs/xrootd.debug.log" >&2
        exit 1
    fi
    wait_port localhost 12094 "xrootd GSI"
    wait_port localhost 12443 "xrootd HTTPS/WebDAV"
    log "xrootd started"
    # Extra wait to ensure xrootd is fully ready
    sleep 2
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


# Setup test data and PKI
setup_test_data

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
