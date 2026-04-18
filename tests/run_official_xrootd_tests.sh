#!/usr/bin/env bash
#
# Run the official XRootD integration tests (from /tmp/xrootd-src/tests/XRootD/)
# against our nginx+xrootd-module proxy instead of a native xrootd server.
#
# The official tests are designed as:
#   test.sh <config> setup   — start an xrootd server
#   test.sh <config> run     — exercise it via xrdfs/xrdcp
#   test.sh <config> teardown — kill the server
#
# We skip setup/teardown (nginx is already running) and just source the
# test functions, point HOST at our nginx listener, and call test_<name>().
#
# Usage:
#   ./tests/run_official_xrootd_tests.sh [noauth|host|all]
#
# Prerequisites:
#   - nginx+xrootd-module running (ports 11094 anon, 11095 GSI)
#   - XRootD client tools on PATH (xrdfs, xrdcp, xrdcrc32c, xrdadler32)
#   - Official XRootD source at /tmp/xrootd-src
#
set -uo pipefail
# Note: we intentionally do NOT use set -e because individual sub-tests
# are expected to fail; pass/fail is tracked per sub-test.

XROOTD_SRC="${XROOTD_SRC:-/tmp/xrootd-src}"
TEST_DIR="${XROOTD_SRC}/tests/XRootD"
NGINX_ANON_PORT="${NGINX_ANON_PORT:-11094}"
NGINX_GSI_PORT="${NGINX_GSI_PORT:-11095}"
# Local scratch for reference files
LOCALDIR="${LOCALDIR:-/tmp/xrd-official-tests}"
# The xrootd_root configured in nginx — remote paths are relative to this
XROOTD_ROOT="${XROOTD_ROOT:-/tmp/xrd-test/data}"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

pass=0; fail=0; skip=0
declare -a failures=()

# ── helpers (same as the official test.sh) ──────────────────────────────
function error()          { echo -e "${RED}ERROR: $*${NC}" >&2; }
function assert()         { echo "+ $*"; "$@" || { error "command failed: $*"; return 1; }; }
function assert_eq()      { [[ "$1" == "$2" ]] || { error "$3: expected '$1' got '$2'"; return 1; }; }
function assert_ne()      { [[ "$1" != "$2" ]] || { error "$3: expected != '$1'"; return 1; }; }
function assert_failure()  { echo "+ (expect fail) $*"; "$@" && { error "command should have failed: $*"; return 1; } || true; }
function require_commands() { for p in "$@"; do command -v "$p" &>/dev/null || { error "missing: $p"; return 1; }; done; }

# ── run a single sub-test, capturing pass/fail ─────────────────────────
run_subtest() {
    local label="$1"; shift
    echo -e "\n${YELLOW}── ${label} ──${NC}"
    if "$@" 2>&1; then
        echo -e "${GREEN}  PASS: ${label}${NC}"
        ((pass++))
    else
        echo -e "${RED}  FAIL: ${label}${NC}"
        ((fail++))
        failures+=("$label")
    fi
}

# ── noauth: file upload/download + checksum ─────────────────────────────
# Adapted from tests/XRootD/noauth.sh — the biggest single integration test.
test_noauth_adapted() {
    local HOST="root://localhost:${NGINX_ANON_PORT}/"
    local tag="noauth-$$-${RANDOM}"
    local LOCAL="${LOCALDIR}/${tag}"
    local REMOTE="/official-tests/${tag}"
    mkdir -p "${LOCAL}"

    # --- stat / ---
    run_subtest "noauth: stat /" \
        xrdfs "${HOST}" stat /

    # --- query config (best-effort — our module only implements a subset) ---
    for param in version sitename role; do
        run_subtest "noauth: query config ${param}" \
            xrdfs "${HOST}" query config "${param}" || true
    done

    # --- create remote directory ---
    run_subtest "noauth: mkdir -p" \
        xrdfs "${HOST}" mkdir -p "${REMOTE}"

    # --- file upload / download / verify ---
    local NFILES=5
    local files
    files=$(seq -w 1 "${NFILES}")

    echo "Creating ${NFILES} random test files …"
    for i in $files; do
        openssl rand -base64 -out "${LOCAL}/${i}.ref" $((1024 * (RANDOM + 1)))
    done

    for i in $files; do
        run_subtest "noauth: xrdcp upload ${i}" \
            xrdcp -np "${LOCAL}/${i}.ref" "${HOST}${REMOTE}/${i}.ref"
    done

    run_subtest "noauth: xrdfs ls -l" \
        xrdfs "${HOST}" ls -l "${REMOTE}/"

    for i in $files; do
        run_subtest "noauth: xrdcp download ${i}" \
            xrdcp -np "${HOST}${REMOTE}/${i}.ref" "${LOCAL}/${i}.dat"
    done

    # Checksum verification
    for i in $files; do
        local ref_a32 new_a32
        ref_a32=$(xrdadler32 < "${LOCAL}/${i}.ref" | cut -d' ' -f1)
        new_a32=$(xrdadler32 < "${LOCAL}/${i}.dat" | cut -d' ' -f1)
        run_subtest "noauth: adler32 verify ${i}" \
            test "${ref_a32}" = "${new_a32}"
    done

    # --- ls variants ---
    run_subtest "noauth: ls -R /" \
        xrdfs "${HOST}" ls -R /

    # --- stat individual files ---
    local file="${REMOTE}/1.ref"
    run_subtest "noauth: stat file" \
        xrdfs "${HOST}" stat "${file}"

    # --- truncate ---
    run_subtest "noauth: truncate" \
        xrdfs "${HOST}" truncate "${file}" 64

    # --- rm ---
    for i in $files; do
        run_subtest "noauth: rm ${i}" \
            xrdfs "${HOST}" rm "${REMOTE}/${i}.ref"
    done

    # --- rmdir ---
    run_subtest "noauth: rmdir" \
        xrdfs "${HOST}" rmdir "${REMOTE}"

    rm -rf "${LOCAL}"
}

# ── host: simple copy + diff ────────────────────────────────────────────
# Adapted from tests/XRootD/host.sh
test_host_adapted() {
    local HOST="root://localhost:${NGINX_ANON_PORT}/"
    local tag="host-$$-${RANDOM}"
    local LOCAL="${LOCALDIR}/${tag}"
    local REMOTE="/official-tests/${tag}"
    mkdir -p "${LOCAL}"

    # Upload a known file, download it, diff
    local srcfile="${TEST_DIR}/host.cfg"
    [[ -f "${srcfile}" ]] || { echo "SKIP: host.cfg not found"; ((skip++)); return 0; }

    run_subtest "host: mkdir -p" \
        xrdfs "${HOST}" mkdir -p "${REMOTE}"

    run_subtest "host: xrdcp upload" \
        xrdcp -f "${srcfile}" "${HOST}${REMOTE}/host.cfg"

    run_subtest "host: xrdcp download" \
        xrdcp -f "${HOST}${REMOTE}/host.cfg" "${LOCAL}/host.cfg"

    run_subtest "host: cat remote file" \
        xrdfs "${HOST}" cat "${REMOTE}/host.cfg"

    run_subtest "host: diff round-trip" \
        diff -u "${srcfile}" "${LOCAL}/host.cfg"

    run_subtest "host: rm" \
        xrdfs "${HOST}" rm "${REMOTE}/host.cfg"

    xrdfs "${HOST}" rmdir "${REMOTE}" 2>/dev/null || true
    rm -rf "${LOCAL}"
}

# ── Bulk file stress (inspired by noauth + stress test patterns) ────────
test_stress_adapted() {
    local HOST="root://localhost:${NGINX_ANON_PORT}/"
    local tag="stress-$$-${RANDOM}"
    local LOCAL="${LOCALDIR}/${tag}"
    local REMOTE="/official-tests/${tag}"
    local NFILES=20
    mkdir -p "${LOCAL}"

    # Create remote directory first
    xrdfs "${HOST}" mkdir -p "${REMOTE}"

    echo "Stress: uploading ${NFILES} files in parallel …"
    for i in $(seq -w 1 "${NFILES}"); do
        openssl rand -base64 -out "${LOCAL}/${i}.ref" $((4096 * (RANDOM + 1)))
    done

    # Parallel upload (backgrounded)
    for i in $(seq -w 1 "${NFILES}"); do
        xrdcp -np "${LOCAL}/${i}.ref" "${HOST}${REMOTE}/${i}.ref" &
    done
    wait

    # Parallel download
    for i in $(seq -w 1 "${NFILES}"); do
        xrdcp -np "${HOST}${REMOTE}/${i}.ref" "${LOCAL}/${i}.dat" &
    done
    wait

    # Verify all
    local ok=0 bad=0
    for i in $(seq -w 1 "${NFILES}"); do
        local ref_a32 new_a32
        ref_a32=$(xrdadler32 < "${LOCAL}/${i}.ref" | cut -d' ' -f1)
        new_a32=$(xrdadler32 < "${LOCAL}/${i}.dat" | cut -d' ' -f1)
        if [[ "${ref_a32}" == "${new_a32}" ]]; then
            ((ok++))
        else
            ((bad++))
            echo "  MISMATCH: file ${i} ref=${ref_a32} got=${new_a32}"
        fi
    done

    run_subtest "stress: ${ok}/${NFILES} round-trip checksums match" \
        test "${bad}" -eq 0

    # Cleanup
    for i in $(seq -w 1 "${NFILES}"); do
        xrdfs "${HOST}" rm "${REMOTE}/${i}.ref" 2>/dev/null &
    done
    wait
    xrdfs "${HOST}" rmdir "${REMOTE}" 2>/dev/null || true
    rm -rf "${LOCAL}"
}

# ── main ────────────────────────────────────────────────────────────────
mkdir -p "${LOCALDIR}"

export XRD_REQUESTTIMEOUT=15
export XRD_STREAMTIMEOUT=10
export XRD_TIMEOUTRESOLUTION=1
export XRD_LOGLEVEL=Warning
export SOURCE_DIR="${TEST_DIR}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Official XRootD tests → nginx+xrootd module"
echo "  XRootD source: ${XROOTD_SRC}"
echo "  nginx anon:    localhost:${NGINX_ANON_PORT}"
echo "  Client:        $(xrdcp --version 2>&1)"
echo "═══════════════════════════════════════════════════════════════"

SUITE="${1:-all}"

case "${SUITE}" in
    noauth)  test_noauth_adapted ;;
    host)    test_host_adapted ;;
    stress)  test_stress_adapted ;;
    all)
        test_noauth_adapted
        test_host_adapted
        test_stress_adapted
        ;;
    *)
        echo "Usage: $0 [noauth|host|stress|all]"
        exit 1
        ;;
esac

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}, ${YELLOW}${skip} skipped${NC}"
if [[ ${#failures[@]} -gt 0 ]]; then
    echo -e "  ${RED}Failures:${NC}"
    for f in "${failures[@]}"; do
        echo "    - ${f}"
    done
fi
echo "═══════════════════════════════════════════════════════════════"

exit "${fail}"
