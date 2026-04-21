#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TESTS=(
    tests/test_file_api.py
    tests/test_query.py
    tests/test_protocol_edge_cases.py
    tests/test_privilege_escalation.py
)

run_backend() {
    local backend="$1"
    shift

    echo
    echo "== Running cross-compatible tests against ${backend} =="
    TEST_CROSS_BACKEND="${backend}" pytest "${TESTS[@]}" "$@"
}

run_backend nginx "$@"
run_backend xrootd "$@"
