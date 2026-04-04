#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# E2E Shell Tests — cookie-rebound
#
# Validates the repository structure, source file presence, SPDX headers,
# and FFI/ABI wiring for the cookie-rebound Idris2+Zig library.
#
# Usage: bash tests/e2e_test.sh [repo-root]
#   Defaults to the parent of this script's directory.
#
# Exit code: 0 if all assertions pass, 1 if any fail.

set -euo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-$(dirname "$SCRIPT_DIR")}"

PASS=0
FAIL=0

# Assertion helper: prints PASS/FAIL line, increments counters.
assert() {
    local description="$1"
    local condition_result="$2"  # 0 = pass, nonzero = fail
    if [[ "$condition_result" -eq 0 ]]; then
        echo "  PASS: $description"
        (( PASS++ )) || true
    else
        echo "  FAIL: $description"
        (( FAIL++ )) || true
    fi
}

echo "=== cookie-rebound E2E Tests ==="
echo "Repo root: $REPO_ROOT"
echo ""

# ---------------------------------------------------------------------------
# 1. ABI files exist and are non-empty
# ---------------------------------------------------------------------------

echo "--- ABI File Existence ---"

ABI_DIR="$REPO_ROOT/src/interface/abi"

[[ -f "$ABI_DIR/Types.idr" ]] ; assert "Types.idr exists" $?
[[ -s "$ABI_DIR/Types.idr" ]] ; assert "Types.idr is non-empty" $?

[[ -f "$ABI_DIR/Layout.idr" ]] ; assert "Layout.idr exists" $?
[[ -s "$ABI_DIR/Layout.idr" ]] ; assert "Layout.idr is non-empty" $?

[[ -f "$ABI_DIR/Foreign.idr" ]] ; assert "Foreign.idr exists" $?
[[ -s "$ABI_DIR/Foreign.idr" ]] ; assert "Foreign.idr is non-empty" $?

# ---------------------------------------------------------------------------
# 2. Zig FFI files exist and have expected structure
# ---------------------------------------------------------------------------

echo ""
echo "--- Zig FFI File Structure ---"

FFI_DIR="$REPO_ROOT/src/interface/ffi"

[[ -f "$FFI_DIR/build.zig" ]] ; assert "ffi/build.zig exists" $?
[[ -f "$FFI_DIR/src/main.zig" ]] ; assert "ffi/src/main.zig exists" $?
[[ -f "$FFI_DIR/test/integration_test.zig" ]] ; assert "ffi/test/integration_test.zig exists" $?

# ---------------------------------------------------------------------------
# 3. Zig FFI test file references correct function signatures
# ---------------------------------------------------------------------------

echo ""
echo "--- FFI Function Signature Checks ---"

INTEGRATION_TEST="$FFI_DIR/test/integration_test.zig"

grep -q "cookie_rebound_init" "$INTEGRATION_TEST" ; assert "integration_test references cookie_rebound_init" $?
grep -q "cookie_rebound_store" "$INTEGRATION_TEST" ; assert "integration_test references cookie_rebound_store" $?
grep -q "cookie_rebound_get" "$INTEGRATION_TEST" ; assert "integration_test references cookie_rebound_get" $?
grep -q "cookie_rebound_free" "$INTEGRATION_TEST" ; assert "integration_test references cookie_rebound_free" $?

# main.zig must export the same function names
grep -q "cookie_rebound_init" "$FFI_DIR/src/main.zig" ; assert "main.zig exports cookie_rebound_init" $?
grep -q "cookie_rebound_store" "$FFI_DIR/src/main.zig" ; assert "main.zig exports cookie_rebound_store" $?

# ---------------------------------------------------------------------------
# 4. SPDX headers present in all source files
# ---------------------------------------------------------------------------

echo ""
echo "--- SPDX Header Checks ---"

check_spdx() {
    local file="$1"
    local label="$2"
    if grep -q "SPDX-License-Identifier" "$file" 2>/dev/null; then
        assert "SPDX header in $label" 0
    else
        assert "SPDX header in $label" 1
    fi
}

check_spdx "$ABI_DIR/Types.idr"                          "Types.idr"
check_spdx "$ABI_DIR/Layout.idr"                         "Layout.idr"
check_spdx "$ABI_DIR/Foreign.idr"                        "Foreign.idr"
check_spdx "$FFI_DIR/build.zig"                          "ffi/build.zig"
check_spdx "$FFI_DIR/src/main.zig"                       "ffi/src/main.zig"
check_spdx "$FFI_DIR/test/integration_test.zig"          "integration_test.zig"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ "$FAIL" -gt 0 ]]; then
    echo "OUTCOME: FAIL"
    exit 1
else
    echo "OUTCOME: PASS"
    exit 0
fi
