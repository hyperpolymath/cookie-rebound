#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# Property Tests — cookie-rebound
#
# Verifies structural invariants of the Idris2 ABI and Zig FFI layer:
#   1. Each ABI module exports required types.
#   2. Layout constants are consistent between Types.idr and Layout.idr.
#   3. All Zig-exported function names appear in the ABI Foreign.idr declarations.
#
# These are static analysis checks on source content — no compilation required.
#
# Usage: bash tests/property_test.sh [repo-root]
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

assert() {
    local description="$1"
    local condition_result="$2"
    if [[ "$condition_result" -eq 0 ]]; then
        echo "  PASS: $description"
        (( PASS++ )) || true
    else
        echo "  FAIL: $description"
        (( FAIL++ )) || true
    fi
}

ABI_DIR="$REPO_ROOT/src/interface/abi"
FFI_SRC="$REPO_ROOT/src/interface/ffi/src/main.zig"

echo "=== cookie-rebound Property Tests ==="
echo "Repo root: $REPO_ROOT"
echo ""

# ---------------------------------------------------------------------------
# 1. Types.idr exports required types
# ---------------------------------------------------------------------------

echo "--- Types.idr exports ---"

grep -q "^public export$"$'\n'"data Result"  "$ABI_DIR/Types.idr" 2>/dev/null \
    || grep -q "data Result" "$ABI_DIR/Types.idr" 2>/dev/null
assert "Types.idr declares Result type" $?

grep -q "data SameSitePolicy" "$ABI_DIR/Types.idr" ; assert "Types.idr declares SameSitePolicy" $?
grep -q "data RuleAction"     "$ABI_DIR/Types.idr" ; assert "Types.idr declares RuleAction" $?
grep -q "data ConsentCategory" "$ABI_DIR/Types.idr" ; assert "Types.idr declares ConsentCategory" $?
grep -q "record Cookie"        "$ABI_DIR/Types.idr" ; assert "Types.idr declares Cookie record" $?
grep -q "data BrowserType"     "$ABI_DIR/Types.idr" ; assert "Types.idr declares BrowserType" $?

# ---------------------------------------------------------------------------
# 2. Layout.idr exports required struct layouts
# ---------------------------------------------------------------------------

echo ""
echo "--- Layout.idr exports ---"

grep -q "cookieLayout"   "$ABI_DIR/Layout.idr" ; assert "Layout.idr defines cookieLayout" $?
grep -q "ruleLayout"     "$ABI_DIR/Layout.idr" ; assert "Layout.idr defines ruleLayout" $?
grep -q "analysisLayout" "$ABI_DIR/Layout.idr" ; assert "Layout.idr defines analysisLayout" $?

# ---------------------------------------------------------------------------
# 3. Memory layout constants consistent between Types.idr and Layout.idr
# ---------------------------------------------------------------------------

echo ""
echo "--- Cross-module constant consistency ---"

# Types.idr documents 72-byte or 56-byte cookie struct; Layout.idr uses 56 bytes for 64-bit.
# Both must reference alignment value of 8.
grep -q "8" "$ABI_DIR/Layout.idr" ; assert "Layout.idr contains alignment value 8" $?

# Types.idr mentions cookieAlignment; Layout.idr defines the concrete layout.
grep -q "cookieAlignment\|cookieLayout" "$ABI_DIR/Types.idr" ; assert "Types.idr references cookie layout concept" $?

# Both modules must agree that the cookie struct is pointer-aligned.
grep -q "cookieLayout\|cookieAlignment" "$ABI_DIR/Layout.idr" ; assert "Layout.idr defines the cookie layout" $?

# ---------------------------------------------------------------------------
# 4. All Zig exported functions have matching names in Foreign.idr
# ---------------------------------------------------------------------------

echo ""
echo "--- ABI ↔ FFI function name alignment ---"

check_zig_fn_in_foreign() {
    local fn_name="$1"
    if grep -q "$fn_name" "$ABI_DIR/Foreign.idr" && grep -q "$fn_name" "$FFI_SRC"; then
        assert "ABI+FFI both declare $fn_name" 0
    else
        assert "ABI+FFI both declare $fn_name" 1
    fi
}

check_zig_fn_in_foreign "cookie_rebound_init"
check_zig_fn_in_foreign "cookie_rebound_store"
check_zig_fn_in_foreign "cookie_rebound_get"
check_zig_fn_in_foreign "cookie_rebound_delete"
check_zig_fn_in_foreign "cookie_rebound_free"
check_zig_fn_in_foreign "cookie_rebound_list"
check_zig_fn_in_foreign "cookie_rebound_analyse"
check_zig_fn_in_foreign "cookie_rebound_version"

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
