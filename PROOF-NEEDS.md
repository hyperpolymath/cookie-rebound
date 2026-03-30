# Proof Requirements

## Current state
- `src/interface/abi/Types.idr` — Cookie/consent types
- `src/interface/abi/Layout.idr` — Memory layout
- `src/interface/abi/Foreign.idr` — FFI declarations
- `src/interface/ffi/src/main.zig` — Zig FFI implementation
- `src/interface/ffi/test/integration_test.zig` — Integration tests
- No dangerous patterns found
- Recently rebuilt with Idris2 ABI + Zig FFI + JSONL storage + 35 tests

## What needs proving
- **Consent state machine correctness**: Prove the consent lifecycle (unset -> accepted/rejected -> revoked) has no invalid transitions
- **Cookie isolation**: Prove that cookie operations for one domain cannot affect cookies of another domain
- **Storage integrity**: Prove JSONL storage is append-only and that reads reflect all prior writes (no lost consent records)
- **Expiry enforcement**: Prove that expired consent entries are never treated as valid
- **GDPR compliance invariant**: Prove that consent withdrawal effectively removes all processing permissions (no residual consent)

## Recommended prover
- **Idris2** — State machine correctness is a natural fit for dependent types; already used for ABI

## Priority
- **MEDIUM** — Cookie consent is a compliance concern (GDPR/ePrivacy). Incorrect consent state could have legal implications. The state machine is small enough that full verification is practical.
