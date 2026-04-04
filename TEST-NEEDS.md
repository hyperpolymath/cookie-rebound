# Test & Benchmark Requirements
## CRG Grade: C — ACHIEVED 2026-04-04

## Current State
- Unit tests: 1 Zig integration test (274 lines) — count unknown (zig test not run)
- Integration tests: 1 (integration_test.zig)
- E2E tests: NONE
- Benchmarks: NONE
- panic-attack scan: NEVER RUN (feature dir exists but no report)

## What's Missing
### Point-to-Point (P2P)
- src/interface/ffi/src/main.zig (1691 lines) — core implementation, partial test coverage via integration_test.zig
- src/interface/abi/Types.idr — no verification tests
- src/interface/abi/Layout.idr — no verification tests
- src/interface/abi/Foreign.idr — no verification tests
- Note: Memory says "35 tests" but only 1 test file (274 lines) found. Verify if tests are inline in main.zig or if some were lost.
- tests/ directory exists but empty (no files)
- tests/fuzz/ exists but empty (placeholder only)
- verification/tests/ exists but only has README placeholder

### End-to-End (E2E)
- Cookie storage and retrieval cycle (JSONL storage)
- Cookie expiration and cleanup
- Cookie consent management workflow
- Import/export cookie data
- Cross-browser cookie format compatibility

### Aspect Tests
- [ ] Security (cookie data sanitisation, JSONL injection, path traversal in storage, consent enforcement)
- [ ] Performance (large cookie store operations, JSONL parsing at scale)
- [ ] Concurrency (concurrent cookie read/write, file locking)
- [ ] Error handling (corrupt JSONL, disk full, invalid cookie data)
- [ ] Accessibility (N/A unless UI component)

### Build & Execution
- [ ] zig build — compiled artifacts exist (libcookie_rebound.a/.so) suggesting past successful build
- [ ] zig test — not verified
- [ ] Library loads and basic operations work — not verified
- [ ] Self-diagnostic — none

### Benchmarks Needed
- JSONL read/write throughput
- Cookie store operations per second
- Memory usage with large cookie databases
- Zig FFI call overhead

### Self-Tests
- [ ] panic-attack assail on own repo
- [ ] Built-in doctor/check command (if applicable)
- [ ] Reconcile memory claim of "35 tests" with actual test count

## Priority
- **MEDIUM** — Small but focused project (1691 lines Zig + 3 Idris2 ABI). Has 1 test file which may contain reasonable coverage for core operations, but the empty test directories and fuzz placeholder suggest testing infrastructure was set up but not populated. The discrepancy between memory ("35 tests") and actual files needs investigation.
