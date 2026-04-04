<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk> -->

# TOPOLOGY.md — cookie-rebound

## Purpose

The canonical RSR (Rhodium Standard Repository) template for new hyperpolymath projects. Demonstrates dual-track architecture (root docs for humans, sub-directories for machine-readable metadata), ABI/FFI standard with Idris2+Zig, and complete CI/CD workflows.

## Module Map

```
cookie-rebound/
├── README.adoc                # High-level orientation
├── EXPLAINME.adoc             # Claims substantiation
├── src/
│   ├── abi/
│   │   └── *.idr              # Idris2 ABI with formal proofs
│   ├── interface/
│   │   └── ... (public API definitions)
│   └── impl.rs                # Implementation
├── ffi/zig/
│   ├── build.zig              # Zig build script
│   └── src/main.zig           # C-compatible FFI layer
├── .machine_readable/
│   ├── STATE.a2ml             # Current project state
│   ├── ECOSYSTEM.a2ml         # Ecosystem position
│   └── META.a2ml              # Philosophy & governance
└── .github/workflows/
    └── ... (17 standard workflows)
```

## Data Flow

```
[Idris2 ABI Definition] ──► [Type Proofs] ──► [C Header Generation]
                                                      ↓
                                            [Zig FFI Implementation]
                                                      ↓
                                          [Language Bindings (Go/Rust/etc.)]
```

## Key Invariants

- Idris2 ABI layer guarantees memory layout correctness at compile-time
- Zig FFI bridges to C ecosystem with zero-cost abstractions
- All 17 standard workflows present and SHA-pinned
- Dual-track design: human docs in root, machine metadata in `.machine_readable/`
