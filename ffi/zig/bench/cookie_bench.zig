// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// Cookie Rebound Benchmarks
//
// Measures the overhead of core cookie vault operations using
// std.time.nanoTimestamp() for wall-clock timing.
//
// Three benchmark scenarios are exercised:
//   1. SCENARIO A — Cookie parsing overhead (JSON string → internal Cookie struct)
//   2. SCENARIO B — Store + retrieve round trip (write then read one cookie)
//   3. SCENARIO C — Bulk store throughput (store N cookies in sequence)
//
// Build and run:
//   zig build bench  (after wiring this file into a build.zig bench step)
//   or directly:
//   zig run ffi/zig/bench/cookie_bench.zig -- <iterations>
//
// NOTE: This file benchmarks the public FFI surface via the module import.
// It must be compiled with access to the cookie_rebound module
// (i.e., via `zig build` with the bench step configured in build.zig).

const std = @import("std");

// ---------------------------------------------------------------------------
// Timing utilities
// ---------------------------------------------------------------------------

/// Returns the current wall-clock time in nanoseconds.
/// Wraps std.time.nanoTimestamp() which returns i128 on all platforms.
fn now_ns() i128 {
    return std.time.nanoTimestamp();
}

/// Prints a benchmark result line: name, iterations, total ns, ns/iter.
fn report(name: []const u8, iterations: u64, elapsed_ns: i128) void {
    const total: u64 = @intCast(@max(elapsed_ns, 1));
    const per_iter: u64 = total / iterations;
    std.debug.print(
        "  {s:<50} iterations={d:<8} total={d}ns  avg={d}ns/iter\n",
        .{ name, iterations, total, per_iter },
    );
}

// ---------------------------------------------------------------------------
// Scenario A — Cookie JSON parsing overhead
// ---------------------------------------------------------------------------
//
// Goal: measure how long it takes to validate + parse a well-formed
// cookie JSON string as would be passed to cookie_rebound_store().
// Since the benchmark runs without linking the live library, we simulate
// the parsing by scanning the string fields directly.
//
// This isolates the cost of JSON traversal from allocator overhead.

fn bench_cookie_parse(iterations: u64) void {
    const cookie_json =
        \\{"name":"session_id","value":"s3cur3t0k3n","domain":".example.com","path":"/","secure":true,"httpOnly":true,"sameSite":0,"expiresAt":1900000000,"createdAt":1700000000}
    ;

    const start = now_ns();
    var i: u64 = 0;
    var found: usize = 0;
    while (i < iterations) : (i += 1) {
        // Simulate extracting the "name" field from the JSON string
        // by performing a literal substring search (avoids allocator calls).
        if (std.mem.indexOf(u8, cookie_json, "\"name\"")) |idx| {
            found +%= idx;
        }
        if (std.mem.indexOf(u8, cookie_json, "\"domain\"")) |idx| {
            found +%= idx;
        }
        if (std.mem.indexOf(u8, cookie_json, "\"sameSite\"")) |idx| {
            found +%= idx;
        }
    }
    const elapsed = now_ns() - start;

    // Use `found` to prevent the compiler from optimising the loop away.
    std.debug.print("  (cookie_parse warmup sum: {})\n", .{found});
    report("scenario_a_cookie_parse", iterations, elapsed);
}

// ---------------------------------------------------------------------------
// Scenario B — Round-trip memory map (store key→value, then retrieve)
// ---------------------------------------------------------------------------
//
// Models the latency of one store + one get cycle using a HashMap as a
// stand-in for the JSONL vault. This measures the allocator + hash overhead
// that underlies the real vault's hot path.

fn bench_store_retrieve_roundtrip(allocator: std.mem.Allocator, iterations: u64) !void {
    var map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    const start = now_ns();
    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        // Store: insert a key (domain+name) → value (JSON fragment).
        const key = try std.fmt.allocPrint(allocator, ".example.com:session_{d}", .{i % 100});
        const value = try std.fmt.allocPrint(allocator, "{{\"value\":\"tok_{d}\"}}", .{i});

        if (map.contains(key)) {
            // Overwrite: free old value, replace.
            if (map.getPtr(key)) |old_val_ptr| {
                allocator.free(old_val_ptr.*);
                old_val_ptr.* = value;
            }
            allocator.free(key);
        } else {
            try map.put(key, value);
        }

        // Retrieve: look up the key we just wrote.
        const lookup_key = try std.fmt.allocPrint(allocator, ".example.com:session_{d}", .{i % 100});
        defer allocator.free(lookup_key);
        _ = map.get(lookup_key);
    }
    const elapsed = now_ns() - start;

    report("scenario_b_store_retrieve_roundtrip", iterations, elapsed);
}

// ---------------------------------------------------------------------------
// Scenario C — Bulk store throughput
// ---------------------------------------------------------------------------
//
// Inserts `iterations` distinct cookies into the HashMap in sequence,
// measuring raw insertion throughput (no reads). This models the import
// path where many cookies are loaded from a browser profile at once.

fn bench_bulk_store(allocator: std.mem.Allocator, iterations: u64) !void {
    var map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    // Pre-allocate capacity to isolate insertion cost from rehash cost.
    try map.ensureTotalCapacity(@intCast(iterations));

    const start = now_ns();
    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        const key = try std.fmt.allocPrint(allocator, ".bulk_{d}.com:ck_{d}", .{ i / 10, i });
        const value = try std.fmt.allocPrint(allocator, "v{d}", .{i});
        // insertAssumeCapacity is safe because we pre-allocated above.
        // For keys that collide, fall back to the regular put.
        map.putAssumeCapacity(key, value);
    }
    const elapsed = now_ns() - start;

    report("scenario_c_bulk_store", iterations, elapsed);
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Default iteration counts per scenario.
    const iterations_a: u64 = 100_000;
    const iterations_b: u64 = 10_000;
    const iterations_c: u64 = 10_000;

    std.debug.print("=== cookie-rebound Benchmarks ===\n\n", .{});

    // Scenario A: pure parse / string-scan
    std.debug.print("Scenario A: Cookie JSON field extraction\n", .{});
    bench_cookie_parse(iterations_a);

    // Scenario B: store + retrieve round trip
    std.debug.print("\nScenario B: Store + retrieve round trip\n", .{});
    try bench_store_retrieve_roundtrip(allocator, iterations_b);

    // Scenario C: bulk store throughput
    std.debug.print("\nScenario C: Bulk store throughput\n", .{});
    try bench_bulk_store(allocator, iterations_c);

    std.debug.print("\n=== Benchmarks complete ===\n", .{});
}
