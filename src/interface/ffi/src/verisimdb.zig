// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// cookie-rebound :: src/interface/ffi/src/verisimdb.zig
//
// VeriSimDB persistence client for consent scan history.
//
// Persists cookie-rebound scan results to VeriSimDB under the collection
// `cookie-rebound:scans` so that Hypatia rules can analyse scan history
// across multiple runs and gitbot-fleet can act on patterns.
//
// ## Collection schema (cookie-rebound:scans)
//
// ```json
// {
//   "scan_id":     "cr:1740000000000:abc123",
//   "timestamp":   "2026-01-30T12:00:00Z",
//   "url":         "https://example.com",
//   "cookies_found": 12,
//   "trackers_found": 3,
//   "consent_gates": ["analytics", "functional"],
//   "violations":  ["missing-samesite", "no-expiry"],
//   "status":      "complete"
// }
// ```
//
// ## Environment
//
// Set `VERISIMDB_URL` to override the default `http://localhost:8080`.
//
// ## Fail-open semantics
//
// If VeriSimDB is unreachable, `persistScan` returns an error but the
// caller continues. Scan results are always written to local JSONL first;
// VeriSimDB is additional durable storage, not a hard dependency.

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_URL = "http://localhost:8080";
const COLLECTION   = "cookie-rebound:scans";
const CONNECT_TIMEOUT_MS: u32 = 2_000;
const REQUEST_TIMEOUT_MS:  u32 = 5_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single cookie consent scan result for VeriSimDB persistence.
pub const ScanResult = struct {
    scan_id:        []const u8,
    timestamp:      []const u8,
    url:            []const u8,
    cookies_found:  u32,
    trackers_found: u32,
    status:         []const u8,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Persist a scan result to VeriSimDB (collection: cookie-rebound:scans).
///
/// Uses HTTP PUT to `/v1/cookie-rebound:scans/<scan_id>`.
/// Returns an error if VeriSimDB is unreachable or returns non-2xx.
/// Callers should log the error and continue — fail-open semantics.
pub fn persistScan(allocator: std.mem.Allocator, result: ScanResult) !void {
    const base_url = std.posix.getenv("VERISIMDB_URL") orelse DEFAULT_URL;

    // Build URL: <base>/v1/cookie-rebound:scans/<scan_id>
    const url = try std.fmt.allocPrint(allocator, "{s}/v1/{s}/{s}", .{
        base_url, COLLECTION, result.scan_id,
    });
    defer allocator.free(url);

    // Build JSON body
    const body = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "scan_id": "{s}",
        \\  "timestamp": "{s}",
        \\  "url": "{s}",
        \\  "cookies_found": {d},
        \\  "trackers_found": {d},
        \\  "status": "{s}"
        \\}}
    , .{
        result.scan_id,
        result.timestamp,
        result.url,
        result.cookies_found,
        result.trackers_found,
        result.status,
    });
    defer allocator.free(body);

    try httpPut(allocator, url, body);
}

/// Generate a stable scan ID from URL and timestamp milliseconds.
///
/// Format: `cr:<ts_ms>:<first_8_of_url_sha256_hex>`
pub fn makeScanId(allocator: std.mem.Allocator, url: []const u8, ts_ms: u64) ![]u8 {
    var hash_buf: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(url, &hash_buf, .{});
    const hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(hash_buf[0..4])});
    defer allocator.free(hex);
    return std.fmt.allocPrint(allocator, "cr:{d}:{s}", .{ ts_ms, hex });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// HTTP PUT via std.http.Client.
fn httpPut(allocator: std.mem.Allocator, url: []const u8, body: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);

    var header_buf: [4096]u8 = undefined;
    var req = try client.open(.PUT, uri, .{
        .server_header_buffer = &header_buf,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = body.len };
    try req.send();
    try req.writeAll(body);
    try req.finish();
    try req.wait();

    const status = req.response.status;
    if (@intFromEnum(status) < 200 or @intFromEnum(status) >= 300) {
        return error.VeriSimDbHttpError;
    }
}
