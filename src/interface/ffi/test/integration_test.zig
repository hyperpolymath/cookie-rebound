// Cookie Rebound Integration Tests
// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// These tests verify the cookie vault FFI through the exported C interface,
// exercising the full lifecycle: init, store, get, list, delete, rules, analyse,
// browser export/import, and cleanup.
//
// NOTE: These tests are designed to be run via `zig build test-integration`
// which links against the cookie_rebound library. They can also be run
// independently with `zig test test/integration_test.zig` if the module
// path is configured.
//
// All tests use the exported C FFI functions directly, simulating how
// the Idris2 ABI layer (or any C consumer) would call the library.

const std = @import("std");
const testing = std.testing;

// Import the main module for direct testing (avoids needing extern linkage)
const cr = @import("cookie_rebound");

// ===========================================================================
// Helper: clean up vault files after tests
// ===========================================================================

fn cleanupTestFiles() void {
    std.fs.cwd().deleteFile("cookie_vault.jsonl") catch {};
    std.fs.cwd().deleteFile("cookie_rules.jsonl") catch {};
}

// ===========================================================================
// Lifecycle Tests
// ===========================================================================

test "integration: create and destroy handle" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    try testing.expect(handle != @as(?*anyopaque, null));
}

test "integration: handle is initialized" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    const initialized = cr.cookie_rebound_is_initialized(handle);
    try testing.expectEqual(@as(u32, 1), initialized);
}

test "integration: null handle is not initialized" {
    const initialized = cr.cookie_rebound_is_initialized(null);
    try testing.expectEqual(@as(u32, 0), initialized);
}

test "integration: free null is safe" {
    cr.cookie_rebound_free(null);
}

// ===========================================================================
// Store and Retrieve Tests
// ===========================================================================

test "integration: store and retrieve a cookie" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    const json =
        \\{"name":"session_id","value":"s3cur3","domain":".example.com","path":"/","secure":true,"httpOnly":true,"sameSite":0,"expiresAt":1900000000,"createdAt":1700000000}
    ;

    const store_result = cr.cookie_rebound_store(handle, json);
    try testing.expectEqual(cr.Result.ok, store_result);

    const got = cr.cookie_rebound_get(handle, ".example.com", "session_id") orelse return error.NotFound;
    defer cr.cookie_rebound_free_string(@constCast(got));

    const got_str = std.mem.span(got);
    try testing.expect(std.mem.indexOf(u8, got_str, "\"name\":\"session_id\"") != null);
    try testing.expect(std.mem.indexOf(u8, got_str, "\"value\":\"s3cur3\"") != null);
}

test "integration: store overwrites existing cookie" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"x","value":"old","domain":".d.com","path":"/","secure":false,"httpOnly":false,"sameSite":1,"expiresAt":null,"createdAt":1700000000}
    );
    _ = cr.cookie_rebound_store(handle,
        \\{"name":"x","value":"new","domain":".d.com","path":"/","secure":false,"httpOnly":false,"sameSite":1,"expiresAt":null,"createdAt":1700000000}
    );

    const got = cr.cookie_rebound_get(handle, ".d.com", "x") orelse return error.NotFound;
    defer cr.cookie_rebound_free_string(@constCast(got));
    const got_str = std.mem.span(got);
    try testing.expect(std.mem.indexOf(u8, got_str, "\"value\":\"new\"") != null);
}

// ===========================================================================
// List Tests
// ===========================================================================

test "integration: list cookies by domain" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"a","value":"1","domain":".alpha.com","path":"/","secure":false,"httpOnly":false,"sameSite":1,"expiresAt":null,"createdAt":1700000000}
    );
    _ = cr.cookie_rebound_store(handle,
        \\{"name":"b","value":"2","domain":".beta.com","path":"/","secure":false,"httpOnly":false,"sameSite":1,"expiresAt":null,"createdAt":1700000000}
    );

    // List all
    const all = cr.cookie_rebound_list(handle, "") orelse return error.ListFailed;
    defer cr.cookie_rebound_free_string(@constCast(all));
    const all_str = std.mem.span(all);
    try testing.expect(std.mem.indexOf(u8, all_str, "\"name\":\"a\"") != null);
    try testing.expect(std.mem.indexOf(u8, all_str, "\"name\":\"b\"") != null);

    // Filter by domain
    const filtered = cr.cookie_rebound_list(handle, ".alpha.com") orelse return error.ListFailed;
    defer cr.cookie_rebound_free_string(@constCast(filtered));
    const filtered_str = std.mem.span(filtered);
    try testing.expect(std.mem.indexOf(u8, filtered_str, "\"name\":\"a\"") != null);
    try testing.expect(std.mem.indexOf(u8, filtered_str, "\"name\":\"b\"") == null);
}

// ===========================================================================
// Delete Tests
// ===========================================================================

test "integration: delete a cookie" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"victim","value":"gone","domain":".del.com","path":"/","secure":false,"httpOnly":false,"sameSite":1,"expiresAt":null,"createdAt":1700000000}
    );

    try testing.expectEqual(cr.Result.ok, cr.cookie_rebound_delete(handle, ".del.com", "victim"));
    try testing.expect(cr.cookie_rebound_get(handle, ".del.com", "victim") == null);
}

test "integration: delete nonexistent returns not_found" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    try testing.expectEqual(cr.Result.not_found, cr.cookie_rebound_delete(handle, ".no.com", "nope"));
}

// ===========================================================================
// Protection Rule Tests
// ===========================================================================

test "integration: add and apply protection rules" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"keep","value":"1","domain":".safe.com","path":"/","secure":true,"httpOnly":true,"sameSite":0,"expiresAt":null,"createdAt":1700000000}
    );
    _ = cr.cookie_rebound_store(handle,
        \\{"name":"trash","value":"2","domain":".ads.tracker.net","path":"/","secure":false,"httpOnly":false,"sameSite":2,"expiresAt":null,"createdAt":1700000000}
    );

    try testing.expectEqual(cr.Result.ok, cr.cookie_rebound_add_rule(handle,
        \\{"pattern":"*.safe.com","action":"protect"}
    ));
    try testing.expectEqual(cr.Result.ok, cr.cookie_rebound_add_rule(handle,
        \\{"pattern":"*.tracker.net","action":"delete"}
    ));

    const report = cr.cookie_rebound_apply_rules(handle) orelse return error.ApplyFailed;
    defer cr.cookie_rebound_free_string(@constCast(report));
    const report_str = std.mem.span(report);
    try testing.expect(std.mem.indexOf(u8, report_str, "\"protected\":1") != null);
    try testing.expect(std.mem.indexOf(u8, report_str, "\"deleted\":1") != null);

    // Verify protected cookie remains
    const kept = cr.cookie_rebound_get(handle, ".safe.com", "keep");
    try testing.expect(kept != null);
    if (kept) |p| cr.cookie_rebound_free_string(@constCast(p));

    // Verify deleted cookie is gone
    try testing.expect(cr.cookie_rebound_get(handle, ".ads.tracker.net", "trash") == null);
}

// ===========================================================================
// Analysis Tests
// ===========================================================================

test "integration: analyse cookies" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"_ga","value":"GA1.2.xxx","domain":".example.com","path":"/","secure":false,"httpOnly":false,"sameSite":2,"expiresAt":null,"createdAt":1700000000}
    );

    const analysis = cr.cookie_rebound_analyse(handle, ".example.com") orelse return error.AnalyseFailed;
    defer cr.cookie_rebound_free_string(@constCast(analysis));
    const analysis_str = std.mem.span(analysis);

    try testing.expect(std.mem.indexOf(u8, analysis_str, "\"summary\"") != null);
    try testing.expect(std.mem.indexOf(u8, analysis_str, "\"total\":1") != null);
}

// ===========================================================================
// Browser Export/Import Tests
// ===========================================================================

test "integration: Firefox export and import round trip" {
    defer cleanupTestFiles();
    const handle = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle);

    _ = cr.cookie_rebound_store(handle,
        \\{"name":"ff_ck","value":"ff_val","domain":".ff.org","path":"/","secure":true,"httpOnly":false,"sameSite":1,"expiresAt":1900000000,"createdAt":1700000000}
    );

    std.fs.cwd().makeDir("_test_ff") catch {};
    defer std.fs.cwd().deleteTree("_test_ff") catch {};

    try testing.expectEqual(cr.Result.ok, cr.cookie_rebound_export_browser(handle, 0, "_test_ff"));

    const handle2 = cr.cookie_rebound_init() orelse return error.InitFailed;
    defer cr.cookie_rebound_free(handle2);
    try testing.expectEqual(cr.Result.ok, cr.cookie_rebound_import_browser(handle2, 0, "_test_ff"));

    const got = cr.cookie_rebound_get(handle2, ".ff.org", "ff_ck");
    try testing.expect(got != null);
    if (got) |g| {
        try testing.expect(std.mem.indexOf(u8, std.mem.span(g), "\"value\":\"ff_val\"") != null);
        cr.cookie_rebound_free_string(@constCast(g));
    }
}

// ===========================================================================
// Version Tests
// ===========================================================================

test "integration: version string" {
    const ver = cr.cookie_rebound_version();
    const ver_str = std.mem.span(ver);
    try testing.expectEqualStrings("0.1.0", ver_str);
}

// ===========================================================================
// Error Handling Tests
// ===========================================================================

test "integration: null operations are safe" {
    try testing.expectEqual(cr.Result.null_pointer, cr.cookie_rebound_store(null, "{}"));
    try testing.expect(cr.cookie_rebound_get(null, "a", "b") == null);
    try testing.expect(cr.cookie_rebound_list(null, "") == null);
    try testing.expectEqual(cr.Result.null_pointer, cr.cookie_rebound_delete(null, "a", "b"));
    try testing.expectEqual(cr.Result.null_pointer, cr.cookie_rebound_add_rule(null, "{}"));
    try testing.expect(cr.cookie_rebound_apply_rules(null) == null);
    try testing.expect(cr.cookie_rebound_analyse(null, "x") == null);
    try testing.expectEqual(@as(u32, 0), cr.cookie_rebound_is_initialized(null));
    cr.cookie_rebound_free(null);
    cr.cookie_rebound_free_string(null);
}
