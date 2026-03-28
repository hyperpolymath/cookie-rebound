// Cookie Rebound FFI Implementation
//
// Persistent cookie vault with JSONL-backed storage, protection rules,
// tracking analysis, and browser import/export.
//
// This module implements the C-compatible FFI declared in src/interface/abi/Foreign.idr.
// All types and layouts must match the Idris2 ABI definitions in Types.idr.
//
// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

const std = @import("std");
const builtin = @import("builtin");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Library version (semantic versioning)
const VERSION = "0.1.0";

/// Build information string
const BUILD_INFO = "cookie_rebound built with Zig " ++ @import("builtin").zig_version_string;

/// Default vault storage file name
const DEFAULT_VAULT_FILE = "cookie_vault.jsonl";

/// Default rules storage file name
const DEFAULT_RULES_FILE = "cookie_rules.jsonl";

/// Maximum number of cookies in a single vault (to prevent runaway memory usage)
const MAX_COOKIES: usize = 100_000;

/// Maximum number of protection rules
const MAX_RULES: usize = 10_000;

/// Maximum JSON string length for a single cookie
const MAX_COOKIE_JSON_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Result Codes (must match Idris2 Result type in Types.idr)
// ---------------------------------------------------------------------------

/// FFI result codes matching the ABI specification
pub const Result = enum(c_int) {
    ok = 0,
    err = 1,
    invalid_param = 2,
    out_of_memory = 3,
    null_pointer = 4,
    not_found = 5,
    duplicate = 6,
    storage_error = 7,
};

// ---------------------------------------------------------------------------
// Cookie Data Model
// ---------------------------------------------------------------------------

/// SameSite policy enum matching Idris2 SameSitePolicy
const SameSitePolicy = enum(u8) {
    strict = 0,
    lax = 1,
    none_ss = 2,
};

/// RuleAction enum matching Idris2 RuleAction
const RuleAction = enum(u8) {
    protect = 0,
    ignore = 1,
    delete = 2,
};

/// ConsentCategory enum matching Idris2 ConsentCategory
const ConsentCategory = enum(u8) {
    necessary = 0,
    functional = 1,
    analytics = 2,
    marketing = 3,
    unknown = 4,
};

/// BrowserType enum matching Idris2 BrowserType
const BrowserType = enum(u32) {
    firefox = 0,
    chrome = 1,
};

/// Internal cookie representation.
/// All string fields are owned by the allocator and must be freed.
const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8,
    secure: bool,
    http_only: bool,
    same_site: SameSitePolicy,
    expires_at: ?u64, // null means session cookie
    created_at: u64,

    /// Free all owned string memory
    fn deinit(self: *Cookie, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        allocator.free(self.domain);
        allocator.free(self.path);
    }

    /// Unique key for deduplication: domain + "||" + name
    fn makeKey(self: *const Cookie, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}||{s}", .{ self.domain, self.name });
    }

    /// Serialize cookie to a JSON string
    fn toJson(self: *const Cookie, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.array_list.Managed(u8).init(allocator);
        defer buf.deinit();
        const writer = buf.writer();

        try writer.writeAll("{\"name\":\"");
        try writeJsonEscaped(writer, self.name);
        try writer.writeAll("\",\"value\":\"");
        try writeJsonEscaped(writer, self.value);
        try writer.writeAll("\",\"domain\":\"");
        try writeJsonEscaped(writer, self.domain);
        try writer.writeAll("\",\"path\":\"");
        try writeJsonEscaped(writer, self.path);
        try writer.print("\",\"secure\":{},\"httpOnly\":{},\"sameSite\":{d}", .{
            self.secure, self.http_only, @intFromEnum(self.same_site),
        });
        if (self.expires_at) |exp| {
            try writer.print(",\"expiresAt\":{d}", .{exp});
        } else {
            try writer.writeAll(",\"expiresAt\":null");
        }
        try writer.print(",\"createdAt\":{d}}}", .{self.created_at});

        return buf.toOwnedSlice();
    }
};

/// Internal protection rule representation.
const ProtectionRule = struct {
    pattern: []const u8,
    action: RuleAction,

    fn deinit(self: *ProtectionRule, allocator: std.mem.Allocator) void {
        allocator.free(self.pattern);
    }

    /// Check if a domain matches this rule's glob pattern.
    /// Supports '*' as a wildcard for any sequence of characters.
    fn matches(self: *const ProtectionRule, domain: []const u8) bool {
        return globMatch(self.pattern, domain);
    }
};

// ---------------------------------------------------------------------------
// Vault Handle (the opaque library state)
// ---------------------------------------------------------------------------

/// The vault handle holds all state: cookies, rules, storage paths, allocator.
const VaultHandle = struct {
    allocator: std.mem.Allocator,
    initialized: bool,
    cookies: std.StringHashMap(Cookie),
    rules: std.array_list.Managed(ProtectionRule),
    vault_path: []const u8,
    rules_path: []const u8,

    /// Create a new vault handle and load existing data from disk.
    fn create(allocator: std.mem.Allocator) !*VaultHandle {
        const handle = try allocator.create(VaultHandle);
        handle.* = .{
            .allocator = allocator,
            .initialized = true,
            .cookies = std.StringHashMap(Cookie).init(allocator),
            .rules = std.array_list.Managed(ProtectionRule).init(allocator),
            .vault_path = DEFAULT_VAULT_FILE,
            .rules_path = DEFAULT_RULES_FILE,
        };

        // Attempt to load existing vault data from disk (ignore errors on first run)
        handle.loadFromDisk() catch {};
        handle.loadRulesFromDisk() catch {};

        return handle;
    }

    /// Destroy the vault handle and free all memory.
    fn destroy(self: *VaultHandle) void {
        const allocator = self.allocator;

        // Free all cookie entries
        var cookie_iter = self.cookies.iterator();
        while (cookie_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            var cookie = entry.value_ptr.*;
            cookie.deinit(allocator);
        }
        self.cookies.deinit();

        // Free all rules
        for (self.rules.items) |*rule| {
            var r = rule.*;
            r.deinit(allocator);
        }
        self.rules.deinit();

        self.initialized = false;
        allocator.destroy(self);
    }

    /// Persist all cookies to the JSONL vault file.
    fn saveToDisk(self: *VaultHandle) !void {
        var file = try std.fs.cwd().createFile(self.vault_path, .{});
        defer file.close();

        var cookie_iter = self.cookies.iterator();
        while (cookie_iter.next()) |entry| {
            const json = try entry.value_ptr.toJson(self.allocator);
            defer self.allocator.free(json);
            try file.writeAll(json);
            try file.writeAll("\n");
        }
    }

    /// Load cookies from the JSONL vault file.
    fn loadFromDisk(self: *VaultHandle) !void {
        var file = std.fs.cwd().openFile(self.vault_path, .{}) catch |e| {
            if (e == error.FileNotFound) return;
            return e;
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 64 * 1024 * 1024) catch return;
        defer self.allocator.free(content);

        var start: usize = 0;
        for (content, 0..) |c, i| {
            if (c == '\n' or i == content.len - 1) {
                const end = if (c == '\n') i else i + 1;
                const l = content[start..end];
                start = i + 1;
                if (l.len == 0) continue;

                var cookie_val = parseCookieJson(l, self.allocator) catch continue;
                const k = cookie_val.makeKey(self.allocator) catch {
                    cookie_val.deinit(self.allocator);
                    continue;
                };

                if (self.cookies.contains(k)) {
                    self.allocator.free(k);
                    cookie_val.deinit(self.allocator);
                } else {
                    self.cookies.put(k, cookie_val) catch {
                        self.allocator.free(k);
                        cookie_val.deinit(self.allocator);
                    };
                }
            }
        }
    }

    /// Persist all rules to the JSONL rules file.
    fn saveRulesToDisk(self: *VaultHandle) !void {
        var file = try std.fs.cwd().createFile(self.rules_path, .{});
        defer file.close();

        for (self.rules.items) |rule| {
            var buf = std.array_list.Managed(u8).init(self.allocator);
            defer buf.deinit();
            const writer = buf.writer();
            try writer.writeAll("{\"pattern\":\"");
            try writeJsonEscaped(writer, rule.pattern);
            try writer.print("\",\"action\":{d}}}\n", .{@intFromEnum(rule.action)});
            try file.writeAll(buf.items);
        }
    }

    /// Load rules from the JSONL rules file.
    fn loadRulesFromDisk(self: *VaultHandle) !void {
        var file = std.fs.cwd().openFile(self.rules_path, .{}) catch |e| {
            if (e == error.FileNotFound) return;
            return e;
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 64 * 1024 * 1024) catch return;
        defer self.allocator.free(content);

        var start: usize = 0;
        for (content, 0..) |c, i| {
            if (c == '\n' or i == content.len - 1) {
                const end = if (c == '\n') i else i + 1;
                const l = content[start..end];
                start = i + 1;
                if (l.len == 0) continue;

                var rule = parseRuleJson(l, self.allocator) catch continue;
                self.rules.append(rule) catch {
                    rule.deinit(self.allocator);
                };
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Thread-local error storage
// ---------------------------------------------------------------------------

threadlocal var last_error: ?[]const u8 = null;

fn setError(msg: []const u8) void {
    last_error = msg;
}

fn clearError() void {
    last_error = null;
}

// ---------------------------------------------------------------------------
// JSON Parsing Helpers
// ---------------------------------------------------------------------------

/// Write a string with JSON escaping (quotes, backslashes, control chars)
fn writeJsonEscaped(writer: anytype, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Extract a JSON string value for a given key from a JSON object string.
/// This is a minimal parser that handles the subset of JSON we generate.
/// Returns a newly allocated copy of the value.
fn jsonGetString(json: []const u8, field: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Build search pattern: "field":"
    var pattern_buf: [256]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":\"", .{field}) catch return error.Overflow;

    const start_idx = std.mem.indexOf(u8, json, pattern) orelse return error.NotFound;
    const value_start = start_idx + pattern.len;

    // Find the closing quote (handle escaped quotes)
    var i: usize = value_start;
    var result = std.array_list.Managed(u8).init(allocator);
    errdefer result.deinit();

    while (i < json.len) {
        if (json[i] == '\\' and i + 1 < json.len) {
            switch (json[i + 1]) {
                '"' => try result.append('"'),
                '\\' => try result.append('\\'),
                'n' => try result.append('\n'),
                'r' => try result.append('\r'),
                't' => try result.append('\t'),
                else => {
                    try result.append(json[i]);
                    try result.append(json[i + 1]);
                },
            }
            i += 2;
        } else if (json[i] == '"') {
            break;
        } else {
            try result.append(json[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Extract a JSON boolean value for a given key.
fn jsonGetBool(json: []const u8, field: []const u8) !bool {
    var pattern_buf: [256]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":", .{field}) catch return error.Overflow;

    const start_idx = std.mem.indexOf(u8, json, pattern) orelse return error.NotFound;
    const value_start = start_idx + pattern.len;

    // Skip whitespace
    var i: usize = value_start;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t')) : (i += 1) {}

    if (i + 4 <= json.len and std.mem.eql(u8, json[i .. i + 4], "true")) {
        return true;
    }
    if (i + 5 <= json.len and std.mem.eql(u8, json[i .. i + 5], "false")) {
        return false;
    }
    return error.InvalidCharacter;
}

/// Extract a JSON integer value for a given key.
fn jsonGetInt(json: []const u8, field: []const u8) !?u64 {
    var pattern_buf: [256]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":", .{field}) catch return error.Overflow;

    const start_idx = std.mem.indexOf(u8, json, pattern) orelse return error.NotFound;
    const value_start = start_idx + pattern.len;

    // Skip whitespace
    var i: usize = value_start;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t')) : (i += 1) {}

    // Check for null
    if (i + 4 <= json.len and std.mem.eql(u8, json[i .. i + 4], "null")) {
        return null;
    }

    // Parse integer
    var end: usize = i;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') : (end += 1) {}

    if (end == i) return error.InvalidCharacter;

    return std.fmt.parseInt(u64, json[i..end], 10) catch return error.InvalidCharacter;
}

/// Parse a complete cookie JSON object into a Cookie struct.
fn parseCookieJson(json: []const u8, allocator: std.mem.Allocator) !Cookie {
    const name = try jsonGetString(json, "name", allocator);
    errdefer allocator.free(name);
    const value = try jsonGetString(json, "value", allocator);
    errdefer allocator.free(value);
    const domain = try jsonGetString(json, "domain", allocator);
    errdefer allocator.free(domain);
    const path = try jsonGetString(json, "path", allocator);
    errdefer allocator.free(path);

    const secure = jsonGetBool(json, "secure") catch false;
    const http_only = jsonGetBool(json, "httpOnly") catch false;

    const same_site_int = jsonGetInt(json, "sameSite") catch null;
    const same_site: SameSitePolicy = if (same_site_int) |v|
        std.meta.intToEnum(SameSitePolicy, @as(u8, @intCast(v))) catch .lax
    else
        .lax;

    const expires_at = jsonGetInt(json, "expiresAt") catch null;
    const created_at = (jsonGetInt(json, "createdAt") catch null) orelse
        @as(u64, @intCast(std.time.timestamp()));

    return Cookie{
        .name = name,
        .value = value,
        .domain = domain,
        .path = path,
        .secure = secure,
        .http_only = http_only,
        .same_site = same_site,
        .expires_at = expires_at,
        .created_at = created_at,
    };
}

/// Parse a protection rule JSON object.
fn parseRuleJson(json: []const u8, allocator: std.mem.Allocator) !ProtectionRule {
    const pattern = try jsonGetString(json, "pattern", allocator);
    errdefer allocator.free(pattern);

    // Try integer action first, then string action
    const action_int = jsonGetInt(json, "action") catch null;
    const action: RuleAction = if (action_int) |v|
        std.meta.intToEnum(RuleAction, @as(u8, @intCast(v))) catch .ignore
    else blk: {
        const action_str = jsonGetString(json, "action", allocator) catch break :blk RuleAction.ignore;
        defer allocator.free(action_str);
        if (std.mem.eql(u8, action_str, "protect")) break :blk RuleAction.protect;
        if (std.mem.eql(u8, action_str, "ignore")) break :blk RuleAction.ignore;
        if (std.mem.eql(u8, action_str, "delete")) break :blk RuleAction.delete;
        break :blk RuleAction.ignore;
    };

    return ProtectionRule{
        .pattern = pattern,
        .action = action,
    };
}

// ---------------------------------------------------------------------------
// Glob Matching
// ---------------------------------------------------------------------------

/// Simple glob pattern matching supporting '*' and '?' wildcards.
/// '*' matches zero or more arbitrary characters.
/// '?' matches exactly one character.
fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    var star_pi: ?usize = null;
    var star_ti: usize = 0;

    while (ti < text.len) {
        if (pi < pattern.len and (pattern[pi] == text[ti] or pattern[pi] == '?')) {
            pi += 1;
            ti += 1;
        } else if (pi < pattern.len and pattern[pi] == '*') {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if (star_pi != null) {
            pi = star_pi.? + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while (pi < pattern.len and pattern[pi] == '*') : (pi += 1) {}

    return pi == pattern.len;
}

// ---------------------------------------------------------------------------
// Known Tracker Domains (for analysis)
// ---------------------------------------------------------------------------

/// List of known tracker domain patterns used by the analysis engine.
/// These cover major ad networks, analytics platforms, and fingerprinting services.
const KNOWN_TRACKER_PATTERNS = [_][]const u8{
    "*.doubleclick.net",
    "*.google-analytics.com",
    "*.googlesyndication.com",
    "*.facebook.com",
    "*.facebook.net",
    "*.analytics.yahoo.com",
    "*.scorecardresearch.com",
    "*.quantserve.com",
    "*.adnxs.com",
    "*.adsrvr.org",
    "*.criteo.com",
    "*.criteo.net",
    "*.outbrain.com",
    "*.taboola.com",
    "*.hotjar.com",
    "*.mouseflow.com",
    "*.fullstory.com",
    "*.clarity.ms",
    "*.amazon-adsystem.com",
    "*.rubiconproject.com",
};

/// Check if a domain is a known tracker.
fn isKnownTracker(domain: []const u8) bool {
    for (&KNOWN_TRACKER_PATTERNS) |pattern| {
        if (globMatch(pattern, domain)) return true;
    }
    return false;
}

/// Infer consent category for a cookie based on name and domain heuristics.
fn inferConsentCategory(name: []const u8, domain: []const u8) ConsentCategory {
    // Known marketing/tracker patterns
    if (isKnownTracker(domain)) return .marketing;

    // Common analytics cookie name patterns
    const analytics_prefixes = [_][]const u8{ "_ga", "_gid", "_gat", "__utm", "_hjid", "_fbp", "_fbc" };
    for (&analytics_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return .analytics;
    }

    // Common necessary cookie name patterns
    const necessary_prefixes = [_][]const u8{ "CSRF", "csrf", "XSRF", "xsrf", "__Host-", "__Secure-", "session", "sid" };
    for (&necessary_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return .necessary;
    }

    // Common functional cookie name patterns
    const functional_prefixes = [_][]const u8{ "lang", "locale", "theme", "pref", "tz", "dark_mode" };
    for (&functional_prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return .functional;
    }

    return .unknown;
}

// ---------------------------------------------------------------------------
// Exported C FFI Functions
// ---------------------------------------------------------------------------

/// Initialize the cookie vault.
/// Creates the vault handle, loads existing data from disk.
/// Returns an opaque pointer, or null on failure.
pub export fn cookie_rebound_init() callconv(.c) ?*anyopaque {
    const allocator = std.heap.c_allocator;

    const handle = VaultHandle.create(allocator) catch {
        setError("Failed to create vault handle");
        return null;
    };

    clearError();
    // SAFETY: VaultHandle pointer is returned as opaque to C; the only way
    // to use it is through our exported functions which cast it back.
    return @ptrCast(handle);
}

/// Free the vault handle and all associated memory.
/// Safe to call with null (no-op).
pub export fn cookie_rebound_free(handle_ptr: ?*anyopaque) callconv(.c) void {
    const ptr = handle_ptr orelse return;
    // SAFETY: We only hand out VaultHandle pointers from cookie_rebound_init,
    // so this cast is valid for any non-null pointer we receive back.
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) return;
    handle.destroy();
    clearError();
}

/// Store a cookie in the vault from a JSON string.
/// Overwrites if cookie with same domain+name already exists.
pub export fn cookie_rebound_store(handle_ptr: ?*anyopaque, json_ptr: ?[*:0]const u8) callconv(.c) Result {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const json_cstr = json_ptr orelse {
        setError("Null JSON string");
        return .null_pointer;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return .err;
    }

    const json = std.mem.span(json_cstr);
    if (json.len == 0) {
        setError("Empty JSON string");
        return .invalid_param;
    }

    var cookie = parseCookieJson(json, handle.allocator) catch {
        setError("Failed to parse cookie JSON");
        return .invalid_param;
    };

    const k = cookie.makeKey(handle.allocator) catch {
        cookie.deinit(handle.allocator);
        setError("Failed to create cookie key");
        return .out_of_memory;
    };

    // If key already exists, remove the old entry first
    if (handle.cookies.fetchRemove(k)) |old| {
        handle.allocator.free(old.key);
        var old_cookie = old.value;
        old_cookie.deinit(handle.allocator);
    }

    handle.cookies.put(k, cookie) catch {
        handle.allocator.free(k);
        cookie.deinit(handle.allocator);
        setError("Failed to store cookie");
        return .out_of_memory;
    };

    // Persist to disk
    handle.saveToDisk() catch {
        setError("Failed to persist vault to disk");
        return .storage_error;
    };

    clearError();
    return .ok;
}

/// Retrieve a cookie by domain and name.
/// Returns a newly allocated JSON string (caller must free with cookie_rebound_free_string),
/// or null if not found.
pub export fn cookie_rebound_get(handle_ptr: ?*anyopaque, domain_ptr: ?[*:0]const u8, name_ptr: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return null;
    };
    const domain_cstr = domain_ptr orelse {
        setError("Null domain");
        return null;
    };
    const name_cstr = name_ptr orelse {
        setError("Null name");
        return null;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return null;
    }

    const domain = std.mem.span(domain_cstr);
    const name = std.mem.span(name_cstr);

    // Build lookup key
    const k = std.fmt.allocPrint(handle.allocator, "{s}||{s}", .{ domain, name }) catch {
        setError("Out of memory building key");
        return null;
    };
    defer handle.allocator.free(k);

    const cookie = handle.cookies.get(k) orelse {
        setError("Cookie not found");
        return null;
    };

    const json = cookie.toJson(handle.allocator) catch {
        setError("Failed to serialize cookie");
        return null;
    };

    // Convert to null-terminated C string
    const c_str = handle.allocator.allocSentinel(u8, json.len, 0) catch {
        handle.allocator.free(json);
        setError("Out of memory");
        return null;
    };
    @memcpy(c_str[0..json.len], json);
    handle.allocator.free(json);

    clearError();
    return c_str.ptr;
}

/// List cookies matching a domain filter (empty string = all cookies).
/// Returns a JSON array string. Caller must free with cookie_rebound_free_string.
pub export fn cookie_rebound_list(handle_ptr: ?*anyopaque, filter_ptr: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return null;
    };
    const filter_cstr = filter_ptr orelse {
        setError("Null filter");
        return null;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return null;
    }

    const filter = std.mem.span(filter_cstr);
    const match_all = filter.len == 0;

    var buf = std.array_list.Managed(u8).init(handle.allocator);
    defer buf.deinit();
    const writer = buf.writer();

    writer.writeByte('[') catch {
        setError("Out of memory");
        return null;
    };

    var first = true;
    var cookie_iter = handle.cookies.iterator();
    while (cookie_iter.next()) |entry| {
        const cookie = entry.value_ptr;
        if (!match_all and !std.mem.eql(u8, cookie.domain, filter) and !globMatch(filter, cookie.domain)) {
            continue;
        }
        if (!first) {
            writer.writeByte(',') catch {
                setError("Out of memory");
                return null;
            };
        }
        const json = cookie.toJson(handle.allocator) catch {
            setError("Failed to serialize cookie");
            return null;
        };
        defer handle.allocator.free(json);
        writer.writeAll(json) catch {
            setError("Out of memory");
            return null;
        };
        first = false;
    }

    writer.writeByte(']') catch {
        setError("Out of memory");
        return null;
    };

    const result = handle.allocator.allocSentinel(u8, buf.items.len, 0) catch {
        setError("Out of memory");
        return null;
    };
    @memcpy(result[0..buf.items.len], buf.items);

    clearError();
    return result.ptr;
}

/// Delete a cookie by domain and name.
pub export fn cookie_rebound_delete(handle_ptr: ?*anyopaque, domain_ptr: ?[*:0]const u8, name_ptr: ?[*:0]const u8) callconv(.c) Result {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const domain_cstr = domain_ptr orelse {
        setError("Null domain");
        return .null_pointer;
    };
    const name_cstr = name_ptr orelse {
        setError("Null name");
        return .null_pointer;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return .err;
    }

    const domain = std.mem.span(domain_cstr);
    const name = std.mem.span(name_cstr);

    const k = std.fmt.allocPrint(handle.allocator, "{s}||{s}", .{ domain, name }) catch {
        setError("Out of memory building key");
        return .out_of_memory;
    };
    defer handle.allocator.free(k);

    if (handle.cookies.fetchRemove(k)) |old| {
        handle.allocator.free(old.key);
        var old_cookie = old.value;
        old_cookie.deinit(handle.allocator);

        handle.saveToDisk() catch {
            setError("Failed to persist deletion to disk");
            return .storage_error;
        };

        clearError();
        return .ok;
    }

    setError("Cookie not found");
    return .not_found;
}

/// Add a protection rule from JSON.
/// JSON format: {"pattern":"*.example.com","action":"protect"} or {"pattern":"*","action":0}
pub export fn cookie_rebound_add_rule(handle_ptr: ?*anyopaque, json_ptr: ?[*:0]const u8) callconv(.c) Result {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const json_cstr = json_ptr orelse {
        setError("Null JSON string");
        return .null_pointer;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return .err;
    }

    const json = std.mem.span(json_cstr);
    var rule = parseRuleJson(json, handle.allocator) catch {
        setError("Failed to parse rule JSON");
        return .invalid_param;
    };

    handle.rules.append(rule) catch {
        rule.deinit(handle.allocator);
        setError("Failed to store rule");
        return .out_of_memory;
    };

    handle.saveRulesToDisk() catch {
        setError("Failed to persist rules to disk");
        return .storage_error;
    };

    clearError();
    return .ok;
}

/// Apply all protection rules to the vault.
/// Returns a JSON report: {"protected":N,"ignored":N,"deleted":N}
pub export fn cookie_rebound_apply_rules(handle_ptr: ?*anyopaque) callconv(.c) ?[*:0]u8 {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return null;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return null;
    }

    var protected: u32 = 0;
    var ignored: u32 = 0;
    var deleted: u32 = 0;

    // Collect keys to delete (cannot modify HashMap during iteration)
    var to_delete = std.array_list.Managed([]const u8).init(handle.allocator);
    defer to_delete.deinit();

    var cookie_iter = handle.cookies.iterator();
    while (cookie_iter.next()) |entry| {
        const cookie = entry.value_ptr;
        var matched = false;
        for (handle.rules.items) |rule| {
            if (rule.matches(cookie.domain)) {
                switch (rule.action) {
                    .protect => {
                        protected += 1;
                        matched = true;
                        break;
                    },
                    .ignore => {
                        ignored += 1;
                        matched = true;
                        break;
                    },
                    .delete => {
                        const k_copy = handle.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                        to_delete.append(k_copy) catch {
                            handle.allocator.free(k_copy);
                            continue;
                        };
                        deleted += 1;
                        matched = true;
                        break;
                    },
                }
            }
        }
        if (!matched) {
            ignored += 1;
        }
    }

    // Delete matched cookies
    for (to_delete.items) |k| {
        if (handle.cookies.fetchRemove(k)) |old| {
            handle.allocator.free(old.key);
            var old_cookie = old.value;
            old_cookie.deinit(handle.allocator);
        }
        handle.allocator.free(k);
    }

    // Persist changes if any deletions occurred
    if (deleted > 0) {
        handle.saveToDisk() catch {
            setError("Failed to persist after rule application");
            return null;
        };
    }

    // Build report JSON
    var buf = std.array_list.Managed(u8).init(handle.allocator);
    defer buf.deinit();
    const writer = buf.writer();
    writer.print("{{\"protected\":{d},\"ignored\":{d},\"deleted\":{d}}}", .{ protected, ignored, deleted }) catch {
        setError("Failed to build report");
        return null;
    };

    const result = handle.allocator.allocSentinel(u8, buf.items.len, 0) catch {
        setError("Out of memory");
        return null;
    };
    @memcpy(result[0..buf.items.len], buf.items);

    clearError();
    return result.ptr;
}

/// Analyse cookies for a given domain.
/// Returns a JSON analysis report with tracking detection, expiry audit, and risk assessment.
pub export fn cookie_rebound_analyse(handle_ptr: ?*anyopaque, domain_ptr: ?[*:0]const u8) callconv(.c) ?[*:0]u8 {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return null;
    };
    const domain_cstr = domain_ptr orelse {
        setError("Null domain");
        return null;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return null;
    }

    const domain = std.mem.span(domain_cstr);
    const now: u64 = @intCast(std.time.timestamp());

    var buf = std.array_list.Managed(u8).init(handle.allocator);
    defer buf.deinit();
    const writer = buf.writer();

    writer.writeAll("{\"domain\":\"") catch return null;
    writeJsonEscaped(writer, domain) catch return null;
    writer.writeAll("\",\"cookies\":[") catch return null;

    var first = true;
    var total_count: u32 = 0;
    var tracker_count: u32 = 0;
    var expired_count: u32 = 0;
    var risk_count: u32 = 0;

    var cookie_iter = handle.cookies.iterator();
    while (cookie_iter.next()) |entry| {
        const cookie = entry.value_ptr;
        if (!std.mem.eql(u8, cookie.domain, domain) and !globMatch(domain, cookie.domain)) {
            continue;
        }

        total_count += 1;
        const is_tracker = isKnownTracker(cookie.domain);
        if (is_tracker) tracker_count += 1;

        const is_expired = if (cookie.expires_at) |exp| exp < now else false;
        if (is_expired) expired_count += 1;

        const cross_site_risk = (cookie.same_site == .none_ss) and !cookie.secure;
        if (cross_site_risk) risk_count += 1;

        const consent = inferConsentCategory(cookie.name, cookie.domain);

        if (!first) {
            writer.writeByte(',') catch return null;
        }

        writer.writeAll("{\"name\":\"") catch return null;
        writeJsonEscaped(writer, cookie.name) catch return null;
        writer.print("\",\"isTracker\":{},\"isExpired\":{},\"crossSiteRisk\":{},\"consentCategory\":{d}}}", .{
            is_tracker,
            is_expired,
            cross_site_risk,
            @intFromEnum(consent),
        }) catch return null;

        first = false;
    }

    writer.print("],\"summary\":{{\"total\":{d},\"trackers\":{d},\"expired\":{d},\"crossSiteRisks\":{d}}}}}", .{
        total_count,
        tracker_count,
        expired_count,
        risk_count,
    }) catch return null;

    const result = handle.allocator.allocSentinel(u8, buf.items.len, 0) catch {
        setError("Out of memory");
        return null;
    };
    @memcpy(result[0..buf.items.len], buf.items);

    clearError();
    return result.ptr;
}

/// Export cookies from vault to a browser cookie file.
/// For Firefox: writes a cookies.txt (Netscape format) to the given profile path.
/// For Chrome: writes a cookies.json (simplified format) to the given profile path.
pub export fn cookie_rebound_export_browser(handle_ptr: ?*anyopaque, browser_type: u32, path_ptr: ?[*:0]const u8) callconv(.c) Result {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const path_cstr = path_ptr orelse {
        setError("Null profile path");
        return .null_pointer;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return .err;
    }

    const profile_path = std.mem.span(path_cstr);
    const browser = std.meta.intToEnum(BrowserType, browser_type) catch {
        setError("Invalid browser type");
        return .invalid_param;
    };

    // Build the output file path
    const filename = switch (browser) {
        .firefox => "cookies_export.txt",
        .chrome => "cookies_export.json",
    };

    var path_buf: [4096]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ profile_path, filename }) catch {
        setError("Profile path too long");
        return .invalid_param;
    };

    // Build output in memory, then write all at once
    var out = std.array_list.Managed(u8).init(handle.allocator);
    defer out.deinit();
    const w = out.writer();

    switch (browser) {
        .firefox => {
            // Netscape cookie file format
            w.writeAll("# Netscape HTTP Cookie File\n# Exported by cookie-rebound\n\n") catch {
                setError("Failed to build export");
                return .out_of_memory;
            };
            var cookie_iter = handle.cookies.iterator();
            while (cookie_iter.next()) |entry| {
                const c = entry.value_ptr;
                const domain_flag = if (std.mem.startsWith(u8, c.domain, ".")) "TRUE" else "FALSE";
                const secure_flag = if (c.secure) "TRUE" else "FALSE";
                const expiry = if (c.expires_at) |exp| exp else 0;

                w.print("{s}\t{s}\t{s}\t{s}\t{d}\t{s}\t{s}\n", .{
                    c.domain, domain_flag, c.path, secure_flag, expiry, c.name, c.value,
                }) catch {
                    setError("Failed to build export");
                    return .out_of_memory;
                };
            }
        },
        .chrome => {
            w.writeAll("[\n") catch {
                setError("Failed to build export");
                return .out_of_memory;
            };
            var first = true;
            var cookie_iter = handle.cookies.iterator();
            while (cookie_iter.next()) |entry| {
                const c = entry.value_ptr;
                if (!first) {
                    w.writeAll(",\n") catch {
                        setError("Failed to build export");
                        return .out_of_memory;
                    };
                }
                const json = c.toJson(handle.allocator) catch {
                    setError("Failed to serialize cookie");
                    return .out_of_memory;
                };
                defer handle.allocator.free(json);
                w.writeAll(json) catch {
                    setError("Failed to build export");
                    return .out_of_memory;
                };
                first = false;
            }
            w.writeAll("\n]\n") catch {
                setError("Failed to build export");
                return .out_of_memory;
            };
        },
    }

    var file = std.fs.cwd().createFile(full_path, .{}) catch {
        setError("Failed to create export file");
        return .storage_error;
    };
    defer file.close();
    file.writeAll(out.items) catch {
        setError("Failed to write export file");
        return .storage_error;
    };

    clearError();
    return .ok;
}

/// Import cookies from a browser profile directory into the vault.
/// For Firefox: reads cookies_export.txt (Netscape format).
/// For Chrome: reads cookies_export.json (JSON array).
pub export fn cookie_rebound_import_browser(handle_ptr: ?*anyopaque, browser_type: u32, path_ptr: ?[*:0]const u8) callconv(.c) Result {
    const ptr = handle_ptr orelse {
        setError("Null handle");
        return .null_pointer;
    };
    const path_cstr = path_ptr orelse {
        setError("Null profile path");
        return .null_pointer;
    };
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    if (!handle.initialized) {
        setError("Handle not initialized");
        return .err;
    }

    const profile_path = std.mem.span(path_cstr);
    const browser = std.meta.intToEnum(BrowserType, browser_type) catch {
        setError("Invalid browser type");
        return .invalid_param;
    };

    const filename = switch (browser) {
        .firefox => "cookies_export.txt",
        .chrome => "cookies_export.json",
    };

    var path_buf: [4096]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ profile_path, filename }) catch {
        setError("Profile path too long");
        return .invalid_param;
    };

    var file = std.fs.cwd().openFile(full_path, .{}) catch {
        setError("Failed to open import file");
        return .storage_error;
    };
    defer file.close();

    switch (browser) {
        .firefox => {
            // Parse Netscape cookie file format — load entire file
            const ff_content = file.readToEndAlloc(handle.allocator, 64 * 1024 * 1024) catch {
                setError("Failed to read import file");
                return .storage_error;
            };
            defer handle.allocator.free(ff_content);

            var line_start: usize = 0;
            for (ff_content, 0..) |ch, idx2| {
                if (ch != '\n' and idx2 != ff_content.len - 1) continue;
                const line_end = if (ch == '\n') idx2 else idx2 + 1;
                const l = ff_content[line_start..line_end];
                line_start = idx2 + 1;
                if (l.len == 0 or l[0] == '#') continue;

                // Parse tab-separated: domain, flag, path, secure, expiry, name, value
                var fields: [7][]const u8 = undefined;
                var field_count: usize = 0;
                var start: usize = 0;
                for (l, 0..) |c, i| {
                    if (c == '\t') {
                        if (field_count < 7) {
                            fields[field_count] = l[start..i];
                            field_count += 1;
                        }
                        start = i + 1;
                    }
                }
                // Last field (no trailing tab)
                if (field_count < 7 and start < l.len) {
                    fields[field_count] = l[start..];
                    field_count += 1;
                }

                if (field_count < 7) continue;

                const expiry_val = std.fmt.parseInt(u64, fields[4], 10) catch 0;
                const now: u64 = @intCast(std.time.timestamp());

                // Build a JSON string and store via parseCookieJson
                var json_buf = std.array_list.Managed(u8).init(handle.allocator);
                defer json_buf.deinit();
                const w = json_buf.writer();
                w.writeAll("{\"name\":\"") catch continue;
                writeJsonEscaped(w, fields[5]) catch continue;
                w.writeAll("\",\"value\":\"") catch continue;
                writeJsonEscaped(w, fields[6]) catch continue;
                w.writeAll("\",\"domain\":\"") catch continue;
                writeJsonEscaped(w, fields[0]) catch continue;
                w.writeAll("\",\"path\":\"") catch continue;
                writeJsonEscaped(w, fields[2]) catch continue;

                const secure = std.mem.eql(u8, fields[3], "TRUE");
                w.print("\",\"secure\":{},\"httpOnly\":false,\"sameSite\":1", .{secure}) catch continue;

                if (expiry_val > 0) {
                    w.print(",\"expiresAt\":{d}", .{expiry_val}) catch continue;
                } else {
                    w.writeAll(",\"expiresAt\":null") catch continue;
                }

                w.print(",\"createdAt\":{d}}}", .{now}) catch continue;

                var cookie = parseCookieJson(json_buf.items, handle.allocator) catch continue;
                const k = cookie.makeKey(handle.allocator) catch {
                    cookie.deinit(handle.allocator);
                    continue;
                };

                // Overwrite existing
                if (handle.cookies.fetchRemove(k)) |old| {
                    handle.allocator.free(old.key);
                    var old_cookie = old.value;
                    old_cookie.deinit(handle.allocator);
                }
                handle.cookies.put(k, cookie) catch {
                    handle.allocator.free(k);
                    cookie.deinit(handle.allocator);
                };
            }
        },
        .chrome => {
            // Read entire file and parse as JSON array of cookie objects
            const content = file.readToEndAlloc(handle.allocator, 10 * 1024 * 1024) catch {
                setError("Failed to read import file");
                return .storage_error;
            };
            defer handle.allocator.free(content);

            // Simple approach: find individual cookie objects by matching braces
            var idx: usize = 0;
            while (idx < content.len) {
                // Find next '{'
                const obj_start = std.mem.indexOfScalarPos(u8, content, idx, '{') orelse break;
                // Find matching '}'
                var depth: i32 = 0;
                var obj_end: usize = obj_start;
                for (content[obj_start..], obj_start..) |c, i| {
                    if (c == '{') depth += 1;
                    if (c == '}') {
                        depth -= 1;
                        if (depth == 0) {
                            obj_end = i + 1;
                            break;
                        }
                    }
                }
                if (obj_end <= obj_start) break;

                const obj_json = content[obj_start..obj_end];
                var cookie = parseCookieJson(obj_json, handle.allocator) catch {
                    idx = obj_end;
                    continue;
                };
                const k = cookie.makeKey(handle.allocator) catch {
                    cookie.deinit(handle.allocator);
                    idx = obj_end;
                    continue;
                };

                if (handle.cookies.fetchRemove(k)) |old| {
                    handle.allocator.free(old.key);
                    var old_cookie = old.value;
                    old_cookie.deinit(handle.allocator);
                }
                handle.cookies.put(k, cookie) catch {
                    handle.allocator.free(k);
                    cookie.deinit(handle.allocator);
                };

                idx = obj_end;
            }
        },
    }

    // Persist imported cookies
    handle.saveToDisk() catch {
        setError("Failed to persist imported cookies");
        return .storage_error;
    };

    clearError();
    return .ok;
}

/// Free a string allocated by cookie_rebound_get / cookie_rebound_list / etc.
pub export fn cookie_rebound_free_string(str_ptr: ?[*:0]u8) callconv(.c) void {
    const s = str_ptr orelse return;
    const allocator = std.heap.c_allocator;
    const slice = std.mem.span(s);
    // Free the sentinel-terminated allocation (len + 1 for null byte)
    allocator.free(slice.ptr[0 .. slice.len + 1]);
}

/// Check if vault handle is initialized.
/// Returns 1 if initialized, 0 otherwise.
pub export fn cookie_rebound_is_initialized(handle_ptr: ?*anyopaque) callconv(.c) u32 {
    const ptr = handle_ptr orelse return 0;
    // SAFETY: handle_ptr came from cookie_rebound_init
    const handle: *VaultHandle = @ptrCast(@alignCast(ptr));
    return if (handle.initialized) 1 else 0;
}

/// Get the library version string (static, do not free).
pub export fn cookie_rebound_version() callconv(.c) [*:0]const u8 {
    return VERSION;
}

/// Get the last error message.
/// Returns null if no error. The returned pointer is valid until the next FFI call.
pub export fn cookie_rebound_last_error() callconv(.c) ?[*:0]const u8 {
    const err = last_error orelse return null;
    const allocator = std.heap.c_allocator;
    const c_str = allocator.allocSentinel(u8, err.len, 0) catch return null;
    @memcpy(c_str[0..err.len], err);
    return c_str.ptr;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "glob matching - exact match" {
    try std.testing.expect(globMatch("example.com", "example.com"));
    try std.testing.expect(!globMatch("example.com", "other.com"));
}

test "glob matching - wildcard" {
    try std.testing.expect(globMatch("*.example.com", "sub.example.com"));
    try std.testing.expect(globMatch("*.example.com", "deep.sub.example.com"));
    try std.testing.expect(!globMatch("*.example.com", "example.com"));
    try std.testing.expect(globMatch("*", "anything.at.all"));
}

test "glob matching - question mark" {
    try std.testing.expect(globMatch("a?c", "abc"));
    try std.testing.expect(!globMatch("a?c", "abbc"));
}

test "json string extraction" {
    const allocator = std.testing.allocator;
    const json = "{\"name\":\"session_id\",\"value\":\"abc123\"}";
    const name = try jsonGetString(json, "name", allocator);
    defer allocator.free(name);
    try std.testing.expectEqualStrings("session_id", name);

    const value = try jsonGetString(json, "value", allocator);
    defer allocator.free(value);
    try std.testing.expectEqualStrings("abc123", value);
}

test "json bool extraction" {
    const json = "{\"secure\":true,\"httpOnly\":false}";
    try std.testing.expect(try jsonGetBool(json, "secure"));
    try std.testing.expect(!try jsonGetBool(json, "httpOnly"));
}

test "json int extraction" {
    const json = "{\"createdAt\":1700000000,\"expiresAt\":null}";
    const created = try jsonGetInt(json, "createdAt");
    try std.testing.expectEqual(@as(?u64, 1700000000), created);
    const expires = try jsonGetInt(json, "expiresAt");
    try std.testing.expectEqual(@as(?u64, null), expires);
}

test "cookie parse and serialize round trip" {
    const allocator = std.testing.allocator;
    const json = "{\"name\":\"test\",\"value\":\"val\",\"domain\":\".example.com\",\"path\":\"/\",\"secure\":true,\"httpOnly\":false,\"sameSite\":1,\"expiresAt\":1800000000,\"createdAt\":1700000000}";

    var cookie = try parseCookieJson(json, allocator);
    defer cookie.deinit(allocator);

    try std.testing.expectEqualStrings("test", cookie.name);
    try std.testing.expectEqualStrings("val", cookie.value);
    try std.testing.expectEqualStrings(".example.com", cookie.domain);
    try std.testing.expectEqualStrings("/", cookie.path);
    try std.testing.expect(cookie.secure);
    try std.testing.expect(!cookie.http_only);
    try std.testing.expectEqual(SameSitePolicy.lax, cookie.same_site);
    try std.testing.expectEqual(@as(?u64, 1800000000), cookie.expires_at);
    try std.testing.expectEqual(@as(u64, 1700000000), cookie.created_at);

    // Serialize back to JSON and verify key fields are present
    const out = try cookie.toJson(allocator);
    defer allocator.free(out);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"name\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"domain\":\".example.com\"") != null);
}

test "rule parse" {
    const allocator = std.testing.allocator;

    // Test integer action
    const json1 = "{\"pattern\":\"*.google.com\",\"action\":0}";
    var rule1 = try parseRuleJson(json1, allocator);
    defer rule1.deinit(allocator);
    try std.testing.expectEqualStrings("*.google.com", rule1.pattern);
    try std.testing.expectEqual(RuleAction.protect, rule1.action);

    // Test string action
    const json2 = "{\"pattern\":\"*.tracker.net\",\"action\":\"delete\"}";
    var rule2 = try parseRuleJson(json2, allocator);
    defer rule2.deinit(allocator);
    try std.testing.expectEqual(RuleAction.delete, rule2.action);
}

test "tracker detection" {
    try std.testing.expect(isKnownTracker("ads.doubleclick.net"));
    try std.testing.expect(isKnownTracker("www.google-analytics.com"));
    try std.testing.expect(!isKnownTracker("www.example.com"));
    try std.testing.expect(!isKnownTracker("github.com"));
}

test "consent category inference" {
    try std.testing.expectEqual(ConsentCategory.analytics, inferConsentCategory("_ga", "www.example.com"));
    try std.testing.expectEqual(ConsentCategory.necessary, inferConsentCategory("CSRF_token", "app.example.com"));
    try std.testing.expectEqual(ConsentCategory.functional, inferConsentCategory("locale", "www.example.com"));
    try std.testing.expectEqual(ConsentCategory.unknown, inferConsentCategory("random_cookie", "www.example.com"));
    try std.testing.expectEqual(ConsentCategory.marketing, inferConsentCategory("anything", "ads.doubleclick.net"));
}

test "vault lifecycle" {
    // Initialize vault
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    try std.testing.expectEqual(@as(u32, 1), cookie_rebound_is_initialized(handle));
}

test "store and retrieve cookie" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    const json = "{\"name\":\"session\",\"value\":\"abc\",\"domain\":\".test.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":true,\"sameSite\":0,\"expiresAt\":null,\"createdAt\":1700000000}";
    const store_result = cookie_rebound_store(handle, json);
    try std.testing.expectEqual(Result.ok, store_result);

    // Retrieve it
    const got = cookie_rebound_get(handle, ".test.com", "session") orelse return error.NotFound;
    defer cookie_rebound_free_string(@constCast(got));

    const got_str = std.mem.span(got);
    try std.testing.expect(std.mem.indexOf(u8, got_str, "\"name\":\"session\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, got_str, "\"domain\":\".test.com\"") != null);

    // Clean up test file
    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
}

test "list cookies by domain" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    _ = cookie_rebound_store(handle, "{\"name\":\"a\",\"value\":\"1\",\"domain\":\".foo.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":false,\"sameSite\":1,\"expiresAt\":null,\"createdAt\":1700000000}");
    _ = cookie_rebound_store(handle, "{\"name\":\"b\",\"value\":\"2\",\"domain\":\".bar.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":false,\"sameSite\":1,\"expiresAt\":null,\"createdAt\":1700000000}");

    // List all
    const all = cookie_rebound_list(handle, "") orelse return error.ListFailed;
    defer cookie_rebound_free_string(@constCast(all));
    const all_str = std.mem.span(all);
    try std.testing.expect(std.mem.indexOf(u8, all_str, "\"name\":\"a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, all_str, "\"name\":\"b\"") != null);

    // List by domain
    const filtered = cookie_rebound_list(handle, ".foo.com") orelse return error.ListFailed;
    defer cookie_rebound_free_string(@constCast(filtered));
    const filtered_str = std.mem.span(filtered);
    try std.testing.expect(std.mem.indexOf(u8, filtered_str, "\"name\":\"a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, filtered_str, "\"name\":\"b\"") == null);

    // Clean up
    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
}

test "delete cookie" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    _ = cookie_rebound_store(handle, "{\"name\":\"del_me\",\"value\":\"x\",\"domain\":\".del.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":false,\"sameSite\":1,\"expiresAt\":null,\"createdAt\":1700000000}");

    const del_result = cookie_rebound_delete(handle, ".del.com", "del_me");
    try std.testing.expectEqual(Result.ok, del_result);

    // Should not be found
    const got = cookie_rebound_get(handle, ".del.com", "del_me");
    try std.testing.expect(got == null);

    // Delete non-existent should return not_found
    const del2 = cookie_rebound_delete(handle, ".del.com", "no_such");
    try std.testing.expectEqual(Result.not_found, del2);

    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
}

test "add and apply protection rules" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    // Store cookies
    _ = cookie_rebound_store(handle, "{\"name\":\"keep\",\"value\":\"1\",\"domain\":\".keep.com\",\"path\":\"/\",\"secure\":true,\"httpOnly\":false,\"sameSite\":0,\"expiresAt\":null,\"createdAt\":1700000000}");
    _ = cookie_rebound_store(handle, "{\"name\":\"tracker\",\"value\":\"2\",\"domain\":\".ads.tracker.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":false,\"sameSite\":2,\"expiresAt\":null,\"createdAt\":1700000000}");

    // Add rules
    const r1 = cookie_rebound_add_rule(handle, "{\"pattern\":\"*.keep.com\",\"action\":\"protect\"}");
    try std.testing.expectEqual(Result.ok, r1);
    const r2 = cookie_rebound_add_rule(handle, "{\"pattern\":\"*.tracker.com\",\"action\":\"delete\"}");
    try std.testing.expectEqual(Result.ok, r2);

    // Apply rules
    const report = cookie_rebound_apply_rules(handle) orelse return error.ApplyFailed;
    defer cookie_rebound_free_string(@constCast(report));
    const report_str = std.mem.span(report);
    try std.testing.expect(std.mem.indexOf(u8, report_str, "\"protected\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, report_str, "\"deleted\":1") != null);

    // Tracker cookie should be gone
    const tracker = cookie_rebound_get(handle, ".ads.tracker.com", "tracker");
    try std.testing.expect(tracker == null);

    // Protected cookie should remain
    const kept = cookie_rebound_get(handle, ".keep.com", "keep");
    try std.testing.expect(kept != null);
    cookie_rebound_free_string(@constCast(kept.?));

    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
    std.fs.cwd().deleteFile(DEFAULT_RULES_FILE) catch {};
}

test "analyse cookies" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    _ = cookie_rebound_store(handle, "{\"name\":\"_ga\",\"value\":\"GA1.2.xxx\",\"domain\":\".example.com\",\"path\":\"/\",\"secure\":false,\"httpOnly\":false,\"sameSite\":2,\"expiresAt\":null,\"createdAt\":1700000000}");

    const analysis = cookie_rebound_analyse(handle, ".example.com") orelse return error.AnalyseFailed;
    defer cookie_rebound_free_string(@constCast(analysis));
    const analysis_str = std.mem.span(analysis);

    // Should have summary section
    try std.testing.expect(std.mem.indexOf(u8, analysis_str, "\"summary\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, analysis_str, "\"total\":1") != null);

    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
}

test "version string" {
    const ver = cookie_rebound_version();
    const ver_str = std.mem.span(ver);
    try std.testing.expectEqualStrings("0.1.0", ver_str);
}

test "null handle operations are safe" {
    try std.testing.expectEqual(Result.null_pointer, cookie_rebound_store(null, "{}"));
    try std.testing.expect(cookie_rebound_get(null, "a", "b") == null);
    try std.testing.expect(cookie_rebound_list(null, "") == null);
    try std.testing.expectEqual(Result.null_pointer, cookie_rebound_delete(null, "a", "b"));
    try std.testing.expectEqual(Result.null_pointer, cookie_rebound_add_rule(null, "{}"));
    try std.testing.expect(cookie_rebound_apply_rules(null) == null);
    try std.testing.expect(cookie_rebound_analyse(null, "x") == null);
    try std.testing.expectEqual(@as(u32, 0), cookie_rebound_is_initialized(null));
    cookie_rebound_free(null); // should not crash
    cookie_rebound_free_string(null); // should not crash
}

test "export and import round trip" {
    const handle = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle);

    // Store a cookie
    _ = cookie_rebound_store(handle, "{\"name\":\"roundtrip\",\"value\":\"test_value\",\"domain\":\".rt.com\",\"path\":\"/app\",\"secure\":true,\"httpOnly\":true,\"sameSite\":0,\"expiresAt\":1900000000,\"createdAt\":1700000000}");

    // Create temp directory for export
    std.fs.cwd().makeDir("_test_export_dir") catch {};
    defer std.fs.cwd().deleteTree("_test_export_dir") catch {};

    // Export to Firefox format
    const exp_result = cookie_rebound_export_browser(handle, 0, "_test_export_dir");
    try std.testing.expectEqual(Result.ok, exp_result);

    // Create a fresh vault and import
    const handle2 = cookie_rebound_init() orelse return error.InitFailed;
    defer cookie_rebound_free(handle2);

    const imp_result = cookie_rebound_import_browser(handle2, 0, "_test_export_dir");
    try std.testing.expectEqual(Result.ok, imp_result);

    // Verify the cookie was imported
    const got = cookie_rebound_get(handle2, ".rt.com", "roundtrip");
    try std.testing.expect(got != null);
    const got_str = std.mem.span(got.?);
    try std.testing.expect(std.mem.indexOf(u8, got_str, "\"value\":\"test_value\"") != null);
    cookie_rebound_free_string(@constCast(got.?));

    std.fs.cwd().deleteFile(DEFAULT_VAULT_FILE) catch {};
}
