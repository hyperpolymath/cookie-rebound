// Cookie Rebound FFI Build Configuration
// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create the root module used by library and tests
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Shared library (.so, .dylib, .dll)
    const lib = b.addLibrary(.{
        .name = "cookie_rebound",
        .root_module = root_module,
        .linkage = .dynamic,
    });
    b.installArtifact(lib);

    // Static library (.a)
    const lib_static = b.addLibrary(.{
        .name = "cookie_rebound",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .linkage = .static,
    });
    b.installArtifact(lib_static);

    // Unit tests (run tests embedded in main.zig)
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const lib_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run library unit tests");
    test_step.dependOn(&run_lib_tests.step);

    // Integration tests
    const integration_mod = b.createModule(.{
        .root_source_file = b.path("test/integration_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    integration_mod.addImport("cookie_rebound", root_module);

    const integration_tests = b.addTest(.{
        .root_module = integration_mod,
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);

    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    // All tests
    const all_test_step = b.step("test-all", "Run all tests (unit + integration)");
    all_test_step.dependOn(&run_lib_tests.step);
    all_test_step.dependOn(&run_integration_tests.step);
}
