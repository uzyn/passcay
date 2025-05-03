const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.

/// Helper function to configure OpenSSL
/// This function just does basic system library linking since we'll use the native OpenSSL
fn linkWithOpenSSL(_: *std.Build, step: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    // Always link with libc
    step.linkLibC();

    // Link with OpenSSL libraries
    step.linkSystemLibrary("crypto");
    step.linkSystemLibrary("ssl");

    // Add special frameworks for macOS
    if (target.result.os.tag == .macos) {
        // step.linkFramework("Security");
        // step.linkFramework("CoreFoundation");
    }
}

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Add dependencies
    const zbor_dep = b.dependency("zbor", .{
        .target = target,
        .optimize = optimize,
    });
    const zbor_mod = zbor_dep.module("zbor");

    // Create and add the passcay module to the build so it can be referenced as a dependency
    const passcay_mod = b.addModule("passcay", .{
        .root_source_file = b.path("src/public.zig"),
        .target = target,
        .optimize = optimize,
    });
    passcay_mod.addImport("zbor", zbor_mod);

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "passcay",
        .root_module = passcay_mod,
    });

    // Link with OpenSSL dynamically
    linkWithOpenSSL(b, lib, target);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/test_entry.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests.root_module.addImport("zbor", zbor_mod);

    // Link with OpenSSL for tests
    linkWithOpenSSL(b, lib_unit_tests, target);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
