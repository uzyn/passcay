const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const passcay = b.dependency("passcay", .{ .target = target, .optimize = optimize });
    const passcay_mod = passcay.module("passcay");

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("passcay", passcay_mod);

    // Autonomous replay harness (Layer B) — drives the conformance endpoints
    // directly, no HTTP transport required. Run with `zig build test`.
    const replay_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/replay.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    replay_tests.root_module.addImport("passcay", passcay_mod);
    replay_tests.root_module.addImport("server", server_mod);

    const run_replay = b.addRunArtifact(replay_tests);
    const test_step = b.step("test", "Run conformance replay tests");
    test_step.dependOn(&run_replay.step);

    // HTTP server shell (for the official FIDO Conformance Tool run).
    const httpz = b.dependency("httpz", .{ .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{
        .name = "conformance-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("passcay", passcay_mod);
    exe.root_module.addImport("httpz", httpz.module("httpz"));
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the conformance HTTP server");
    run_step.dependOn(&run_cmd.step);
}
