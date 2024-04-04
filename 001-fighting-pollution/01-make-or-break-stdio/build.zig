const std = @import("std");

pub fn build(b: *std.Build) void {

    ////////////////////////////////////
    ///////////// BINARIES /////////////
    ////////////////////////////////////

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Define an array of structs containing the executable name and source path
    const executables = [_]struct { name: []const u8, source_path: []const u8 }{
        .{ .name = "01-make-or-break-stdio", .source_path = "src/main.zig" },
        .{ .name = "01A-closed-stdio", .source_path = "src/closed.zig" },
        .{ .name = "01B-fd-forward", .source_path = "src/fd_forward.zig" },
        .{ .name = "01B-whatis-pts", .source_path = "src/pts.zig" },
        // Add more executables here
    };

    // Iterate over the executables array and create each executable
    inline for (executables) |exe| {
        const exe_full = b.addExecutable(.{ .name = exe.name, .root_source_file = .{ .path = exe.source_path }, .target = target, .optimize = optimize });

        b.installArtifact(exe_full);

        const run_cmd = b.addRunArtifact(exe_full);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        // Here we use string concatenation within a comptime block, so it's allowed.
        const run_step_name = "run-" ++ exe.name;
        const run_step_desc = "Run " ++ exe.name;
        const run_step = b.step(run_step_name, run_step_desc);
        run_step.dependOn(&run_cmd.step);
    }

    ////////////////////////////////////
    //////////// UNIT TESTS ////////////
    ////////////////////////////////////

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
