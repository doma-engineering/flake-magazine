const std = @import("std");

pub fn main() !void {
    try fds("PARENT_BEFORE");
    // Close standard file descriptors
    std.os.close(0);
    try fds("PARENT_NO_STDIN");
    std.os.close(1);
    try fds("PARENT_NO_STDOUT");
    // std.os.close(2); // Leave STDERR open for debugging

    const pid = try std.os.fork();

    if (pid == 0) {
        try fds("CHILD");
        const stdin_fd = 0; // STDIN file descriptor
        var buf = [_:1]u8{0};
        std.debug.print("[CHILD] Attempting to read from STDIN...\n", .{});
        _ = std.os.read(stdin_fd, &buf) catch std.os.exit(1);
        std.debug.print("[CHILD] Read from STDIN: {s}\n", .{buf});
        std.os.exit(0);
    } else {
        try fds("PARENT_AFTER");
        const wpr = std.os.waitpid(pid, 0x00000000); // Wait for child process to exit

        // Check if the child exited with an error due to closed STDIN
        if (std.os.W.IFEXITED(wpr.status) and std.os.W.EXITSTATUS(wpr.status) == 1) {
            std.debug.print("[PARENT] Child process confirmed that STDIN is closed.\n", .{});
        } else {
            std.debug.print("[PARENT] Child process did not behave as expected.\n", .{});
        }
    }
}

pub fn fds(whose: [*:0]const u8) !void {
    // std.debug.print("1", .{});
    var dir = try std.fs.openIterableDirAbsolute("/proc/self/fd", .{});
    // std.debug.print("2", .{});
    defer dir.close();

    var it = dir.iterate();
    // std.debug.print("3", .{});
    while (try it.next()) |entry| {
        // std.debug.print("4", .{});
        if (entry.kind == .sym_link) {
            // std.debug.print("5", .{});
            var resolved_path: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const sl_resolved_path = try std.os.readlinkat(dir.dir.fd, entry.name, &resolved_path);
            // std.debug.print("6", .{});
            // const path = resolved_path[0..len];
            std.debug.print("[{s}] FD {s}: {s}\n", .{ whose, entry.name, sl_resolved_path });
            // std.debug.print("7", .{});
        }
    }
}
