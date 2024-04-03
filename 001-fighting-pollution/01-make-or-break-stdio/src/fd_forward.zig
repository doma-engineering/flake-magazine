const std = @import("std");

pub fn fds(whose: [*:0]const u8) !void {
    // std.debug.print("1", .{});
    var dir = try std.fs.cwd().openIterableDir("/proc/self/fd", .{});
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

pub fn main() !void {
    const message = "Hello, world!\n";
    const flags = std.os.O.WRONLY | std.os.O.CREAT;
    const fd = try std.os.open("./output.txt", flags, 0o644);

    const pid = try std.os.fork();

    if (pid == 0) {
        std.os.nanosleep(0, 100_000_000);
        std.debug.print("[CHILD] Attempting to write to fd.\n", .{});
        try fds("CHILD");
        const result = try std.os.write(fd, message);
        if (result != message.len) {
            std.debug.print("[CHILD] Failed to write to fd.\n", .{});
            std.os.exit(1);
        } else {
            std.debug.print("[CHILD] We do what we must because we can.\n", .{});
            std.os.exit(0);
        }
    } else {
        std.debug.print("[PARENT] Closing fd immediately.\n", .{});
        // Close fd immediately from the parent.
        std.os.close(fd);
        try fds("PARENT");

        const wpr = std.os.waitpid(pid, 0x00000000); // Wait for child process to exit

        // Check if the child exited with an error due to closed STDIN
        if (std.os.W.IFEXITED(wpr.status) and std.os.W.EXITSTATUS(wpr.status) == 0) {
            std.debug.print("[PARENT] This was a triumph.\n", .{});
        }
    }
}
