const std = @import("std");

pub fn main() !void {
    // const allocator = std.heap.page_allocator;

    // Close standard file descriptors
    std.os.close(0);
    std.os.close(1);
    // std.os.close(2); // Leave STDERR open for debugging

    const pid = try std.os.fork();

    if (pid == 0) {
        // Open the directory as an IterableDir
        var dir = try std.fs.cwd().openIterableDir("/proc/self/fd", .{});
        defer dir.close();

        // Get an iterator from the IterableDir
        var it = dir.iterate();

        // Iterate over the directory entries
        while (try it.next()) |entry| {
            std.debug.print("[Child process] /proc/self/fd: {s}\n", .{entry.name});
        }

        // const message = "[Child process] Hello\n";
        // const stdout_fd = 1; // STDOUT file descriptor
        // _ = std.os.write(stdout_fd, message) catch std.os.exit(1);
        const stdin_fd = 0; // STDIN file descriptor
        var buf = [_:1]u8{0};
        _ = std.os.read(stdin_fd, &buf) catch std.os.exit(1);
        std.debug.print("[Child process] Read from STDIN: {s}\n", .{buf});
        std.os.exit(0);
    } else {
        // Parent process
        const wpr = std.os.waitpid(pid, 0x00000000); // Wait for child process to exit

        // debug wpr
        // std.debug.print("wpr: {}; IFEXITED: {}; EXITSTATUS: {}\n", .{ wpr, std.os.W.IFEXITED(wpr.status), std.os.W.EXITSTATUS(wpr.status) });

        // Check if the child exited with an error due to closed STDOUT
        if (std.os.W.IFEXITED(wpr.status) and std.os.W.EXITSTATUS(wpr.status) == 1) {
            std.debug.print("Child process confirmed that STDIN is closed.\n", .{});
        } else {
            std.debug.print("Child process did not behave as expected.\n", .{});
        }
    }
}
