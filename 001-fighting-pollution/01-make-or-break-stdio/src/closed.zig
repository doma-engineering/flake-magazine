const std = @import("std");

pub fn main() !void {
    // Close standard file descriptors
    std.os.close(0);
    std.os.close(1);
    // std.os.close(2); // Leave STDERR open for debugging

    const pid = try std.os.fork();

    if (pid == 0) {
        const stdin_fd = 0; // STDIN file descriptor
        var buf = [_:1]u8{0};
        _ = std.os.read(stdin_fd, &buf) catch std.os.exit(1);
        std.debug.print("[Child process] Read from STDIN: {s}\n", .{buf});
        std.os.exit(0);
    } else {
        const wpr = std.os.waitpid(pid, 0x00000000); // Wait for child process to exit

        // Check if the child exited with an error due to closed STDIN
        if (std.os.W.IFEXITED(wpr.status) and std.os.W.EXITSTATUS(wpr.status) == 1) {
            std.debug.print("Child process confirmed that STDIN is closed.\n", .{});
        } else {
            std.debug.print("Child process did not behave as expected.\n", .{});
        }
    }
}
