const std = @import("std");

pub fn main() !void {
    _ = try std.os.write(0, "Hello, world!\n");
}

// WON'T WORK
// pub fn main() !void {
//     const pid = try std.os.fork();

//     if (pid == 0) {
//         var buf = [_:12]u8{0};
//         _ = try std.os.read(0, &buf);
//         std.debug.print("Child read: {s}\n", .{buf});
//     } else {
//         std.os.nanosleep(0, 10_000);
//         _ = try std.os.write(0, "Hello, world!\n");
//     }
// }

// WON'T WORK
// pub fn main() !void {
//     var args = std.process.args();
//     const bin = args.next() orelse {
//         std.debug.print("illegal argument list, no argv[0]\n", .{});
//         return;
//     };

//     const argv1 = args.next() orelse {
//         std.debug.print("Usage: {s} <filename>\n", .{bin});
//         return;
//     };

//     const pid = try std.os.fork();

//     if (pid == 0) {
//         var buf = [_:12]u8{0};
//         // Open argv[1] and read from it
//         const flags = std.os.O.RDONLY;
//         const fd = try std.os.open(argv1, flags, 0o644);
//         defer std.os.close(fd);
//         // Now read from it:
//         const bsl = try std.os.read(fd, &buf);
//         std.debug.print("Child read: {s} ({any} bytes)\n", .{ buf, bsl });
//     } else {
//         std.os.nanosleep(0, 100_000_000);
//         _ = try std.os.write(0, "Hello, world!\n");
//     }
// }

// This version will work to read one line from STDIN fd 0
// pub fn main() !void {
//     // Simply read a line from terminal emulator by using open() and read()
//     var buf = [_:12]u8{0};
//     const bsl = try std.os.read(0, &buf);
//     std.debug.print("Child read: {s} ({any} bytes)\n", .{ buf, bsl });
// }
