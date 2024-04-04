const std = @import("std");

pub fn print_kinds(from: []const u8) !void {
    var dir = try std.fs.openIterableDirAbsolute(from, .{});
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        // Switch on entry.kind
        switch (entry.kind) {
            .block_device => std.debug.print("block device: {s}\n", .{entry.name}),
            .character_device => std.debug.print("character device: {s}\n", .{entry.name}),
            .directory => std.debug.print("directory: {s}\n", .{entry.name}),
            .named_pipe => std.debug.print("named pipe: {s}\n", .{entry.name}),
            .sym_link => std.debug.print("sym link: {s}\n", .{entry.name}),
            .file => std.debug.print("file: {s}\n", .{entry.name}),
            .unknown => std.debug.print("unknown: {s}\n", .{entry.name}),
            else => std.debug.print("non-linux: {s}\n", .{entry.name}),
        }
    }
}

pub fn main() !void {
    try print_kinds("/dev/pts");
}
