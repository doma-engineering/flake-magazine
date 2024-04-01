# Make or Break Standard I/O

Sometimes, while working on complex code bases that are executed in UNIX systems, we need to have different processes communicate with each other.
This approach is broadly called inter-process communication (IPC), and there are many similar but different ways in which this can be achieved.
The most basic one is using standard input/output (stdio) to set up such communication.
In this article we shall focus on this approach.

## Standard Who?

## Deep-dive

## From Whence You Came

We have seen that there is nothing special about these file descriptors aside from the fact that they are inherited by children processes of a given process.
But where do these file descriptors come from in the first place?
For some reason this is not a question that is easy to find an answer to.
A short answer -- they get created before the userspace TODO.
head.S -> start_kernel -> ... console_on_rootfs.

To answer it, let's briefly recap the way modern Linux TODO.

### Then Why Don't STDINs of Different Terminal Windows Pollute Each Other?

TODO explore and explain the source code that shows how pty sets up fd 0, 1, 2.

TODO explore and explain the source code that shows how terminal emulators, for example `st` (suckless terminal) sets up /dev/pts/XX and links fd 0, 1, 2 to it

---

# Notes & Sketches

## Zig on I/O

Almost echoing my words about how fundamental of a concept I/O is in UNIX, Zig's hello world is talking about how important it is not to pollute stdout.

```zig
const std = @import("std");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
}
```

## To investigate kernel list, use bootlin indexer

https://elixir.bootlin.com/linux/latest/C/ident/console_on_rootfs

## Style of this Article

Is inspired by "The Little X"

## Agetty

https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/v2.7.1/login-utils/agetty.c
