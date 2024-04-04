# Make or Break Standard I/O

Sometimes, while working on complex code bases that are executed in UNIX systems, we need to have different processes communicate with each other.
This approach is broadly called inter-process communication (IPC), and there are many similar but different ways in which this can be achieved.
The most basic one is using standard input/output (stdio) to set up such communication.
In this article we shall take a deep-dive into this approach hoping to demystify it.

The practical benefit of using this article is that we use Zig code snippets in this article to illustrate the concepts.
If you always were interested in what this language looks like and how to work with it, this article is for you.

## Files!

If there was a UNIX musical ever made, in the tradition of punchy single-word musical names, it would be called "Files!".
There is an old adage that everything in UNIX is a file.
It certainly holds true for stdio.
In Linux, every process has a data structure called `files_struct`, which holds `fdtable`, which provides a low-level interface to all the file descriptors currently associated with said process.

```C
/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *files_lookup_fd_raw(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned long mask = array_index_mask_nospec(fd, fdt->max_fds);
	struct file *needs_masking;

	/*
	 * 'mask' is zero for an out-of-bounds fd, all ones for ok.
	 * 'fd&mask' is 'fd' for ok, or 0 for out of bounds.
	 *
	 * Accessing fdt->fd[0] is ok, but needs masking of the result.
	 */
	needs_masking = rcu_dereference_raw(fdt->fd[fd&mask]);
	return (struct file *)(mask & (unsigned long)needs_masking);
}
```
_Low-level file descriptor lookup. `include/linux/fdtable.h`, Kernel v6.8.2._

Note that it stores the descriptors of all the files, not just the open ones.
Kernel routines can verify if a file is open by calling `fd_is_open(unsigned int fd, const struct fdtable *fdt)` on a given file descriptor table.

> Hint! If you want to easily look up and cross-reference identifiers in Linux kernel, you can use Bootlin cross-referencer, hosted over at https://elixir.bootlin.com/linux/v6.8.2/source.

![Elixir Cross-Referencer](./01-01-elixir.png)

When `sys_clone()`, a generic process forking routine, which is a macro-wrapper around `kernel_clone()` is called, all the files from the parent process, shall be copied into the child process.
It is done inside the most intricate `copy_process()` function between tracer setup and the information about the newly forked process is relayed to the scheduler.
The function that governs copying the `files_struct` is `copy_files()` and it will do what it says on the tin unless clone argument `no_files` is set (see struct `kernel_clone_args` defined in `sched/task.h`).

To illustrate the semantics of `copy_files()`, let's have a look at the following Zig code:

```zig
const std = @import("std");

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

// Dummy function to print active file descriptors, ignore for the time being
pub fn fds(_: [*:0]const u8) !void {}
```

You see that we fork a process here and let the parent process close `output.txt` by waiting in the child for 100 milliseconds.
As we described above, the files are copied to the child at fork time, so it doesn't matter that the file is closed by parent.
The child has the copied file "alive", so `fd` resolves to an open file in `files_struct`.

To illustrate this point further, we would like to query `files_struct`, but to my knowledge we can't do it with `libc` facilities or otherwise.
We can, however, get the information about the file descriptors tracked by kernel by querying `/proc/self/fd`. 
Let's implement the dummy `fds` function from the previous example.

```zig
pub fn fds(whose: [*:0]const u8) !void {
    var dir = try std.fs.cwd().openIterableDir("/proc/self/fd", .{});
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind == .sym_link) {
            var resolved_path: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const sl_resolved_path = try std.os.readlinkat(dir.dir.fd, entry.name, &resolved_path);
            std.debug.print("[{s}] FD {s}: {s}\n", .{ whose, entry.name, sl_resolved_path });
        }
    }
}
```

As we run this in a clean terminal, we get output that confirms that `output.txt` was, indeed, closed from the parent process.

```
λ zig build run-01B-fd-forward && cat output.txt
[PARENT] Closing fd immediately.
[PARENT] FD 0: /dev/pts/19
[PARENT] FD 1: /dev/pts/19
[PARENT] FD 2: /dev/pts/19
[PARENT] FD 3: /proc/455/fd
[CHILD] Attempting to write to fd.
[CHILD] FD 0: /dev/pts/19
[CHILD] FD 1: /dev/pts/19
[CHILD] FD 2: /dev/pts/19
[CHILD] FD 3: /home/sweater/flake-mag/001/01/output.txt
[CHILD] FD 4: /proc/456/fd
[CHILD] We do what we must because we can.
[PARENT] This was a triumph.
Hello, world!
```

You can see that file descriptors 0, 1, and 2 are set both for parent and the child.
Of course, most, if not all, the materials online on `stdio` will tell you that these are three special files that get passed from parent to child.
But if we look at the process initiation code or, in fact, aforementioned `copy_files` function, we will see that there is no special treatment of any files in `files_struct` whatsoever!

```C
static int copy_files(unsigned long clone_flags, struct task_struct *tsk,
		      int no_files)
{
	struct files_struct *oldf, *newf;
	int error = 0;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;

	if (no_files) {
		tsk->files = NULL;
		goto out;
	}

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	newf = dup_fd(oldf, NR_OPEN_MAX, &error);
	if (!newf)
		goto out;

	tsk->files = newf;
	error = 0;
out:
	return error;
}
```
_Routine that copies files in the kernel doesn't have any special treatment for stdio. `kernel/fork.c`, Kernel 6.8.2._

As a matter of fact, we can scour the entirety of kernel codebase responsible for files and processes for stdio-related stuff, we will find naught.

In the following section, we discuss how stdio files actually come into existence.

## From Whence You Came

![From Whence You Came](./01-01-from-whence.jpg)

The earliest place where we find our elusive stdio files is `console_on_rootfs()` function.
As the kernel gets unpacked (`head.S` -> `start_kernel` -> `...`), a file `/dev/console` gets populated by initramfs.
Afterwards, this file gets multiplexed into three file descriptors and an early console driver will use it to organise its stdio.

```
/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
	struct file *file = filp_open("/dev/console", O_RDWR, 0);

	if (IS_ERR(file)) {
		pr_err("Warning: unable to open an initial console.\n");
		return;
	}
	init_dup(file);
	init_dup(file);
	init_dup(file);
	fput(file);
}
```
_Early console is the first place where stdio appears during Linux boot process. `init/main.c`, Kernel 6.8.2._

> Note! While normally stdio is populated using `dup2()` system call (see below), early console setup does it differently.
> It uses a custom file descriptor duplication technique to prevent race conditions.
> Under the hood, it uses read-copy-update (RCU) synchronization mechanism which:
> 1. Removes the pointer to the early file descriptor table, preventing new read attempts.
> 2. Waits for its readers to complete critical sections of working with the data behind the original pointer.
> 3. Frees (or otherwise rearranges) memory section after all the existing readers reported that their critical sections are completed.

## Doppelgang Paradox

Q: If stderr is stdout is stdin, how come they can be distinguished as stuff gets output into those?
A: It can't unless you reattach fds to something else.

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

## Make "bug"

See section 5.7.4 here: https://www.gnu.org/software/make/manual/make.html

## /dev/console on rootfs

Rob is cool btw

https://buildroot.uclibc.narkive.com/rM1I9Jix/where-is-dev-console-created-when-using-devtmpfs#post2
