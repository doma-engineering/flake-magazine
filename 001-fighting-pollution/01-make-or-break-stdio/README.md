# Make or Break Standard I/O

Sometimes, while working on complex code bases that are executed in UNIX systems, we need to have different processes communicate with each other.
This approach is broadly called inter-process communication (IPC), and there are many similar but different ways in which this can be achieved.
The most basic one is using standard input/output (stdio) to set up such communication.
In this article we shall take a deep-dive into this approach hoping to demystify it.

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

When `sys_clone()`, a generic process forking routine, which is a macro-wrapper around `kernel_clone()` is called, all the files from the parent process, shall be copied into the child process.
It is done inside the most intricate `copy_process()` function between tracer setup and the information about the newly forked process is relayed to the scheduler.
The function that governs copying the `files_struct` is `copy_files()` and it will do what it says on the tin unless clone argument `no_files` is set (see struct `kernel_clone_args` defined in `sched/task.h`).

Of course, most, if not all, the materials online on `stdio` will tell you, that there are three special files with file descriptors 0, 1, and 2, that get passed from parent to child, but if we look at the process initiation code or, in fact, aforementioned `copy_files` function, we will see that there is no special treatment of any files in `files_struct` whatsoever!

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
_Routine that copies files in the kernel doesn't have any special treatment for stdio. Kernel 6.8.2._

As a matter of fact, we can scour

In the following section, we discuss how stdio files come into existence.

## From Whence You Came

The earliest place where we find our elusive 

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

## Make "bug"

See section 5.7.4 here: https://www.gnu.org/software/make/manual/make.html

## /dev/console on rootfs

Rob is cool btw

https://buildroot.uclibc.narkive.com/rM1I9Jix/where-is-dev-console-created-when-using-devtmpfs#post2
