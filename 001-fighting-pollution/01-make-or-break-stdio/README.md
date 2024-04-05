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
    var dir = try std.fs.openIterableDirAbsolute("/proc/self/fd", .{});
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
>
> A good example of RCU strategy from daily computer use would be the way Firefox browser forces restart after upgrade.
> It lets the user finish their work in the existing tabs, but shan't allow a new tab to be opened, prompting browser restart.

## Streams of the Multitudes

Looking at the code snippets, you may already understand how does it happen that standard input-outputs of various programs don't cross-pollute.
Let's discuss it with more precision, however. 

First of all, we should be clear that `/dev/console` file we have seen and, indeed, `/dev/pts/19`, aren't regular text files.
Linux kernel defines many file types, making adage of "everything is a file" a bit unnuanced.
Let's annotate these types using Zig standard library:

```zig
    pub const Kind = enum {
        block_device, // Your hard drives and other
                      // possible devices that store
                      // data in fixed-size blocks.
                      // Normally provide random access.

        character_device, // Your keyboards, mice,
                          // serial ports. Devices
                          // that emit and consume
                          // data byte-by-byte.
                          // Random access infrequent.

        directory, // A file that only can refer to
                   // other files. Normal stuff.

        named_pipe, // A more advanced IPC method, out
                    // of scope of this article.

        sym_link, // A file that contains exactly one
                  // reference to another file.
                  // Can be thought of as a "shortcut".

        file, // A byte-aligned file holding some data.
              // This file type is what people imagine
              // when you say "a file". Hence the name.

        unix_domain_socket, // A socket that behaves like
                            // a TCP/IP socket, except is
                            // using file system for data
                            // transfer.

        // ... and some more non-Linux file types 
        // that exist on other UNIXes.
    };
```
_File kinds, per Zig standard library. `lib/zig/std/fs/file.zig`, Zig 0.11._

>Note! The letters `pt` in `pts` stand for "pseudo-terminal", and `s` stands for an archaic word meaning "secondary".
> Pseudo-terminals shouldn't be confused with virtual terminals!
> A virtual terminal is an emulator of a hardware terminal in software.
> Linux without graphical server running such as `wayland` or `X11` creates a bunch of consoles that are connected to their own virtual terminal via `/dev/tty{0,1,...}` devices.
> Pt-main and pt-secondary (named differently in Linux Kernel) are acquired via `openpty()` call from `libc`.
> Virtual terminals are created with `getty()` call from the kernel.

![Two sessions are active and attached to virtual terminals](./01-03-getty.png)

I think you can guess what sort of files are stored in `/dev/pts`, but let's verify it:

```zig
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
```
_A zig program that prints the kinds of the files in a given directory._

The output of this program is as follows:

```
character device: 0
character device: 2
character device: 1
character device: ptmx
```
_An output of `try print_kinds("/dev/pts")`._

Root-owned `ptmx` is the key to how pseudo-terminal devices are created.

```
crw--w---- 1 sweater tty  136,  0 Apr  4 21:46 0
crw--w---- 1 sweater tty  136,  1 Apr  1 03:38 1
crw--w---- 1 sweater tty  136,  2 Apr  1 03:38 2
c--------- 1 root    root   5,  2 Mar 31 06:32 ptmx
```
_An output of `ls -la /dev/pts`._

It's a pseudo-terminal multiplexer.
This is the way all the terminal emulators, such as `alacritty` or `urxvt`, get main and secondary device pairs (named differently in Linux kernel).
Terminal emulator itself then relies on the main device (a device with no path) to orchestrate session management and uses the secondary device to orchestrate input and output.

All of the above considerations explain the following two properties of stdio:

 1. You can't seek stdio, once you flush bytes into a stdio file, they can only be sequentially consumed by a reader.
 2. One does not simply attaches to a pts device file or to a tty file in hopes to be able to read stdio contents.

As a matter of fact, you can conduct the following experiment:

 1. Get `pts` device file of your pseudo-terminal by running `tty`.
 2. Start reading from it with `cat /dev/pts/$pts_id`
 3. Try typing `echo Hello` into your pseudo-terminal.

What you will observe is that your keypresses are *either* consumed by `cat` *or* displayed in your terminal emulator because keypress was communicated to PTM, which told it to redraw, but not both at the same time.
I don't know if you find it to be a funny prank, but the behaviour of the active console is sure confusing.

![Probably a bad prank?..](./01-04-prank.png)

As you can see in the code of your favourite terminal emulator, the secondary pseudo-terminal device, obtained via an `openpty(&main, &secondary, ...)` call shall be exactly the file which is going to be duplicated with `dup2` and serve as *the* stdio file.

```C
int
ttynew(const char *line, char *cmd, const char *out, char **args)
{
    int m, s;

    if (out) {
        term.mode |= MODE_PRINT;
        iofd = (!strcmp(out, "-")) ?
              1 : open(out, O_WRONLY | O_CREAT, 0666);
        if (iofd < 0) {
            fprintf(stderr, "Error opening %s:%s\n",
                out, strerror(errno));
        }
    }

    if (line) {
        if ((cmdfd = open(line, O_RDWR)) < 0)
            die("open line '%s' failed: %s\n",
                line, strerror(errno));
        dup2(cmdfd, 0);
        stty(args);
        return cmdfd;
    }

    /* seems to work fine on linux, openbsd and freebsd */
    if (openpty(&m, &s, NULL, NULL, NULL) < 0)
        die("openpty failed: %s\n", strerror(errno));

    switch (pid = fork()) {
    case -1:
        die("fork failed: %s\n", strerror(errno));
        break;
    case 0:
        close(iofd);
        close(m);
        setsid(); /* create a new process group */
        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        if (ioctl(s, TIOCSCTTY, NULL) < 0)
            die("ioctl TIOCSCTTY failed: %s\n", strerror(errno));
        if (s > 2)
            close(s);
#ifdef __OpenBSD__
        if (pledge("stdio getpw proc exec", NULL) == -1)
            die("pledge\n");
#endif
        execsh(cmd, args);
        break;
    default:
#ifdef __OpenBSD__
        if (pledge("stdio rpath tty proc", NULL) == -1)
            die("pledge\n");
#endif
        close(s);
        cmdfd = m;
        signal(SIGCHLD, sigchld);
        break;
    }
    return cmdfd;
}

size_t
ttyread(void)
{
    static char buf[BUFSIZ];
    static int buflen = 0;
    int ret, written;

    /* append read bytes to unprocessed bytes */
    ret = read(cmdfd, buf+buflen, LEN(buf)-buflen);

    switch (ret) {
    case 0:
        exit(0);
    case -1:
        die("couldn't read from shell: %s\n", strerror(errno));
    default:
        buflen += ret;
        written = twrite(buf, buflen, 0);
        buflen -= written;
        /* keep any incomplete UTF-8 byte sequence for the next call */
        if (buflen > 0)
            memmove(buf, buf + written, buflen);
        return ret;
    }
}

void
ttywrite(const char *s, size_t n, int may_echo)
{
    const char *next;

    if (may_echo && IS_SET(MODE_ECHO))
        twrite(s, n, 1);

    if (!IS_SET(MODE_CRLF)) {
        ttywriteraw(s, n);
        return;
    }

    /* This is similar to how the kernel handles ONLCR for ttys */
    while (n > 0) {
        if (*s == '\r') {
            next = s + 1;
            ttywriteraw("\r\n", 2);
        } else {
            next = memchr(s, '\r', n);
            DEFAULT(next, s + n);
            ttywriteraw(s, next - s);
        }
        n -= next - s;
        s = next;
    }
}
```
_Stdio, writing and reading in suckless terminal. `st.c`, st 0.9._

```C
void
ttywriteraw(const char *s, size_t n)
{
    fd_set wfd, rfd;
    ssize_t r;
    size_t lim = 256;

    /*
     * Remember that we are using a pty, which might be a modem line.
     * Writing too much will clog the line. That's why we are doing this
     * dance.
     * FIXME: Migrate the world to Plan 9.
     */
    while (n > 0) {
        FD_ZERO(&wfd);
        FD_ZERO(&rfd);
        FD_SET(cmdfd, &wfd);
        FD_SET(cmdfd, &rfd);

        /* Check if we can write. */
        if (pselect(cmdfd+1, &rfd, &wfd, NULL, NULL, NULL) < 0) {
            if (errno == EINTR)
                continue;
            die("select failed: %s\n", strerror(errno));
        }
        if (FD_ISSET(cmdfd, &wfd)) {
            /*
             * Only write the bytes written by ttywrite() or the
             * default of 256. This seems to be a reasonable value
             * for a serial line. Bigger values might clog the I/O.
             */
            if ((r = write(cmdfd, s, (n < lim)? n : lim)) < 0)
                goto write_error;
            if (r < n) {
                /*
                 * We weren't able to write out everything.
                 * This means the buffer is getting full
                 * again. Empty it.
                 */
                if (n < lim)
                    lim = ttyread();
                n -= r;
                s += r;
            } else {
                /* All bytes have been written. */
                break;
            }
        }
        if (FD_ISSET(cmdfd, &rfd))
            lim = ttyread();
    }
    return;

write_error:
    die("write error on tty: %s\n", strerror(errno));
}
```
_Funny FIXME. `st.c`, st 0.9._

## Doppelgang Paradox

We already learned that it doesn't happen that three different device files are created for each entity in `stdio`.
But if it's the same file, how come they can be distinguished as data gets flushed into those?
Well, the short answer is that they can't be distinguished.
To a degree that even stdin gets opened with write permissions by default, which means you can write into it.
And indeed, when you write into STDIN, your terminal will behave in the same way as it would if you wrote into STDOUT or STDERR.
Thus, the three are, unsurprisingly, true doppelgangers!

```zig
const std = @import("std");

pub fn main() !void {
    _ = try std.os.write(0, "Hello, world!\n");
}
```
_This program will output "Hello, world!" in your terminal emulator._

However, since the meaning of STDIN being attached to `/dev/pts/$pts_id` is to read user input, which is passed to PTS via PTM as a result of handling keypresses, this write shall be ignored and won't be read by the following program.
The forked child here shall terminate only after a user presses a key, which shall be relayed to the child via STDIN.

```zig
const std = @import("std");

pub fn main() !void {
    const pid = try std.os.fork();

    if (pid == 0) {
        var buf = [_:255]u8{0};
        _ = try std.os.read(0, &buf);
        std.debug.print("Child read: {s}\n", .{buf});
    } else {
        std.os.nanosleep(0, 10_000);
        _ = try std.os.write(0, "Hello, world!\n");
    }
}
```
_This program will crash if you pipe something into it, because the pipe won't be opened for writing!_

Thus, the only way to "un-dopplegang" stdio is to swap out some file descriptors.
The easiest way to do so is by using pipes and redirections while invoking programs from a shell like `bash`.
Observe every stdio file being replaced in the following snippet.

```
λ echo '/dev/pts/ who?' | ls -la /proc/self/fd 2>output.err | tee output.txt
total 0
dr-x------ 2 sweater sweater  0 Apr  5 01:20 ./
dr-xr-xr-x 9 sweater sweater  0 Apr  5 01:20 ../
lr-x------ 1 sweater sweater 64 Apr  5 01:20 0 -> pipe:[8367988]
l-wx------ 1 sweater sweater 64 Apr  5 01:20 1 -> pipe:[8367990]
l-wx------ 1 sweater sweater 64 Apr  5 01:20 2 -> /home/sweater/output.err
lr-x------ 1 sweater sweater 64 Apr  5 01:20 3 -> /proc/26527/fd
```
_Input and output are piped, while stderr is recorded into a regular file. bash 5.0.7._

> Note! `tee` is a very useful program for situations when you need to have an interactive session, traces of which you want to preserve for a later review or further automated manipulation.
> It displays whatever it gets into STDIN into STDOUT, but also records that data into file.
> Use `tee -a` if you want to append to file without overwriting.

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
