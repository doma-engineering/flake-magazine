# Flake Magazine #001: Fighting Pollution

Editor's note:

I think that it would be a nice idea to have a common theme, which is then roughly related to most of the articles within an issue.

We can also write something wholesome about how we want our magazine to be a sourc of quality content in the era of information pollution.

The articles I want to write are:

- IPC via STDIO, tools that pollute STDOUT and how to work around it.
- Running the same service many times on the same machine with zero code overhead with transient Docker networks.

## Tips in the issue:

- nativeBuildInputs to remove the pollution of `LD_LIBRARY_PATH` and other variables.
- `/filter add irc_smart * irc_smart_filter *` and `/set irc.look.smart_filter_delay 5` remove service message pollution in weechat IRC client.
- Use `inline for` in zig to get around compile-time unknown items. (Useful in build programs).
