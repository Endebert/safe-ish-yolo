# safe(ish)-yolo

A [maki](https://github.com/tontinton/maki) plugin that refuses the handful of
bash commands that destroy a machine with no undo, even under `--yolo`.

It hooks `tool.bash.input`, which runs before the permission system. A command
this plugin refuses never reaches a prompt and cannot be waved through by YOLO
or `always_yolo`.

## What it blocks

- Deletes (`rm`, `rmdir`, `shred`, `unlink`, `truncate`, `dd`, `mkfs`, `fdisk`,
  `parted`, `wipefs`, `srm`) that name no single path, so they would take the
  working directory: `rm -rf *`, `rm -rf "$dir"/*`, `rm -rf .`, `rm -rf` with
  no target.
- Deletes that reach a protected path: `/`, `/etc`, `/boot`, `/dev`, `/usr`,
  `/var`, `/bin`, `/lib`, `/sbin`, `/home`, `/root`, `/proc`, `/sys`, `/mnt`,
  `/opt`, `/srv`, and under `$HOME` / `${HOME}` the `.ssh`, `.gnupg`, `.aws`
  and `.kube` directories. `..` segments are collapsed first, so
  `rm -rf /tmp/../etc` still reads as `/etc`.
- Redirects (`>`, `>>`, `2>`) that write over `/`, `/etc`, `/boot`, `/dev` or
  `/root`, while `/dev/null` and friends stay allowed.
- `git reset --hard`, `git clean -f`, `git branch -D`, `git stash clear`,
  `git stash drop`. These discard work with no undo.

Wrappers are unwrapped first, so `sudo rm -rf /` and `command rm -rf /` read as
`rm`. Both halves of `cd x && rm -rf /` are read, not just the first. Analysis
runs per command node of the tree-sitter-bash parse, so heredoc bodies,
`printf` payloads, and later `&&` segments cannot poison the scan.

## What it does not do

This is a circuit breaker, not a sandbox. It reads the command's parse tree. It
does not contain the command.

- A destructive line inside a script or an interpreter is not caught.
  `python3 -c "import shutil; shutil.rmtree('/home')"` passes. Runner payloads
  pass too: `xargs rm -rf /etc`, `find / -delete`, `find . -exec rm ... \;`.
- A command node the parser cannot read is skipped, fail-open: an unparseable
  extglob elsewhere in the line does not disable the rest (`rm -rf /etc && echo
  @(x)` still refuses the `rm`), but a destructive verb inside such a node is
  not judged.
- Program arguments that write without a redirect are not guarded:
  `cp y /etc/y`, `tee /etc/passwd`, `install` into a protected root pass; only
  shell redirects over those roots are refused.
- It only guards the bash tool. Writes, edits, and any other tool are outside
  it.

Keep the OS boundary (a container, a VM, a separate user) for anything that
matters. This plugin raises the cost of the common accident, nothing more.

## Install

1. Copy the module into maki's config dir:

   ```sh
   mkdir -p ~/.config/maki/lua
   cp safe-ish-yolo.lua ~/.config/maki/lua/safe-ish-yolo.lua
   ```

2. Load it from `~/.config/maki/init.lua`:

   ```lua
   require("safe-ish-yolo")
   ```

3. Grant the `run` capability. The plugin reads the command through the
   bash tool's input slot, which needs the permission that tool declares. Add a
   `plugin.toml` next to `init.lua`, or add these lines to the one you have:

   ```toml
   [permissions]
   run = true
   ```

   Without this the slot is skipped and the plugin silently does nothing.

4. Run `/reload`, or restart maki.

## Verify

Ask the agent to run `rm -rf /`. It comes back with:

```
refused: `rm` argument `/` targets /. Run it outside the agent if it is really wanted.
```

A normal `rm -rf build/` still runs without a prompt.

## Deferred

- The wrapper list covers `sudo`, `doas`, `env`, `nohup`, `setsid`, plus the
  value-free prefixes `exec`, `command`, `builtin`, `time`. Wrappers that take
  a value before the program (`nice 5 rm`, `timeout 10 rm`) are left out
  until their flags are parsed, and a flag that takes a value
  (`sudo -u root rm`) still reads `root` as the verb.
- Runner payloads (`xargs rm`, `find -delete`, `find -exec`) and write programs
  without a redirect (`cp`, `tee`, `install` into a protected root) are not
  unwrapped yet.
- The protected list is fixed. It could read the session's real home and
  working directory from the tool context instead.
- A load-time selftest (44 cases) logs `selftest passed` to maki's log; check
  `~/.local/logs/maki/maki.log` after `/reload`.

## License

MIT
