# safe(ish)-yolo

A [maki](https://github.com/tontinton/maki) plugin that refuses the handful of
bash commands that destroy a machine with no undo, even under `--yolo`.

It hooks `tool.bash.input`, which runs before the permission system. A command
this plugin refuses never reaches a prompt and cannot be waved through by YOLO
or `always_yolo`.

## What it blocks

- Deletes (`rm`, `rmdir`, `shred`, `unlink`, `truncate`, `dd`, `mkfs`, `fdisk`,
  `parted`, `wipefs`, `srm`) that name no single path, so they would take the
  working directory: `rm -rf *`, `rm -rf .`, `rm -rf` with no target.
- Deletes that reach a protected path: `/`, `/etc`, `/boot`, `/dev`, `/usr`,
  `/var`, `/bin`, `/lib`, `/sbin`, `/home`, `/root`, and under `$HOME` the
  `.ssh`, `.gnupg`, `.aws` and `.kube` directories.
- `git reset --hard`, `git clean -f`, `git branch -D`, `git stash clear`,
  `git stash drop`. These discard work with no undo.

Wrappers are unwrapped first, so `sudo rm -rf /` reads as `rm`. Both halves of
`cd x && rm -rf /` are read, not just the first.

## What it does not do

This is a circuit breaker, not a sandbox. It reads the command text. It does
not contain the command.

- A destructive line inside a script or an interpreter is not caught.
  `python3 -c "import shutil; shutil.rmtree('/home')"` passes.
- A command the bash parser cannot read is let through. maki already prompts
  for unparseable input, so there is nothing to add there.
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

3. Grant the `run` capability. The plugin reads the command text through the
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
refused: `rm` targets /. Run it outside the agent if it is really wanted.
```

A normal `rm -rf build/` still runs without a prompt.

## Deferred

- The wrapper list covers `sudo`, `doas`, `env`, `nohup`, `setsid`. Wrappers
  that take a value before the program (`nice 5 rm`, `timeout 10 rm`) are left
  out until their flags are parsed.
- The protected list is fixed. It could read the session's real home and
  working directory from the tool context instead.

## License

MIT
