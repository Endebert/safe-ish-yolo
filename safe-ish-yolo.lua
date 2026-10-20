-- Catastrophic-target guard for the bash tool.
--
-- Refuses the handful of commands that destroy a machine irrecoverably. This
-- runs before the permission system, so YOLO cannot reach past it.
--
-- Analysis is per command node from tree-sitter, not flat text: a destructive
-- verb is only ever judged by its own arguments. Heredoc bodies, printf
-- payloads, and later `&&` segments are separate nodes and cannot poison the
-- scan. Every refusal names the exact argument that triggered it, so the model
-- can fix the command instead of guessing.
--
-- It is a circuit breaker, not a sandbox. A command the parser cannot read, a
-- script with a harmless name, or a destructive line inside an interpreter is
-- not caught. Keep the OS-level boundary for anything that matters.

-- Verbs whose whole purpose is destroying data.
local DESTRUCTIVE = {
  ["rm"] = true,
  ["rmdir"] = true,
  ["shred"] = true,
  ["unlink"] = true,
  ["truncate"] = true,
  ["dd"] = true,
  ["mkfs"] = true,
  ["fdisk"] = true,
  ["parted"] = true,
  ["wipefs"] = true,
  ["srm"] = true,
}

-- Programs that run another program named in their arguments. The verb after
-- one of these is the one that matters, so `env rm -rf ~` reads as `rm`.
-- Only wrappers that take no value before the program: `nice 5 rm` would read
-- `5` as the verb, so `nice` and `timeout` stay out. A wrapper flag that takes
-- a value (`sudo -u root rm`) reads `root` as the verb, which is not
-- destructive, so that form passes: a known blind spot.
local WRAPPER = {
  ["sudo"] = true,
  ["doas"] = true,
  ["env"] = true,
  ["nohup"] = true,
  ["setsid"] = true,
  -- Value-free prefixes that run another program: `command rm -rf x` is
  -- ordinary shell spelling for alias suppression, not an evasion.
  ["exec"] = true,
  ["command"] = true,
  ["builtin"] = true,
  ["time"] = true,
}

-- Directories a delete must never reach. Compared exact-or-descendant, so
-- `/etc` matches `/etc/passwd` while `/etc.bak` is a different name and stays
-- allowed. The `/` entry matches only the literal root path; the other
-- top-level system dirs are listed individually, so `/tmp` and friends stay
-- deletable.
local PROTECTED = {
  "/",
  "/etc",
  "/boot",
  "/dev",
  "/usr",
  "/var",
  "/bin",
  "/lib",
  "/sbin",
  "/home",
  "/root",
  "/proc",
  "/sys",
  "/mnt",
  "/opt",
  "/srv",
}

-- Redirects are writes, not deletes: writing under `/home` or `/var` is daily
-- business, so only these roots make a redirect catastrophic.
local PROTECTED_WRITE = {
  "/",
  "/etc",
  "/boot",
  "/dev",
  "/root",
}

-- Under the home directory: keys and cloud credentials a coding task never
-- needs to touch. Deleting anything anchored at `~` is refused; writes are
-- refused only under these dirs, so editing `~/.bashrc` stays possible.
local PROTECTED_HOME = {
  ".ssh",
  ".gnupg",
  ".aws",
  ".kube",
}

-- Harmless endpoints under a protected root: the discard sinks every build
-- pipeline pipes into. Exact or descendant.
local ALLOWED = {
  "/dev/null",
  "/dev/stdin",
  "/dev/stdout",
  "/dev/stderr",
  "/dev/fd",
}

-- Git forms that discard work with no undo. Matched as subcommand plus flag,
-- because `git clean -n` is a preview and `git checkout -b` is a new branch.
local GIT_DAMAGING = {
  { "reset", "--hard" },
  { "clean", "-f" },
  { "branch", "-D" },
  { "stash", "clear" },
  { "stash", "drop" },
}

-- Command children that are not arguments. Prefix assignments (`FOO=bar rm x`)
-- stay: they ride on the command node but the resolver skips leading words it
-- cannot run either way, so the assignment never reaches a target check.
local NON_ARG = {
  comment = true,
}

-- Node types whose text is a literal token. Quoted text is kept as written;
-- callers strip quotes before path checks and use the type for glob checks.
local TEXTY = {
  word = true,
  string = true,
  raw_string = true,
  simple_expansion = true,
  expansion = true,
  command_substitution = true,
  concatenation = true,
}

local function strip_quotes(text)
  return (text:gsub("[\"']", ""))
end

-- `mkfs.ext4` and `mkfs.xfs` are the same program family as `mkfs`, so match by
-- prefix as well as exactly.
local function is_destructive(verb)
  if DESTRUCTIVE[verb] then
    return verb
  end
  for name in pairs(DESTRUCTIVE) do
    if verb:sub(1, #name + 1) == name .. "." then
      return name
    end
  end
  return nil
end

-- The verb a command node really runs, skipping wrappers and their flags, and
-- its argument words. `sudo rm -rf x` resolves to `rm` with `[-rf, x]`.
-- Compares by text: the name child is a `command_name` wrapper node, not a
-- bare `word`, in tree-sitter-bash.
local function resolve(words)
  local i = 1
  while words[i] do
    local part = words[i]
    if part.type == "variable_assignment" or WRAPPER[part.text] or part.text:sub(1, 1) == "-" then
      i = i + 1
    else
      break
    end
  end
  local head = words[i]
  if not head then
    return nil
  end
  local name = is_destructive(strip_quotes(head.text))
  if not name then
    return nil
  end
  local args = {}
  for j = i + 1, #words do
    args[#args + 1] = words[j]
  end
  return name, args
end

-- The effective verb, wrappers stripped, or nil. `git` skips to its
-- subcommand through wrapper flags like `-C repo`.
local function effective_verb(words)
  local i = 1
  while words[i] do
    local part = words[i]
    if WRAPPER[part.text] or part.text:sub(1, 1) == "-" then
      i = i + 1
    else
      break
    end
  end
  return words[i] and strip_quotes(words[i].text) or nil
end

-- Words of a command node: its name and direct arguments only. Heredoc bodies
-- and later `&&` segments live in other nodes and never enter this list.
-- `concatenation` words keep their unquoted pieces, so a glob character can be
-- told apart from quoted data.
local function words_of(node, source)
  local words = {}
  for _, child in ipairs(node:named_children()) do
    if not NON_ARG[child:type()] then
      local word = { type = child:type(), text = maki.treesitter.get_node_text(child, source) }
      if word.type == "concatenation" then
        word.pieces = {}
        for _, piece in ipairs(child:named_children()) do
          word.pieces[#word.pieces + 1] = {
            type = piece:type(),
            text = maki.treesitter.get_node_text(piece, source),
          }
        end
      end
      words[#words + 1] = word
    end
  end
  return words
end

-- Run fn for every node under root whose type is in {types}, at any depth, so
-- a nested `$(rm -rf /)` is seen too.
local function each_node(root, source, types, fn)
  local function visit(node)
    if types[node:type()] then
      fn(node)
    end
    for _, child in ipairs(node:children()) do
      visit(child)
    end
  end
  visit(root)
end

-- The path a token names: `of=/dev/sda` carries one behind a key, so drop
-- everything up to the last `=`. `if=` names a source rather than a target, so
-- it is read out but not treated as the thing being written.
local function path_of(target)
  if target:match("^if=") then
    return nil
  end
  return target:match("=([^=]*)$") or target
end

local function in_list(path_token, list)
  for _, path in ipairs(list) do
    if path_token == path or path_token:sub(1, #path + 1) == path .. "/" then
      return path
    end
  end
  return nil
end

-- `/a/b/../c` names `/a/c`. Collapse `.` and `..` lexically, no filesystem
-- needed. A `..` that would climb above the root stays at the root.
local function lex_normalize(path_token)
  if not path_token:find(".", 1, true) then
    return path_token
  end
  local absolute = path_token:sub(1, 1) == "/"
  local out = {}
  for seg in path_token:gmatch("[^/]+") do
    if seg == ".." then
      if #out > 0 and out[#out] ~= ".." then
        table.remove(out)
      elseif not absolute then
        out[#out + 1] = ".."
      end
    elseif seg ~= "." then
      out[#out + 1] = seg
    end
  end
  local joined = table.concat(out, "/")
  if absolute then
    return "/" .. joined
  end
  return joined
end

-- for_delete picks the list: deletes guard `/home` and `/var` too, writes only
-- the roots whose corruption bricks the machine.
local function is_protected(target, for_delete)
  local path_token = path_of(target)
  if not path_token then
    return nil
  end
  -- Both expansion spellings point at the home directory: `$HOME/x`,
  -- `${HOME}/x`, `${HOME:-/fallback}/x`.
  path_token = path_token
    :gsub("%$%{HOME[^}]*%}", "~", 1)
    :gsub("%$HOME", "~", 1)
  if in_list(path_token, ALLOWED) then
    return nil
  end
  local hit = in_list(lex_normalize(path_token), for_delete and PROTECTED or PROTECTED_WRITE)
  if hit then
    return hit
  end
  if path_token:sub(1, 1) == "~" then
    for _, dir in ipairs(PROTECTED_HOME) do
      if path_token:find("/" .. dir, 1, true) then
        return "~/" .. dir
      end
    end
    -- Deleting under the home directory wholesale is the mistake; writing a
    -- dotfile there is daily business.
    if for_delete then
      return path_token
    end
  end
  return nil
end

-- An argument that expands to whatever the directory happens to hold: an
-- unquoted wildcard, bare or inside a concatenation like `"$dir"/*` (the glob
-- character is its own node there). Expansion nodes themselves are excluded,
-- so a literal `*` inside quotes stays data.
local function is_glob(part)
  if part.type == "word" then
    return part.text:find("[*?]") ~= nil
  end
  if part.type ~= "concatenation" then
    return false
  end
  for _, piece in ipairs(part.pieces) do
    if piece.type == "word" and piece.text:find("[*?]") ~= nil then
      return true
    end
  end
  return false
end

-- An argument that points at the directory itself.
local function is_self_dir(part)
  local text = strip_quotes(part.text)
  return text == "." or text == ".." or text == "./" or text == "../"
end

-- Matched positionally: the flag must be the word right after the
-- subcommand, so `git stash push -m clear` is a message, not `stash clear`.
local function git_damage(words)
  for _, rule in ipairs(GIT_DAMAGING) do
    for i = 2, #words do
      if strip_quotes(words[i].text) == rule[1] then
        local flag = words[i + 1] and strip_quotes(words[i + 1].text) or ""
        if flag == rule[2] or (flag:sub(1, 1) == "-" and flag:sub(1, #rule[2]) == rule[2]) then
          return rule[1] .. " " .. rule[2]
        end
        break
      end
    end
  end
  return nil
end

-- Returns a reason to refuse the command, or nil to let it run.
local function check(command)
  local parser = maki.treesitter.get_parser(command, "bash")
  if not parser then
    return nil
  end
  local root = parser:parse()[1]:root()
  -- A root-level parse error means the grammar cannot read this input as a
  -- whole (e.g. an extglob elsewhere in the line). Checking per command node
  -- below keeps the guard on the parts that did parse: `rm -rf /etc && echo
  -- @(x)` still refuses the `rm`.


  local deletes = {}
  local gits = {}
  each_node(root, command, { command = true }, function(node)
    -- A node the parser could not read has no trustworthy shape to judge.
    if not node:has_error() then
      local words = words_of(node, command)
      local verb, args = resolve(words)
      if verb then
        deletes[#deletes + 1] = { verb = verb, args = args }
      elseif effective_verb(words) == "git" then
        local damage = git_damage(words)
        if damage then
          gits[#gits + 1] = damage
        end
      end
    end
  end)

  -- Protected delete targets first: the most destructive mistakes.
  for _, call in ipairs(deletes) do
    for _, part in ipairs(call.args) do
      local text = strip_quotes(part.text)
      local hit = is_protected(text, true)
      if hit then
        return ("refused: `%s` argument `%s` targets %s. Run it outside the agent if it is really wanted."):format(
          call.verb,
          text,
          hit
        )
      end
    end
  end

  -- Redirects write files; `file_redirect` covers `>`, `>>`, and `2>`. Its
  -- destination is a sibling of the command, so scan redirects globally.
  local writes = {}
  each_node(root, command, { file_redirect = true }, function(node)
    if not node:has_error() then
      for _, part in ipairs(node:children()) do
        if TEXTY[part:type()] then
          writes[#writes + 1] = maki.treesitter.get_node_text(part, command)
        end
      end
    end
  end)
  for _, target in ipairs(writes) do
    local text = strip_quotes(target)
    local hit = is_protected(text, false)
    if hit then
      return ("refused: redirect to `%s` targets %s. Run it outside the agent if it is really wanted."):format(
        text,
        hit
      )
    end
  end

  if #gits > 0 then
    return ("refused: `git %s` discards work with no undo. Run it outside the agent if it is really wanted."):format(
      gits[1]
    )
  end

  -- Then blind deletes: an unquoted glob, a dot form, or no path at all.
  for _, call in ipairs(deletes) do
    local named = {}
    for _, part in ipairs(call.args) do
      if part.text:sub(1, 1) ~= "-" then
        named[#named + 1] = part
      end
    end
    if #named == 0 then
      return ("refused: `%s` names no path, so it would take the working directory. Name the path."):format(
        call.verb
      )
    end
    for _, part in ipairs(named) do
      if is_glob(part) then
        return ("refused: `%s` argument `%s` is a glob that deletes whatever the pattern matches here. Name the paths."):format(
          call.verb,
          part.text
        )
      end
      if is_self_dir(part) then
        return ("refused: `%s` argument `%s` is the working directory itself. Name the paths."):format(
          call.verb,
          part.text
        )
      end
    end
  end

  return nil
end

maki.api.set_slot("tool.bash.input", function(prev, input, ctx)
  if type(input) == "table" and type(input.command) == "string" then
    -- Fail open: a broken guard must never take every bash call down with it.
    local ok, reason = pcall(check, input.command)
    if not ok then
      maki.log.error("safe-ish-yolo: check raised, allowing command: " .. tostring(reason))
    elseif reason then
      return nil, reason
    end
  end
  return prev(input, ctx)
end)

-- Self-test: every case is a command plus either nil (must pass) or a
-- substring the refusal must contain. Runs on load and reports through
-- maki.log, so `/reload` is verifiable without risking a real deletion.
local SELFTEST = {
  -- The commands session CfxSSuFw5aRewr2hhXXK4 was refused for: an explicit
  -- rm path, plus later segments and payloads full of Rust `use super::*;`.
  -- The `*` is data in other nodes, not a delete argument.
  {
    [[cd /tmp && rm -rf sidecar && cargo new --lib sidecar -q 2>/dev/null; cd sidecar && mkdir -p src/dirmod && cat > src/lib.rs <<'EOF'
pub mod filemod;
mod dirmod;
EOF
cat > src/filemod_tests.rs <<'EOF'
use super::*;
#[test]
fn reaches_private() { assert_eq!(hidden(2), 3); }
EOF
cargo test -q 2>&1 | tail -8]],
    nil,
  },
  {
    [[rm -rf /tmp/sidecar && cargo new --lib /tmp/sidecar -q && cd /tmp/sidecar && printf 'fn hidden(a: u32) -> u32 { a + 1 }
use super::*;
' > src/filemod.rs && printf 'use super::*;
#[test]
fn reaches_private() { assert_eq!(hidden(2), 3); }
' > src/filemod_tests.rs && cargo test -q]],
    nil,
  },
  {
    [[cd /tmp/demo && mkdir -p src/dirmod/tests && rm src/dirmod/tests.rs && printf 'use crate::dirmod::*;
' > src/dirmod/tests/mod.rs && cargo test 2>&1 | rg 'test \w|running|result']],
    nil,
  },
  -- Cross-talk regression: a protected path in a later segment that the
  -- destructive verb never touches, and discard sinks on stderr.
  { [[rm -rf /tmp/build && echo x >> /home/ren/notes.md]], nil },
  { [[rm -rf build 2>/dev/null]], nil },
  { [[echo done > /dev/null && echo err 1>&2]], nil },
  { [[echo x >> ~/.bashrc]], nil },
  { [[cp config ~/.vimrc && echo ok >> ~/.bashrc]], nil },
  { [[ls *]], nil },
  { [[git clean -n]], nil },
  { [[git checkout -b feature]], nil },
  { [[truncate -s 0 bigfile]], nil },
  { [[rm -rf ./target && cargo build]], nil },
  { [[rm -rf "$dir" && mkdir -p "$dir"]], nil },
  { [[FOO=bar rm build/out.o]], nil },
  -- Still refused, with the trigger named.
  { [[rm -rf /]], "argument `/`" },
  { [[rm -rf ~]], "targets ~" },
  { [[rm ~/.bashrc]], "targets ~/.bashrc" },
  { [[rm -rf ~/.ssh/id_ed25519]], "~/.ssh" },
  { [[sudo rm -rf /etc]], "/etc" },
  { [[env rm -rf "$HOME/.aws"]], "~/.aws" },
  { [[dd if=/dev/zero of=/dev/sda bs=1M]], "/dev" },
  { [[cat x > /etc/y]], "targets /etc" },
  { [[echo pwned >> ~/.ssh/authorized_keys]], "~/.ssh" },
  { [[rm *]], "glob" },
  { [[rm -rf build/*.o]], "glob" },
  { [[rm -rf .]], "working directory itself" },
  { [[rm]], "names no path" },
  { [[rm -rf x && rm *]], "argument `*`" },
  { [[git reset --hard]], "git reset --hard" },
  { [[cd repo && git stash drop]], "git stash drop" },
  { [[git branch -D stale]], "git branch -D" },
  { [[foo=$(rm -rf /)]], "argument `/`" },
  -- Regression guards for review fixes: glob inside a concatenation, `${HOME}`
  -- spelling, value-free wrapper prefixes, positional git matching, lexical
  -- `..`, `/` as a plain prefix, and a destructive command next to an
  -- unparseable extglob.
  { [[rm -rf "$dir"/*]], "glob" },
  { [[rm -rf $DIR/*]], "glob" },
  { [[rm -rf ${HOME}/.ssh]], "~/.ssh" },
  { [[exec rm -rf /etc]], "/etc" },
  { [[command rm -rf /etc]], "/etc" },
  { [[git stash push -m clear]], nil },
  { [[sudo git reset --hard]], "git reset --hard" },
  { [[rm -rf /tmp/../etc]], "targets /etc" },
  { [[rm -rf /mnt]], "targets /mnt" },
  { [[rm -rf /etc.bak]], nil },
  { [[rm -rf /etc && echo @(x)]], "targets /etc" },
}

local function selftest()
  local failed = {}
  for i, case in ipairs(SELFTEST) do
    local cmd, expect = case[1], case[2]
    local ok, reason = pcall(check, cmd)
    if not ok then
      failed[#failed + 1] = ("case %d raised %s"):format(i, tostring(reason))
    elseif expect == nil and reason ~= nil then
      failed[#failed + 1] = ("case %d unexpectedly refused: %s"):format(i, tostring(reason))
    elseif expect ~= nil and (type(reason) ~= "string" or not reason:find(expect, 1, true)) then
      failed[#failed + 1] = ("case %d not refused with `%s` (got %s)"):format(i, expect, tostring(reason))
    end
  end
  local total = #SELFTEST
  if #failed == 0 then
    maki.log.info(("safe-ish-yolo: selftest passed (%d cases)"):format(total))
  else
    maki.log.error(("safe-ish-yolo: selftest FAILED %d/%d: %s"):format(#failed, total, table.concat(failed, "; ")))
  end
end

selftest()
