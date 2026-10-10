-- Catastrophic-target guard for the bash tool.
--
-- Refuses the handful of commands that destroy a machine irrecoverably. This
-- runs before the permission system, so YOLO cannot reach past it.
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
-- `5` as the verb, so `nice` and `timeout` stay out until arguments are parsed.
-- braid: next-word, surpass with wrapper-specific flag parsing
local WRAPPER = {
  ["sudo"] = true,
  ["doas"] = true,
  ["env"] = true,
  ["nohup"] = true,
  ["setsid"] = true,
}

-- Directories a delete must never reach. Compared exact-or-descendant, so
-- `/etc` matches `/etc/passwd` and `/` matches every absolute path.
-- braid: fixed list, surpass with the session's real home and cwd from ctx
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
}

-- Under the home directory: keys and cloud credentials a coding task never
-- needs to delete.
local PROTECTED_HOME = {
  ".ssh",
  ".gnupg",
  ".aws",
  ".kube",
}

-- The verb a command runs, skipping wrappers and their flags. Works on the
-- flat text because a wrapper's target is an argument to the wrapper, not a
-- nested node the tree would hand back on its own.
local function verb_of(text)
  local rest = text
  while true do
    local word, tail = rest:match("^%s*(%S+)%s*(.*)$")
    if not word then
      return nil
    end
    if WRAPPER[word] then
      rest = tail
    elseif word:sub(1, 1) == "-" then
      rest = tail
    else
      return word
    end
  end
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

local function verbs(command)
  local found = {}
  for segment in command:gmatch("[^;&|\n]+") do
    local verb = verb_of(segment)
    if verb then
      found[#found + 1] = verb
    end
  end
  return found
end

local function targets(command)
  local out = {}
  for token in command:gmatch("%S+") do
    local word = token:gsub("^['\"]", ""):gsub("['\"]$", "")
    -- `of=/dev/sda` hides the path behind a key, so scan the whole token for a
    -- slash rather than only its first character.
    if word:find("/", 1, true) or word:find("~", 1, true) or word:find("$HOME", 1, true) then
      out[#out + 1] = word
    end
  end
  return out
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

local function is_protected(target)
  local path_token = path_of(target)
  if not path_token then
    return nil
  end
  for _, path in ipairs(PROTECTED) do
    if path_token == path or path_token:sub(1, #path + 1) == path .. "/" then
      return path
    end
  end
  if path_token:sub(1, 1) == "~" or path_token:find("$HOME", 1, true) then
    for _, dir in ipairs(PROTECTED_HOME) do
      if path_token:find("/" .. dir, 1, true) then
        return "~/" .. dir
      end
    end
    return path_token
  end
  return nil
end

-- Git forms that discard work with no undo. Matched as subcommand plus flag,
-- because `git clean -n` is a preview and `git checkout -b` is a new branch.
local GIT_DAMAGING = {
  { "reset", "--hard" },
  { "clean", "-f" },
  { "branch", "-D" },
  { "stash", "clear" },
  { "stash", "drop" },
}

-- A delete whose target is a directory form rather than something inside one:
-- a glob, a dot form, a traversal, or nothing at all. Those act on whatever the
-- working directory happens to hold, which is the mistake worth one prompt.
local function is_blind(target)
  if target == nil or target == "" then
    return true
  end
  if target:find("[*?]") then
    return true
  end
  return target == "." or target == ".." or target == "./" or target == "../"
end

-- The targets a delete names, flags excluded.
local function delete_targets(command)
  local out = {}
  local seen_verb = false
  for word in command:gmatch("%S+") do
    if seen_verb then
      if word:sub(1, 1) ~= "-" then
        out[#out + 1] = word
      end
    elseif is_destructive(word) then
      seen_verb = true
    end
  end
  return out
end

local function damaging_git(command)
  -- Every segment, not just the first: `cd x && git reset --hard` hides the
  -- git in the second one.
  for segment in command:gmatch("[^;&|\n]+") do
    local words = {}
    for word in segment:gmatch("%S+") do
      words[#words + 1] = word
    end
    if words[1] == "git" then
      for _, rule in ipairs(GIT_DAMAGING) do
        local sub, flag = rule[1], rule[2]
        for i = 2, #words do
          if words[i] == sub then
            for j = i + 1, #words do
              if words[j] == flag or words[j]:find("^" .. flag) then
                return sub .. " " .. flag
              end
            end
          end
        end
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
  -- A command maki's own parser cannot read already forces a prompt, so there
  -- is nothing to add here.
  if root:has_error() then
    return nil
  end

  local destructive
  for _, verb in ipairs(verbs(command)) do
    destructive = is_destructive(verb)
    if destructive then
      break
    end
  end

  if destructive then
    for _, target in ipairs(targets(command)) do
      local hit = is_protected(target)
      if hit then
        return ("refused: `%s` targets %s. Run it outside the agent if it is really wanted."):format(
          destructive,
          hit
        )
      end
    end
  end

  local git = damaging_git(command)
  if git then
    return ("refused: `git %s` discards work with no undo. Run it outside the agent if it is really wanted."):format(
      git
    )
  end

  if destructive then
    local named = delete_targets(command)
    local blind = #named == 0
    if not blind then
      for _, target in ipairs(named) do
        if is_blind(target) then
          blind = true
        end
      end
    end
    if blind then
      return ("refused: `%s` names no single path, so it would take the working directory. Name the path."):format(
        destructive
      )
    end
  end

  return nil
end

maki.api.set_slot("tool.bash.input", function(prev, input, ctx)
  if type(input) == "table" and type(input.command) == "string" then
    local reason = check(input.command)
    if reason then
      return nil, reason
    end
  end
  return prev(input, ctx)
end)
