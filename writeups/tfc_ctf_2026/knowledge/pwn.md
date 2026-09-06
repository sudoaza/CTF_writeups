# Pwn techniques

## Common styles
- Netcat binary; buffer overflow -> ret2win/ROP; format string; heap (tcache); shellcode.

## Key techniques
1. Recon: `file`, `checksec`, `strings`, `readelf -a`, `objdump -d`, run it.
2. Buffer overflow: find offset (cyclic), control RIP -> ret2win or system("/bin/sh").
3. ROP: `ROPgadget`/pwntools `ROP`; ret2libc (leak puts/libc base then system).
4. Format string: `%p`/`%n` write; leak then overwrite GOT.
5. Shellcode: NX off -> jump to shellcode; seccomp -> open/read/write syscalls only.
6. Heap: tcache poisoning, UAF, double free.
7. One-gadget for libc.

## Tools
- `uv pip install pwntools`; `checksec`, `gdb` (pwndbg if available), `ROPgadget`.

## SEARCH
- "<challenge> pwn writeup", "ret2libc writeup", "format string writeup"

## References
- pwntools docs: https://docs.pwntools.com/


## SOLVED case study: TFC 2026 `bitdebit³` (one-bit arbitrary write + FILE overflow -> House of Apple 2)
- Binary leaks libc base, then gives ONE arbitrary single-bit XOR write (addr + bit 0-7), then one fgets(name,0x100).
- setup() sets stdin/stdout/stderr _IONBF, so stdin._IO_buf_base=shortbuf(stdin+0x83), _IO_buf_end=shortbuf+1.
- Exploit: flip bit 14 of stdin->_IO_buf_end (write to base+0x21aae1, bit=6) so the unbuffered underflow read length becomes 0x4001. The name fgets then does one big read(0, shortbuf, 0x4001), overflowing stdin FILE tail + _IO_wide_data_0 + main_arena + ... forward.
- Forge a fake FILE (vtable=_IO_wfile_jumps, _wide_data=fake), fake _IO_wide_data (write_base=0, buf_base=0, _wide_vtable=fake), and a fake wide vtable with __doallocate=system. Set _IO_list_all=fake FILE. Command string at fake FILE start.
- exit -> _IO_cleanup -> _IO_flush_all_lockp(0) -> _IO_OVERFLOW -> _IO_wfile_overflow -> _IO_wdoallocbuf -> WJUMP1(__doallocate) (wide vtable is NOT IO_validate_vtable'd) -> system(cmd).
- Gotcha 1: _IO_wdoallocbuf skips __doallocate if fp->_flags & _IO_UNBUFFERED (0x2); the command string's first char must have bit1 and bit3 clear (NO_WRITES=0x8) and second char bit3 clear (CURRENTLY_PUTTING=0x800). " cat flag" (leading space) works.
- Gotcha 2: send addr\n+bit\n+payload in ONE send() so the whole overflow payload is buffered before the big read. Sending the payload after waiting for the name prompt races with read() and truncates over TCP/TLS (read returns partial).
- Gotcha 3: main_arena gets overwritten but this is fine — system()/posix_spawn/execvpe never malloc in the parent, and the exec'd shell/cat get a fresh libc image.
- glibc 2.35 offsets (provided libc.so.6): _IO_2_1_stdin_ 0x21aaa0, _IO_list_all 0x21b680, _IO_wfile_jumps 0x2170c0, system 0x50d70, stdin lock 0x21ca80, _IO_jump_t.__doallocate=0x68, _IO_wide_data._wide_vtable=0xe0.

## TFC CTF 2026 unbrevable (solved)
- Arbitrary write via scanf("%zu %zu") + fgets(buf,size,stdin); libc leak via printf of setvbuf GOT value.
- Seccomp allowlist only: open, openat, read, write, rt_sigprocmask, rt_sigreturn, exit, exit_group, execveat. fork() -> clone -> SIGSYS.
- Bypass: overwrite libc fork_handlers count (0x221ae0) and fork_handler_pool base (0x221af0) so __run_fork_handlers calls a raw prepare_handler (no PTR_MANGLE). Set count=fake_ucontext_addr (rdi=count), base=fake_handler-((count-1)<<5), prepare=setcontext+4 -> ROP open/read/write.
- setcontext+4 (glibc 2.35: 0x53a1d pivot, use 0x539e4 for push rdi/pop rdx) needs [uc+0xe0] = valid fpstate pointer.
- Avoid hardcoding fd after open: socat leaves fd3 busy; use xchg edi,eax gadget (libc+0x164eec) preceded by pop rdi to a writable addr.
- Payload bytes must avoid 0x0a (fgets newline terminator); retry connection on collision.
- Remote netcat endpoints: ncat --ssl <deploymentName>.challs.ctf.thefewchosen.com 1337 (deploymentName from POST challenge-manager /isolated).


## V8 motor (TFC CTF 2026) — bitFlip single-bit JIT-spray sandbox escape
Flag technique summary:
- d8 patched: global bitFlip(object, bit_offset) flips ONE bit at object.address()+bit_offset/8,
  rejects sandbox-internal targets, one use. Wasm RWX code lives OUTSIDE sandbox.
- Leak wasm codeObj + eval SFI from --log-code log via /proc/self/fd scan (remote fd 6).
- Flip the Liftoff epilogue `pop rbp` (0x5d) into `jge` (0x7d) so the tiering `ret` byte
  (0xc3) is reused as the jge rel8, redirecting backward into JIT-sprayed immediates.
- Trap: Liftoff DEDUPS identical i64.const values (7-byte rip-relative mov), shifting the
  epilogue. Calibrate the ACTUAL pop-rbp offset from a local gdb disasm, don't assume 0xaa.
- Trap: SFI->JSFunction offset is GC/parse sensitive and differs locally vs remote; find it
  remotely with a return-value oracle (make the final i32.const value have a 4-byte LEB and
  4 distinct flip outcomes per immediate byte).
- Shellcode via rdi=codeObj+8 (deterministic register) + add rdi to reach a string stored in
  an earlier i64.const immediate; rdx=0 already; push 59/pop rax (NOT mov al,59) to set rax.
