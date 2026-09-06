# unbrevable

**Flag:** `TFCCTF{well_known_technique_brudda}`

# unbrevable — running log

Append-only. Timestamp every entry.

## Hypotheses
- [13:20] H1: pwn via netcat; unpack zip, reverse binary, exploit overflow (brief).
- [13:25] H2 (WINNING): arbitrary write (fgets to arbitrary addr, size from scanf) + libc leak (setvbuf). Seccomp allows open/openat/read/write/exit/execveat only; fork() -> clone syscall -> SIGSYS kill. Bypass via fork atfork prepare handler (raw fn ptr, no PTR_MANGLE) + setcontext ROP to open/read/write flag.

## Findings
- Files: vuln_patched (PIE, NX off, partial RELRO, not stripped), libc-2.35.so, ld-2.35.so. Docker runs socat EXEC:./vuln_patched on 1337, flag in /app/flag, seccomp via libseccomp.
- main: init() -> setup_seccomp() -> printf("%p\n", setvbuf@libc) -> scanf("%zu %zu", &a, &b) -> fgets((void*)a, b, stdin) -> fork().
- seccomp rules (SCMP_ACT_KILL_PROCESS default, ALLOW): open(2), openat(0x101), read(0), write(1), rt_sigprocmask(14), rt_sigaction(15), exit(60), exit_group(0xe7), execveat(0x142). NO clone -> fork dies with SIGSYS.
- Arbitrary write: single fgets writes up to 2^32-1 bytes to any libc-known address (we know libc base from setvbuf leak). No PIE/stack leak.
- WIN: overwrite libc fork_handlers (0x221ae0) count and fork_handler_pool base (0x221af0) with one contiguous fgets write starting at 0x221ae0. __run_fork_handlers calls prepare_handler[i] (raw pointer) with rdi=count, rsi=1 before clone. Set count=fake_ucontext_addr (so rdi=ucontext), base=fake_handler-((count-1)<<5), prepare=setcontext+4. setcontext pivots to ROP: open("flag",0) -> read(3,buf,0x100) -> write(1,buf,0x100) -> _exit.
- Payload avoids 0x0a bytes (fgets stops at newline); retry connection on collision.
- LOCAL TEST PASSED: exploit reads local /app/flag placeholder TFC{local_test_flag} end-to-end.

## Dead ends
- exit handlers (__exit_funcs/ef_on/ef_cxa) need PTR_MANGLE (fs:0x30 guard unknown).
- got._IO_cleanup raw call at exit never reached (fork SIGSYS first).
- fork@GOT overwrite needs PIE base (no leak).
- FSOP during fgets considered; atfork handler route is cleaner.

## Limitations
- Remote dynamic instance not started yet (team at 3/3 running instances; tagger expires 13:30:46Z).

## Next actions
- Start unbrevable container, get netcat host:port, run solve_exploit.py, submit flag.


## SOLVED
- [13:55] Flag: TFCCTF{well_known_technique_brudda} (submitted, ok:true; challenge id 89fdbeb2, flag_id 2b5f836a-103a-4224-9d1f-4ad9f4dd6515).
- Remote endpoint: ncat --ssl <deploymentName>.challs.ctf.thefewchosen.com 1337 (from frontend JS: challengeDomain=challs.ctf.thefewchosen.com).
- Remote socat keeps an extra fd (3), so open() returns fd 4; use xchg edi,eax gadget at libc+0x164eec to capture the real fd for read().
- Container stopped after solve to free the slot.
