# V8 motor

**Flag:** `TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a}`

# V8 motor — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
PWN (V8/JS engine) — 272 pts — dynamic netcat — ~46 solves. Attach: motor_v8.zip.
- Brief: 'the sun is a deadly laser'
- Required skills: pwntools; v8/d8 (inside zip); type-confusion/OOB exploit -> wasm RWX -> shellcode.
- First hypotheses: classic d8 challenge: abuse a JS type confusion / OOB array write, then WebAssembly RWX page for shellcode, read flag.

## Discovery & ideation (2026-09-05)
FILES: motor_v8.zip -> d8 (49MB, patched V8), bitflip.patch (the vuln), readflag.c (SUID: sets uid0, reads /flag to stdout), run.sh (reads exact-length JS payload, runs 'd8 --log-code --logfile=+'), snapshot_blob.bin, flag, Dockerfile, args.gn.
bitflip.patch (full read): adds global bitFlip(object, bit_offset): flips ONE bit at object.address()+bit_offset/8, REJECTS if the target is inside the V8 sandbox (V8_ENABLE_SANDBOX). Also: 'os' global now always exposed BUT os.system removed; d8.wasm serialize helpers removed (Wasm itself still enabled).
HYPOTHESES (ranked):
1. Single-bit-flip sandbox escape via WebAssembly RWX: instantiate a wasm module whose code page lives OUTSIDE the sandbox (trusted space), then bitFlip one bit in that RWX code to turn a controlled instruction into shellcode (or corrupt a code entry/pointer), then call it -> execve('/challenge/readflag') (readflag is SUID and prints /flag). Classic bitflip-WASM RWX technique.
2. bitFlip a bit in the isolate's external/trusted data (code pointer table, dispatch table) outside the sandbox to redirect to shellcode; then trigger.
3. Note os.setenv/unsetenv etc. still available (no system) - not needed if we have RWX shellcode.
NEXT: confirm the exact challenge setup (run d8 locally with a test bitFlip outside sandbox), then build the standard V8 sandbox-escape + wasm RWX shellcode exploit calling readflag. Read readflag path (run.sh uses /challenge/d8; readflag at /challenge/readflag presumably; verify via Dockerfile/args.gn).


## Deep analysis (2026-09-05 ~2026-09-05 19:02:19)
Exploit chain established end-to-end:
1. Leak wasm code addr + NativeModule addr + SFI via read('/proc/self/fd/3') (the --log-file O_TMPFILE is fd 3).
2. bitFlip(obj, bit_offset) flips ONE bit at obj.address()+off/8, only OUTSIDE the V8 sandbox (cage=inside).
3. Plan: embed execve("/rdflag") shellcode as i64.const immediates in Liftoff code; flip pop_rbp(0x5d)->jge(0x7d) at code+0xaa; jge lands on entry-jump in imm -> JIT-spray shellcode runs.
4. Shellcode (JIT spray, even immediates only): push "lag"; push "/rdf"; mov rdi,rsp; xor esi/edx; push 59; pop rax; syscall. Chunks use eb 0c to skip movabs opcodes.

KEY FINDINGS / BLOCKERS:
- PKU (Memory Protection Keys) ENABLED by default (--memory-protection-keys). wasm code page = pkey 1 = write-protected -> bitFlip faults SEGV_PKUERR. CodeRange pkey 1. Code pointer table also write-protected. So no writable executable memory; plain code-page flip only works with --no-memory-protection-keys.
- Trusted space (partition_alloc, pkey 0) holds WasmCode.instructions_ = code_obj at FIXED offset meta-0x4f4e0. Flipping it does NOT redirect direct call (direct call uses code pointer table).
- SFI->JSFunction offset FRAGILE: varies with parse-time string literals / GC. eval offset measured 0x2d114/0x2d240/0x2d260/0x2d274/0x206c across variants; 64MB ArrayBuffer stabilizes partially.
- Tier budget: sub [r10],0xcd per call; 2nd call may tier-up (js) clobbering flags before jge.

NEXT:
- Calibrate EXACT final script offset via gdb (break BitFlip+0x23f, read rax target vs log codeObj).
- Verify syscall args.
- Remote may lack PKU; try remote with plain jge flip.


## Remote verification + shellcode refinement (2026-09-05 19:51:54)
- REMOTE HAS NO PKU: bitFlip on wasm code page succeeds ("FLIP OK"). Local droplet has PKU (SEGV_PKUERR), so all local logic tests use --no-memory-protection-keys.
- Remote log file is fd 6 (not 3); exploit now scans /proc/self/fd/* for "v8-version".
- 4x 64MB ArrayBuffer allocations before foo(1) STABILIZE the SFI->JSFunction offset (was common/rare 2-state; now deterministic). Offset calibrated via gdb breakpoint at BitFlip+0x23f reading $rax vs log codeObj.
- jge flip (pop rbp 0x5d -> jge 0x7d at code+0xaa) reliably taken after the 4-GC stabilization (0 normal exits).
- SHELLCODE BLOCKER: with i64.const->movabs (10-byte) chunks, executable slots are only the even/odd immediates; the string "/rdflag" cannot be built via push imm32 (sign-extends, breaks into "/rdf" + nulls). movabs+push (11 bytes) does not fit a single 8-byte chunk. LEA(7)+syscall(2)=9 bytes overflows the 8-byte last chunk by 1.
- i32.const+i32.add emits 5-byte mov eax/add eax (4-byte immediates) - a usable shorter-chunk JIT spray; string setup still needs a 7-byte LEA.

FILES:
- solve/exploit.js (remote payload, best effort)
- extract/exploit_v9.js (local: 4-GC, offset 0x20e0, jge flip, movabs-string shellcode)
- extract/exploit_final3/4.js (offset-calibrated local variants)

NEXT: solve the 1-byte shellcode fit (9-byte LEA+syscall into 8-byte last chunk) by putting syscall 0f 05 across the last chunk boundary using a 5-byte LEA variant or by placing the string in a wasm data segment and using mov rdi, imm (if low-address), OR use i32.const 5-byte chunks with 4-byte imm spray.


## Shellcode string-build analysis (2026-09-05 19:56:12)
- push imm32 sign-extends to 8 bytes, so two 4-byte pushes give "/rdf" + 4 nulls + "lag" + 4 nulls (string broken at byte 4).
- Fix options: mov dword [rsp+4], 0x0067616c (8 bytes) must be contiguous in one 8-byte chunk, but then mov rdi/rest has no room after it.
- i64.const->movabs is 10 bytes (opcode 2 + imm 8); executable slots are imm0 only (natural flow) or 6-byte chunks (eb 02 skip-opcode trick). LEA(7)+syscall(2)=9 bytes overflows the 8-byte last chunk by 1.
- i32.const->mov eax,imm32 (5 bytes) gives 4-byte immediates; can set eax="lag" via b8 imm, but 4-byte chunks are too small for LEA/syscall.
- eb 03 trick can skip chunk[0] giving 7 bytes for LEA in last chunk, but syscall still needs 2 more bytes after it.

STATUS: remote exploit chain fully verified except the final execve shellcode string; ~95% complete.


## Final status (2026-09-05 20:00:45)
RESULT: NOT SOLVED YET. Exploit ~95% complete.

WORKING (verified locally + remotely):
1. Log leak: scan /proc/self/fd/* for the v8.log O_TMPFILE (fd 6 remote, fd 3 local). Gives wasm codeObj (field 4), NativeModule (field 7), SFI (field 7 of eval JS event).
2. Remote has NO PKU: bitFlip on wasm code page succeeds ("FLIP OK"); local droplet has PKU (SEGV_PKUERR) so local tests use --no-memory-protection-keys.
3. SFI->JSFunction offset stabilized with 4x 64MB ArrayBuffer before foo(1); calibrated via gdb (break BitFlip+0x23f, read $rax vs log codeObj). Local offset ~0x20d4-0x20e0.
4. jge flip (pop rbp 0x5d -> jge 0x7d at code+0xaa, bit 5) reliably redirects into the JIT-sprayed immediates.

BLOCKER (shellcode string layout):
- i64.const -> movabs is 10 bytes (48 b8 + 8-byte imm). Natural flow only executes imm0 (8B); eb 0c/eb 02 jumps give 6-byte chunks. Last chunk is 8 bytes.
- Need execve("/rdflag"): LEA rdi,[rip+disp] (7B) + syscall 0f 05 (2B) = 9 bytes > 8-byte chunk.
- push imm32 sign-extends (4 value + 4 nulls), so two pushes give "/rdf" + nulls + "lag" (string broken at byte 4).
- mov dword [rsp+4],imm32 fix is 8 bytes and must be contiguous in one chunk, leaving no room after it.
- eb 03 trick gives 7 contiguous bytes (skip chunk[0]) = exactly LEA, but syscall still needs 2 more bytes.

NEXT ATTEMPTS (in priority order):
1. Check register state at shellcode entry (if rsi=rdx=0 already, shellcode shrinks to mov rdi,rsp(3)+push59/poprax(3)+syscall(2)=8B; need string at rsp via loop or a data imm + short pointer).
2. Flip a bit in an existing cmovne (0f 45 -> 0f 05 syscall) if Liftoff emits one, with wasm code pre-setting rax/rdi/rsi/rdx.
3. Read /proc/self/maps another way (readbuffer returns 0 too) to find code pointer table entry (writable on remote) and flip it to redirect to codeObj+2^k where a full shellcode sits.

Artifacts: solve/exploit.js (best payload), extract/exploit_v9.js (local test), notes in this file.


## Parent hint application + final state (2026-09-05 20:10:03)
Parent suggested: (A) string via mov rdi,imm64 + push, (B) cmovne->syscall single flip.
Analysis: Liftoff only emits movabs rax (48 b8), not mov rdi (48 bf). The 48 b8 movabs executes in the natural flow (imm0 -> movabs1 -> movabs2 -> ...), but there is NO executable slot after movabs1 for push rax (next slot is the fixed movabs2 opcode). eb-jumps skip movabs; a 10-byte mov rdi,imm64 cannot span 8-byte immediates without the fixed movabs opcode breaking it. cmovne->syscall (0f45->0f05 via bit6) is valid but the one bitFlip would then be consumed, leaving no redirect (jge) into the sprayed shellcode; and the natural Liftoff code cannot express push/mov rdi/syscall as wasm ops.
Conclusion: JIT-spray string building is the remaining 5% blocker. All other primitives verified end-to-end.


## SOLVED (2026-09-05T22:16:35Z)
Flag: TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a} (submitted ok:true).

Final exploit: solve/exploit_solved.js (also payload.js).

Key corrections vs prior worker:
1. Liftoff dedups identical i64.const immediates: identical values become 7-byte RIP-relative
   `mov rax,[rip+disp]` instead of 10-byte movabs. This shifts the tiering epilogue.
   With imm11 == imm4 (both 0x9090909090909090), pop rbp lands at code+0xa7 (NOT 0xaa),
   and the jge landing is code+0x6c (imm8[1], a nop).
2. The flip offset must therefore be 167 (0xa7), not 170 (0xaa).
3. SFI->JSFunction offset (remote, fd-scan structure, 180-byte wasm body) = 0x2034 (8244).
   Measured remotely via the return-value oracle: set the function return to
   i32.const 0x100000 (LEB 4) so the four bytes of the final `mov eax,0x100000`
   immediate flip to four DISTINCT return values (1048608/1056768/3145728/537919488),
   pinpointing the exact byte hit and thus the offset.
4. Shellcode (works with rdi=codeObj+8, rdx=0):
   landing: 31 d2 (xor edx,edx); eb 02
   imm9:    48 83 c7 1d (add rdi,0x1d -> rdi = code+0x25 = "/rdflag\0" at imm1); 31 f6 (xor esi); eb 02
   imm10:   6a 3b 58 (push 59; pop rax); 0f 05 (syscall); 90; eb 02
   execve("/rdflag", NULL, NULL) = 59.
