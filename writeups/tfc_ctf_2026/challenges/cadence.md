# Cadence

`Cadence` (500 pts, 1 solve) is a reversing + remote challenge ("Winamp who?")
shipping a static Zig 0.16 ELF: a music player with a hidden "Encore" stage. The
remote runs it with the flag in the environment and prints the flag only when
you feed it a WAV whose samples make an internal PRF hit a target state. Key
idea: the whole sample-to-state map is **linear over GF(2)**, so the "music" is
a 256-bit linear system to solve.

## Recon

```
$ file cadence
cadence: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped

$ strings -a cadence | grep -iE 'EXTENC|SESSION|PERFECT|resonat|Encore'
PERFECT CADENCE - the track resonates
Encore
SESSION
ADD ENCORE TRACK
#EXTENC:
cadence/encore/session/v2
Wrong sample rate for this session.
Add a track whose waveform resonates with this session.
This stage carries no flag - the encore only pays out on the remote.
Too few samples to resonate.
```

The binary has DWARF debug info (Zig symbols intact), which makes the reverse
fast. The hidden Encore stage is enabled by feeding an `.m3u` file containing
the line `#EXTENC:<32 hex seed>`.

## Analysis

Observation: Encore shows a session id and a required sample rate, then asks for
base64 WAV data (mono 16-bit PCM at the exact rate, more than 15 samples). On
success it prints `PERFECT CADENCE - the track resonates` — and, only on the
remote, the flag.

The session and rate come from the seed:

```
nonce = SHA256("cadence/encore/session/v2" || seed)[0:16]
SESSION = hex(nonce)
rate = [8000, 11025, 16000, 22050, 32000, 44100][nonce[0] % 6]
```

Reversing `encore.resonates` shows it is a custom PRF:

- SHA-256 domain-separated `init` and `target` (8 x 32-bit words),
- a GF(2^32) multiply with polynomial `0x4c11db7`,
- a `splitmix64` counter, and a 4-lane per-sample update.

Hypothesis: `resonates(nonce, rate, samples)` is GF(2)-linear in the sample
bits. Confirmation: modeling it as a linear map and solving the linear system
yields samples that land exactly on the target state. The technique is a
**GF(2) linear solve of a hash/PRF** — each sample is 16 bits, so n samples give
16n unknowns against a 256-bit target state; n = 48 gives full rank 256.

Dead ends: the local TUI prepends a stray `9` view-switch key to pasted input,
and the local binary uses SHA-NI instructions the host CPU lacks (worked around
by running under `qemu-x86_64 -cpu max` as an oracle). Neither matters for the
remote, which starts directly on the Encore view.

## Exploit

1. **Implement the PRF.** The essential pieces are `gfmul`, `splitmix64`, and
   the 4-lane update (from the reversed `encore.resonates`):

   ```python
   MASK32 = 0xffffffff
   MASK64 = 0xffffffffffffffff
   GOLD64 = 0x9e3779b97f4a7c15
   BASE64 = 0xc0dace5551a7e001
   GC0 = 0x9e3779b1; GC1 = 0x85ebca77; GC2 = 0xc2b2ae3d
   POLY = 0x104c11db7
   CINV = 0x9a7ed247
   C_words = [0x452821e6,0x38d01377,0xbe5466cf,0x34e90c6c,0xc0ac29b7,0xc97c50dd,0x3f84d5b5,0xb5470917]
   RATES = [8000,11025,16000,22050,32000,44100]

   def gfmul(a, b):
       res = 0
       for _ in range(32):
           if b & 1: res ^= a
           b >>= 1
           a = (a << 1) & MASK32
           if a & 0x100000000: a ^= POLY
       return res & MASK32

   def splitmix64(z):
       z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK64
       z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK64
       return (z ^ (z >> 31)) & MASK64

   def prf(domain, nonce, rate=None):
       msg = domain + nonce + (b'' if rate is None else struct.pack('<I', rate))
       return hashlib.sha256(msg).digest()

   def words(d): return [int.from_bytes(d[i:i+4], 'little') for i in range(0, len(d), 4)]

   def init_state(nonce, rate): return words(prf(b'cadence/resonance/init/v2', nonce, rate))

   def target_state(nonce):
       T = words(prf(b'cadence/resonance/target/v2', nonce))
       nw = words(nonce)
       g = [0]*8
       g[5] = nw[0]^T[0]^C_words[0]; g[2] = nw[1]^T[1]^C_words[1]
       g[7] = nw[2]^T[2]^C_words[2]; g[0] = nw[3]^T[3]^C_words[3]
       g[3] = nw[0]^T[4]^C_words[4]; g[6] = nw[1]^T[5]^C_words[5]
       g[1] = nw[2]^T[6]^C_words[6]; g[4] = nw[3]^T[7]^C_words[7]
       return [gfmul(g[i], CINV) for i in range(8)]
   ```

2. **Model the per-sample update** (the full `resonates` from `solver.py`).
   Because every operation is XOR/shift/GF-multiply, the final state is linear
   in the sample bits. Build the linear system: for each sample `i` and each bit
   `b`, compute the delta from the all-zero input, and solve for the combination
   that equals `target_state`:

   ```python
   def pack(S): return sum(w << (32*i) for i, w in enumerate(S)) & ((1<<256)-1)

   def solve_wav(nonce, rate, n=48):
       c0 = pack(resonates(nonce, rate, [0]*n))
       cols = []
       for i in range(n):
           for b in range(16):
               s = [0]*n; s[i] = 1 << b
               cols.append(pack(resonates(nonce, rate, s)) ^ c0)
       rhs = pack(target_state(nonce)) ^ c0
       basis = {}
       for j, col in enumerate(cols):
           val, var = col, 1 << j
           while val:
               p = val.bit_length() - 1
               if p in basis: val ^= basis[p][0]; var ^= basis[p][1]
               else: basis[p] = (val, var); break
       r, sol = rhs, 0
       for p in sorted(basis, reverse=True):
           if (r >> p) & 1: r ^= basis[p][0]; sol ^= basis[p][1]
       assert r == 0
       samples = []
       for i in range(n):
           x = 0
           for b in range(16):
               if (sol >> (i*16+b)) & 1: x |= 1 << b
           samples.append(x)
       assert resonates(nonce, rate, samples) == target_state(nonce)
       return samples
   ```

   n = 48 is used because smaller n is not reliably surjective over GF(2)^256
   (rank can be 255).

3. **Build the WAV** (mono 16-bit PCM, the session's exact rate) and base64 it:

   ```python
   def build_wav(samples, rate):
       data = b''.join(struct.pack('<H', s & 0xffff) for s in samples)
       return (b'RIFF' + struct.pack('<I', 36+len(data)) + b'WAVE'
               + b'fmt ' + struct.pack('<IHHIIHH', 16,1,1,rate,rate*2,2,16)
               + b'data' + struct.pack('<I', len(data)) + data)

   def solve(nonce_hex, n=48):
       nonce = bytes.fromhex(nonce_hex)
       rate = RATES[nonce[0] % 6]
       samples = solve_wav(nonce, rate, n)
       return base64.b64encode(build_wav(samples, rate)).decode(), rate, samples
   ```

   n = 48 -> 140-byte WAV -> 188 base64 chars.

4. **Talk to the remote** (TLS on `<deployment>.challs.ctf.thefewchosen.com:1337`).
   The service runs the TUI in a PTY (canonical + echo). The seed line content is
   ignored — the server generates a fresh random seed per connection — so read
   `SESSION` and the rate from the rendered screen instead:

   ```python
   import socket, ssl, re, time
   ctx = ssl.create_default_context()
   ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
   s = socket.create_connection((host, 1337), timeout=20)
   tls = ctx.wrap_socket(s, server_hostname=host)
   tls.settimeout(0.5)

   tls.sendall(b'000102030405060708090a0b0c0d0e0f\r')   # any 32-hex line + CR
   buf = b''
   deadline = time.time() + 12
   while time.time() < deadline:
       try:
           d = tls.recv(65536)
           if d: buf += d
       except socket.timeout:
           pass
       if b'\x1b[?1049h' in buf: break          # TUI is up
   text = buf.decode('latin1', 'replace')
   session = re.search(r'([0-9a-f]{32})', text).group(1)   # SESSION
   ```

5. **Submit the WAV and read the flag.**

   ```python
   b64, rate, samples = solve(session, n=48)    # nonce = bytes.fromhex(SESSION)
   tls.sendall(b64.encode())
   time.sleep(0.4)
   tls.sendall(b'\r')
   # read ~10s, then match the flag in the raw stream
   flag = re.search(r'TFCCTF\{[^}]+\}', buf.decode('latin1','replace')).group(0)
   ```

   The screen prints `PERFECT CADENCE - the track resonates`; the remote then
   prints the flag.

## Full chain

```
python3 solver.py            # import solve() from cadence_4b6fe26a/solver.py
# 1. TLS connect to <deployment>.challs.ctf.thefewchosen.com:1337 (no verify, timeout 0.5)
# 2. send any 32-hex line + CR; wait (~12s) for \x1b[?1049h
# 3. regex SESSION ([0-9a-f]{32}) and the Hz rate from the screen
# 4. b64,rate,samples = solve(SESSION, n=48)
# 5. send b64, sleep 0.4, send CR, read ~10s
# 6. regex TFCCTF{...}
```

## Flag

`TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}`

## Lessons

- If a challenge's "resonance/PRF" check only mixes samples with XOR, shifts,
  and GF-multiply, treat it as a GF(2)-linear map and solve a linear system
  instead of searching the audio space.
- For a PTY-backed remote TUI, don't compute from your own seed: read the
  session/nonce the server renders and solve for that.
- A blocking socket with `settimeout` is more robust than non-blocking
  `recv()` loops when the daemon echoes slowly — a first empty read is not a
  dead pod.
