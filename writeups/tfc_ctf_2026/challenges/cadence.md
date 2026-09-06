# Cadence

**Flag:** `TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}`

# Cadence — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## [2026-09-05T14:19:15Z] Recon & algorithm recovered
- Binary: Zig 0.16 static ELF, DWARF debug info. Music player "cadence" with hidden "Encore" stage.
- Encore enabled by passing an .m3u file containing line `#EXTENC:<32 hex seed>`.
- Remote service runs cadence with FLAG env; Encore success prints flag.
- TUI Encore screen shows SESSION = hex(SHA256("cadence/encore/session/v2" || seed)[0:16]) and required sample rate = [8000,11025,16000,22050,32000,44100][nonce[0]%6].
- Submission: paste unpadded base64 WAV (mono 16-bit PCM, exact rate, >15 samples); binary rejects '=' padding.
- Reversed `encore.resonates`: SHA-256 PRF init/target, GF(2^32) gfmul (poly 0x4c11db7), splitmix64 counter, 4-lane update.
- Whole sample->final-state map is GF(2)-linear; solving linear system gives valid WAV (n=28 works in Python sim).
- Local binary uses SHA-NI (host lacks it); running under `qemu-x86_64 -cpu max` works as oracle.
- Dead end: local TUI prompt prepends the view-switch '9' key to submitted base64 input (input becomes '9'+b64), breaking decoding. Need workaround (use tab to reach Encore, or account for extra char).
## Next actions
- Fix TUI input workaround; validate solver locally under qemu.
- Start remote instance when slot free, solve, submit flag.

## [2026-09-05T16:26Z] Solver complete; remote protocol recovered; paused by coordinator

### SOLVER (offline, validated)
- `solver.py` in this folder: `solve(nonce_hex, n=28)` -> (b64, rate, samples).
- Local validation under qemu: pasting the b64 into the Encore prompt yields
  "PERFECT CADENCE - the track resonates" (flag only prints on remote).
- Key constants in solver.py (GC0/GC1/GC2/GFINAL/POLY/CINV/C_words/RATES).
- rate = RATES[nonce[0] % 6]; nonce = SHA256("cadence/encore/session/v2" || seed)[0:16].

### REMOTE SERVICE PROTOCOL (verified once, instance affd659eb99e3328)
1. TLS connect to <name>.challs.ctf.thefewchosen.com:1337 (no verify).
2. The service runs a pty in canonical+echo mode. It reads LINES and ignores any
   line that is not exactly 32 hex chars.
3. Send the 32-hex SEED line + CR. The wrapper echoes it, then launches the
   cadence TUI with that seed (writes an #EXTENC m3u). Observed bytes after seed:
   `<seed>\r\n` + `\x1b[?1049h\x1b[?25l`.
4. With a seed m3u, cadence opens DIRECTLY on the Encore view (verified locally):
   SESSION <32hex>, rate, prompt `> ` waiting for base64. NO tab navigation needed.
5. Paste the base64 (standard padded b64, 136 chars for n=28) then Enter.
6. Screen shows "PERFECT CADENCE - the track resonates"; remote prints the FLAG
   (locally prints "This stage carries no flag - the encore only pays out on the remote.").

### SINGLE-SHOT RUN STEPS (do exactly this on a fresh live instance)
- `python3 solver.py` is not a CLI; import it. Steps in remote_solve2.py:
  1. connect TLS (setblocking False).
  2. sendall(seed.encode()+b'\r').
  3. feed output into pyte.Screen(100,30); WAIT until raw stream contains
     b'\x1b[?1049h' (TUI up) or screen shows SESSION. Be patient (>=15s).
  4. Only AFTER TUI confirmed: sendall(b64.encode()); sleep 0.4; feed 1s; sendall(b'\r').
  5. feed 6s; read screen; regex TFCCTF{...}.
- CRITICAL: do NOT send tabs/Enter/base64 before the TUI is up. The wrapper is
  still canonical while it processes the seed; any early input is echoed and
  eaten by the line reader (this broke the 63ca attempt: base64 was echoed back).

### INFRA FLAKINESS (why paused)
- Dynamic-instance pods are unreliable. Only ~3 of ~8 cadence starts came up
  (echo on 8d3ec0c1d8858055, affd659eb99e3328, 63ca5354bb60cff2). The rest never
  echoed (pod not ready / dead) even after 5-15 min.
- On affd, after seed we saw only 48 bytes = seed echo + 1049h+25l; the full
  TUI render did not arrive in a 3-4s window, so either the render is delayed
  (blocking mpv/audio init?) or cadence dies inside ui.run on the remote.
  NOT the terminal-size issue (verified locally 0x0/24x80/30x100 all render).
- Hypothesis to test next: wait much longer (20-30s) for the render after 1049h.
- Slot pressure from siblings; coordinator suspended re-arming.

### FILES
- solver.py, remote_solve2.py, diag.py (raw-byte capture) in this folder.

## [2026-09-05T20:25Z] 5-for-5 dead pods post-restart -> infra escalated
- Challenge-manager restarted 19:18:26Z (process_start_time_seconds 1788635906).
- Retried 5 fresh pods per coordinator policy (probe :1337 echo, 25s-4min each):
  43649b5c, da8021e2, 1d1b07f6, 9c26f049, c0d24d71 -> ALL 0 bytes (TLS terminates,
  no canonical echo, no 1049h, seed line also gets nothing).
- Pre-restart pods were ~40% live (echo + TUI init); post-restart 0/8 live.
- Conclusion: cadence pod startup is broken after the CM restart (image pull,
  entrypoint, or Traefik backend health), not random flakiness.
- Solver + single-shot run steps still ready (solver.py, auto_solve.py, diag.py).
- Slot freed (stopped last pod); only larpin running.

## [2026-09-06T00:33Z] SOLVED
FLAG: TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}

### Root cause of my earlier "dead pod" reads
- Python non-blocking ssl recv() raises ssl.SSLWantReadError, which is NOT a
  BlockingIOError; my `except BlockingIOError`/`except Exception: break` loop
  aborted on the FIRST empty recv, so live pods looked dead.
- Fix: use blocking socket with settimeout(0.5) and catch socket.timeout to keep
  reading. openssl s_client confirmed the pod was alive all along.

### Actual remote protocol (corrected)
- The service ignores the sent 32-hex line's CONTENT: it generates a FRESH
  RANDOM seed per connection. Do NOT compute from your own seed.
- Read SESSION (32 hex) and rate from the rendered Encore screen, then solve for
  nonce = bytes.fromhex(SESSION). rate = RATES[nonce[0] % 6] (confirmed).
- n=28/32/40 are NOT reliably surjective over GF(2)^256 for all nonces (rank can
  be 255). Use n=48 (rank 256 across tested nonces; b64 = 188 chars, accepted).

### Single-shot solve (working)
1. TLS connect :1337 (blocking, timeout 0.5).
2. send any 32-hex line + CR.
3. read ~12s into pyte.Screen(100,30); wait for 1049h.
4. regex SESSION ([0-9a-f]{32}) and at (\d+) Hz from screen.
5. b64,rate,samples = solve(SESSION)  # n=48
6. send b64, sleep 0.4, send CR, read 10s.
7. flag regex [A-Za-z0-9_]{2,30}{...} on raw text (strip leading junk from render).
