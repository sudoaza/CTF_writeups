# Mid

`Mid` (474 pts, 4 solves) is a crypto game-oracle challenge ("Mid means middle,
right?"). The remote holds a random 30-character password over
`[0-9A-Za-z]` and answers up to 220 lexicographic comparisons — but a hidden
`mood` bit flips once, after which one of the two query "states" starts lying.
Key idea: detect the flip with cheap canary probes, then roll the binary search
back to a checkpoint and finish on the truthful state.

## Recon

The attachment is `chall.py`, the full service source:

```python
MAX_QUERIES = 195
PASSWORD_LENGTH = 30
ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase  # 62

password = generate_password()
switch_at = secrets.randbelow(MAX_QUERIES + 1)
mood = 0
for query_id in range(MAX_QUERIES):
    if query_id == switch_at: mood = 1
    line = input("> ").strip()
    state_raw, guess = line.split(maxsplit=1)
    state = int(state_raw)              # 0 or 1
    truth = real_answer(guess, password)   # "smaller"/"larger"/"equal"
    if state == mood:
        print(truth)
        if truth == "equal": print(FLAG); return
    else:
        print(secrets.choice(("smaller", "larger")))
```

Connecting to the real instance shows a crucial discrepancy — the deployed
`mid2` image allows more queries than the stale attached source:

```
$ openssl s_client -connect <deployment>.challs.ctf.thefewchosen.com:1337 -quiet
Find the secret.
length = 30
queries = 220
>
```

## Analysis

Observation: each query is `<state> <guess>`. When `state == mood` the answer is
the true lexicographic comparison (`smaller`/`larger`/`equal`, with `equal`
printing the flag); when `state != mood` the answer is a random
`smaller`/`larger`. `mood` starts at 0 and flips to 1 exactly once at
`switch_at`, so the "truthful state" is 0 before the flip and 1 after it.

The password has `30 * log2(62) ≈ 178.6` bits, so a plain binary search needs
about 179 truthful comparisons — tight against 195, but comfortable against the
remote's 220, leaving ~40 spare queries to handle the flip.

The detection primitive: guess `"0"*30` on **state 0**. While state 0 is
truthful, `"0"*30 < password` always (the password is essentially never all
zeros), so the truthful answer is always `smaller`. A `larger` on this probe is
therefore impossible truthfully — it can only come from the random (lying) state,
i.e. the flip has happened. Each probe catches the flip with probability ~1/2,
so a decreasing-gap probe schedule (sparse early, dense late) detects it quickly
and cheaply.

Because the flip also corrupts the running binary-search interval, the solver
keeps a checkpoint after every midpoint query and, on detection, rolls back to
the widest checkpoint still searchable in the remaining budget, then finishes on
state 1. The technique is **change-point detection + checkpoint rollback** (a
single-sided liar search).

## Exploit

1. **Map integers to 30-char base-62 strings** (most-significant digit first)
   and back:

   ```python
   ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
   A = len(ALPHABET)   # 62
   L = 30
   N = A ** L

   def i2s(v):
       out = []
       for _ in range(L):
           out.append(ALPHABET[v % A]); v //= A
       return "".join(reversed(out))
   ```

2. **Binary search on state 0, interleaved with canary probes.** The probe
   schedule is 30 indices with a decreasing gap, the last at 219:

   ```python
   PROBES = [8,17,26,35,44,53,62,71,79,87,95,103,111,119,127,
             134,141,148,155,162,169,175,181,187,193,199,204,209,214,219]
   ```

   At a probe index, query `(0, i2s(0))`; `larger` means the flip happened:

   ```python
   def solve_session(query):
       lo, hi = 0, N - 1
       checkpoints = []
       i, detected, pset = 0, False, set(PROBES)
       while i < 220:
           if i in pset:
               y = query(0, i2s(0)); i += 1
               if y == "equal": return True
               if y is None: return False
               if y == "larger": detected = True; break
           else:
               g = (lo + hi) // 2
               y = query(0, i2s(g)); i += 1
               if y == "equal": return True
               if y is None: return False
               if y == "smaller": lo = g + 1
               else: hi = g - 1
               checkpoints.append((lo, hi))
       if not detected: return False
       # roll back to the widest checkpoint still searchable in R queries
       R = 220 - i
       for cl, ch in checkpoints:
           if ch - cl + 1 <= (1 << R):
               lo, hi = cl, ch; break
       else:
           return False
   ```

3. **Finish the search on state 1** (now the truthful state):

   ```python
       while i < 220:
           if lo > hi: return False
           if lo == hi: return query(1, i2s(lo)) == "equal"
           g = (lo + hi) // 2
           y = query(1, i2s(g)); i += 1
           if y == "equal": return True
           if y is None: return False
           if y == "smaller": lo = g + 1
           else: hi = g - 1
       return False
   ```

4. **Handle the remote transport.** It is TLS on port 1337 behind a PTY that
   echoes every input line and prints a `> ` prompt after each answer, so the
   reader must skip the echo and consume the prompt:

   ```python
   def query(self, state, guess_str):
       sent = f"{state} {guess_str}"
       self.s.sendall((sent + "\n").encode())
       while True:
           line = self._readline()
           if line == sent: continue        # PTY echo
           if line == "equal":
               self.flag = self._readline(); return "equal"
           if line in ("smaller", "larger"):
               self._read_exact(2)          # "> " prompt
               return line
           if line in ("out of queries", "usage", "invalid"): return None
   ```

5. **Run it.** Local simulation measures ~93.2% success (30000 trials); the
   remote was solved on attempt 1.

## Full chain

```
python3 solve/final220.py --host <deployment>.challs.ctf.thefewchosen.com --attempts 40
```

## Flag

`TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}`

## Lessons

- Always read the live banner: the deployed service allowed 220 queries while
  the attached source said 195 — that extra budget is what made the ~93% solve
  feasible (the 195-query version caps this strategy around 40%).
- A single monotone state flip in a comparison oracle can be handled by cheap
  canary probes plus checkpoint rollback; you do not need full joint decoding.
- On PTY-backed services, remember every line you send is echoed and every
  answer is followed by a prompt — parse those explicitly.
