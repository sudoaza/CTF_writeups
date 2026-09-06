# Mid

**Flag:** `TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}`

# Mid — running log

Append-only. Timestamp every entry.

## Hypotheses
- [10:30] H1-H4 as in brief.md: 62-ary lexicographic binary search + oracle-flip detection.
## Findings
- [10:30] Source recovered and read: exact semantics confirmed (195 queries, 30 chars, mood flips once at switch_at).
- [10:30] local flag placeholder is TFCCTF{no1_s0_3asy} (only the remote env flag counts).
## Dead ends
- (none)
## Limitations
- Remote connection endpoint not yet started/known (dynamic netcat challenge; needs the platform to assign host:port).
## Next actions
- Start the dynamic instance to get host:port.
- Write and test the solver locally against chall.py, then run against the remote.

## Brief / category / skills / hypotheses
MISC/GAME — 175 pts — dynamic netcat — ~87 solves.
- Brief: 'Mid means middle, right?' Source at files/chall.py: ~195 queries, 30-char password over [0-9A-Za-z], a 'mood' flips once at switch_at.
- Required skills: pwntools remote I/O; strategy/optimization (information-theoretic guessing with flip detection).
- First hypotheses: mastermind-style oracle (higher/lower or proximity to 'mid'); detect the flip point, then binary search the alphabet; reconnect for fresh instances.


## 2026-09-05 16:31 UTC — solver-design session (paused by coordinator)
### Findings
- Re-verified oracle semantics against files/chall.py (195 queries, 30 chars, mood flips once at switch_at in 0..195).
- Info budget: password entropy = 30*log2(62) = 178.63 bits; worst-case search = 178 comparisons + 1 final "equal" query = 179 truthful queries; avg ~177.7. Only ~16 spare queries for flip detection.
- Naive state-0 global binary search wins iff F >= ~180: measured 6.4-8% (matches parent's 8-16% for naive).
- Canary-every-K + checkpoint rollback CANNOT fit: overhead ~ 179/K + K >= 26.8 > 16, so it always exceeds 195 queries. Confirmed by simulation (with query limit enforced, max ~7%).
- Weighted Renyi-Ulam search (tolerating e lies) implemented and verified correct on small N; 0-lie cost ~182 (e=1) / ~186 (e=2) queries vs 177.7 plain. But it does NOT detect the flip early: random answers decay the <=e candidate set only like (k+1)/2^k, so "candidate set empty" fires far too late (~192 queries).
- Fixed two-phase state schedule gives >=179 truthful bits only for F in a 33-wide window => ~17% theoretical ceiling; joint (P,F) decoding would be needed to exploit it.
- Joint entropy of (password, flip) is ~186.2 bits < 195, so an optimal joint scheme exists, but a practical one was not found.
### Dead ends
- Canary/rollback strategies (all K, rollback depths, canary styles): budget-infeasible.
- Renyi-Ulam "detect flip via empty candidate set": too slow.
- Multi-hypothesis F-tracker (midpoint+canary policy): ~1% (policy ineffective).
### Limitations
- Did not reach a solver with credible success rate; paused before remote run. No dynamic instance was started (respecting 3-slot limit).
### Artifacts
- solve/mid_solver.py: exact Oracle simulator + naive solver + WeightedSearchE + remote I/O skeleton.
- solve/solver_experiments.py: notes.
### Next (if revisited)
- Find a practical JOINT (P, F) decoding scheme (adaptive state via multi-hypothesis tracking with a better query policy) targeting ~186 bits in 195 queries.
- Or implement the ~17% two-phase joint decoder and retry over fresh reconnects (~6 attempts => ~67%).


## 2026-09-05 23:15 UTC — SOLVED
### Findings
- Remote (mid2 image) uses MAX_QUERIES = 220, NOT 195 as in the attached source.
  Banner: "length = 30", "queries = 220". The provided chall.py (195) is stale.
- Remote transport: TLS to <deployment>.challs.ctf.thefewchosen.com:1337, PTY echo
  (each input line is echoed), CRLF line endings, "> " prompt after every answer.
- Winning solver: checkpoint+rollback binary search (state 0) with 30 decreasing-gap
  change-point probes [8,17,...,219]. Probe = guess "0"*30 on state 0; "larger" =>
  mood flipped => switch to state 1 and roll back to the widest checkpoint still
  searchable in the remaining budget (size <= 2^R), then finish on state 1.
- Local success rate ~93.2% (30000 trials); remote solved on attempt 1.
### Flag
- TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch} (submitted, ok:true)
### Dead ends / limitations
- For the ORIGINAL 195-query source, this class of strategy caps ~40% (tight info
  budget); the remote being 220 queries is what makes ~93% achievable.
