# Crypto techniques

## Common challenge styles
- RSA: small e (cube root), factorable n (shared prime gcd across keys), Wiener (small d), Franklin-Reiter (related messages), Coppersmith, LSB oracle, Hastad broadcast, partial key recovery.
- AES modes: ECB byte-at-a-time oracle, CBC bit-flipping, padding oracle, nonce reuse (CTR), GCM forbidden attack.
- Stream/OTP: keystream reuse (ciphertext xor), crib dragging.
- PRNG: Python random (MT19937) state recovery from 624 x 32-bit outputs (untemper); partial outputs -> GF(2) linear solve with Sage (m4ri); Java Random (LCG, 48-bit, 2 outputs), LCG parameter recovery, seed brute force when small.
- Lattices: LLL/SVP, hidden subset-sum/knapsack, approximate common divisor (AGCD), HNP/ECDSA nonce bias, Coppersmith for small roots.
- Hash: length extension (MD5/SHA1/SHA256), collisions, HMAC key leak via length extension.
- Misc: modular arithmetic, CRT, discrete log (pohlig-hellman if smooth), elliptic curve invalid curve attacks.

## Key techniques
1. AGCD (x_i = p*q_i + r_i, small r): SDA lattice. Matrix [2^(rho+1), x_2..x_t; 0, -x_0, 0..; ...], LLL, q1 = M[0][0]//2^(rho+1), p = (x_0 - (x_0 mod q1))//q1. (Solved TFC 2026 `1+1`.)
2. Python MT19937: untemper each 32-bit output (invert temper), feed 624 words to randcrack-style predictor. For getrandbits(48), note it consumes 2 words and returns (w0<<16)|(w1>>16), so you get full w0 and top16 of w1. Partial-state recovery -> model as GF(2) linear system in Sage.
3. CBC bit-flip: flip bytes in IV/ciphertext to control plaintext; know plaintext position to inject.
4. LLL in Sage: `Matrix(ZZ,...).LLL()`; build lattice so the target is the shortest vector.

## Tools
- Sage (`/opt/sage/bin/sage`) for LLL, `sympy`, `z3-solver`, `Crypto`, `randcrack` (pip), `fpylll`.
- Local Z3 via smt-solve skill.

## SEARCH (before solving)
- "site:ctftime.org/writeup <challenge name>"
- "<technique> ctF writeup" (e.g. "AGCD writeup", "MT19937 getrandbits(48) recovery", "CBC bit flipping writeup")

## References
- https://jia.je/ctf-writeups/misc/acd.html  (ACD/AGCD solver code)
- https://eprint.iacr.org/2016/215.pdf  (Algorithms for the Approximate Common Divisor Problem)


## SOLVED case study: TFC 2026 `cer frumos` (Python random partial outputs)
- Leak: 625 x getrandbits(48) (consumes 2 MT words: w0 full 32 bits + w1 top16), plus a discarded getrandbits(16) each iteration (w2 top16, not leaked).
- Key/nonce derived later from getrandbits(64) calls.
- Method that worked: build a GF(2) linear system over the MT19937 state (624*32 = 19968 bits, reduced to 13312 vars) using the twist recurrence + tempering + the known full/partial output bits (23344 equations). numpy Gaussian elimination over GF(2), rank==vars -> unique state; then simulate forward, temper words 1885..1888 to rebuild key/nonce, AES-CBC decrypt.
- Lesson: you do NOT need 624 consecutive full outputs; partial getrandbits(k) outputs give enough linear constraints to solve the MT state as a GF(2) system.


## SOLVED case study: TFC 2026 `math or meth?` (hidden planted row / subset sum)
- Given: h = a^T A (mod p), A in [0,32]^(57x88), one row of A is the base-33 digits of bytes_to_long(flag). Only h, n, m, B, p known.
- Method: Nguyen-Stern hidden subset sum. Build the orthogonal lattice L_x^perp via LLL, integer kernel C of the 57x88 relation, then CVP enumeration (fpylll) around the all-16 center to recover the small rows; one recovered row decoded base-33 -> printable flag.
- Lesson: a small-entry hidden row inside a modular linear combination is a hidden subset sum; orthogonal-lattice + CVP (not just LLL) recovers it.


## SOLVED case study: TFC 2026 `rivers` (Jacobian-Conjecture counterexample / polynomial map collision)
- Binary = static C++ + GMP exact rationals. Input: 3 sparse polys P,Q,R in x,y,z
  (monomial = 3 exponent bytes a,b,c <=60, a+b+c<=120, + 8-byte double coeff).
- Program computes det(Jacobian(P,Q,R)) with truncated mult (overflow of any exponent
  beyond 60 or total 120 => fail). Phase 1 wants det(JF) = single nonzero constant.
  Phase 2: 6 doubles = two points g1,g2; wants g1 != g2 AND F(g1)==F(g2).
- So the task is a non-injective polynomial map with constant Jacobian = JC counterexample.
- ANSWER: Alpöge (July 2026) explicit JC counterexample in C^3, det JF = -2:
    F1 = x^3 z - 3 x^2 y + 2 x
    F2 = -3 x^3 y^2 z + 9 x^2 y^3 - 6 x^2 y z + 12 x y^2 - 3 x z + y
    F3 = -x^3 y^3 z + 3 x^2 y^4 - 3 x^2 y^2 z + 7 x y^3 - 3 x y z + 4 y^2 - z
  Fiber over (0,2,0): (-1,2,-8), (0,2,16), (1,-1,-5) all map to (0,2,0).
  Use g1=(-1,2,-8), g2=(0,2,16). All coeffs integers -> exact doubles.
- References: https://aaronlou.com/jacobian_counterexample_derivation.pdf
  (Deriving an Explicit Polynomial Counterexample to the Jacobian Conjecture, 20 July 2026).
