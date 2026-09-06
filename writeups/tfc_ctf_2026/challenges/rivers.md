# rivers

**Flag:** `TFCCTF{even_math_is_cooked_its_so_joever}`

# rivers — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
CRYPTO — 239 pts — dynamic netcat — ~58 solves.
- Brief: 'cry me a rivers'
- Required skills: pwntools + sage (LLL), PRNG/stream analysis.
- First hypotheses: 'rivers' pun on a stream/LCG/PRNG (e.g. Mersenne/River); recover PRNG state from outputs, predict, decrypt.


## 2026-09-05 15:52:19Z — SOLVED locally (exploit ready, waiting for instance slot)

FINDINGS:
- Reversed the static C++ binary (GMP-backed exact rationals). Input = 3 groups, each
  [2-byte LE count][count x (3 exponent bytes a,b,c + 8-byte double coeff)]. Exponents
  must satisfy a,b,c <= 60 and a+b+c <= 120.
- The program builds 3 sparse polynomials P,Q,R in x,y,z and computes the 9 partial
  derivatives (Jacobian matrix), then the determinant det(Jacobian(P,Q,R)) using
  truncated polynomial multiplication (any term exceeding exponent<=60 / total<=120
  sets an overflow flag and FAILS).
- Phase 1 requires det(JF) = single nonzero constant term.
- Phase 2 reads 6 doubles (two points g1,g2), requires g1 != g2, then requires
  F(g1) == F(g2) where F = (P,Q,R).
- This is exactly: find a non-injective polynomial map with constant Jacobian =
  a counterexample to the Jacobian Conjecture.

SOLUTION:
- The challenge is based on the July 2026 Alpöge counterexample to the JC in C^3
  (see aaronlou.com/jacobian_counterexample_derivation.pdf):
    F1 = x^3 z - 3 x^2 y + 2 x
    F2 = -3 x^3 y^2 z + 9 x^2 y^3 - 6 x^2 y z + 12 x y^2 - 3 x z + y
    F3 = -x^3 y^3 z + 3 x^2 y^4 - 3 x^2 y^2 z + 7 x y^3 - 3 x y z + 4 y^2 - z
  det JF = -2 (constant).
  Three-point fiber: F(-1,2,-8) = F(0,2,16) = F(1,-1,-5) = (0,2,0).
- Payload (all coeffs are integers, exactly representable): P=F1 (3 terms),
  Q=F2 (6 terms), R=F3 (7 terms), g1=(-1,2,-8), g2=(0,2,16).
- VERIFIED locally: binary prints the FLAG env var for this payload.

LIMITATIONS:
- Needed the external Alpöge paper (July 2026) to get the map; without it this is an
  open-problem counterexample and not realistically derivable.
- Coefficients happen to be integers; if they had denominators, doubles might not
  represent them exactly.

NEXT:
- Start dynamic instance, send payload, read flag, verify ok:true via API, write flag.txt.


## 2026-09-05 16:28:20Z — SOLVED

FINDINGS:
- Connected via pwntools remote(host, 1337, ssl=True, sni=host). Plain TCP gives HTTP 400
  (edge expects TLS). Raw ssl socket returned raw TLS-record bytes; pwntools ssl=True worked.
- Flag: TFCCTF{even_math_is_cooked_its_so_joever}
- API submit returned ok:true. flag.txt written.
- Container stopped.
