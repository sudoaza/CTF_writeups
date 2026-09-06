# rivers

`rivers` is a crypto challenge served as a TLS netcat binary: submit three sparse polynomials in `x,y,z` whose Jacobian determinant is a constant, and two distinct points with the same image. Key idea: it is an interactive Jacobian Conjecture counterexample, and the July 2026 Alpöge map (constant Jacobian `-2`, non-injective) satisfies both checks.

## Recon

The attachment is a single file, `rivers` (907,968 bytes) — a static C++ binary backed by GMP for exact rational arithmetic. The challenge is dynamic (`netcat`, port 1337) and the instance hostname ends with `.challs.ctf.thefewchosen.com`.

Reversing the binary showed the input grammar:

- 3 groups; each group = `[2-byte LE count][count x (3 exponent bytes a,b,c + 8-byte little-endian double coeff)]`.
- Exponents must satisfy `a,b,c <= 60` and `a+b+c <= 120`.
- The program builds three sparse polynomials `P,Q,R`, computes the 9 partial derivatives (Jacobian `JF`), then `det(JF)` using truncated polynomial multiplication. Any term exceeding `exponent <= 60` / `total <= 120` sets an overflow flag and fails.
- Phase 1: `det(JF)` must be a single nonzero constant term.
- Phase 2: read 6 doubles (two points `g1,g2`), require `g1 != g2`, then require `F(g1) == F(g2)` with `F = (P,Q,R)`.

Observation: a polynomial map with constant Jacobian that is not injective is exactly a counterexample to the Jacobian Conjecture.

## Analysis

Observation -> hypothesis: the two checks are "constant Jacobian determinant" and "two distinct points collide", so the intended solution is a known non-injective polynomial automorphism candidate. Confirmation: the July 2026 Alpöge counterexample to the Jacobian Conjecture in `C^3` (derivation at aaronlou.com/jacobian_counterexample_derivation.pdf) satisfies both conditions:

```
F1 = x^3 z - 3 x^2 y + 2 x
F2 = -3 x^3 y^2 z + 9 x^2 y^3 - 6 x^2 y z + 12 x y^2 - 3 x z + y
F3 = -x^3 y^3 z + 3 x^2 y^4 - 3 x^2 y^2 z + 7 x y^3 - 3 x y z + 4 y^2 - z

det JF = -2 (a constant)

F(-1,2,-8) = F(0,2,16) = F(1,-1,-5) = (0,2,0)
```

All coefficients are small integers, so they are exactly representable as `double`s. This gives phase 1 (`det JF = -2`) and phase 2 (`g1 = (-1,2,-8)`, `g2 = (0,2,16)` collide at `(0,2,0)`).

## Exploit

1. Encode the map and the two points into the binary's wire format (`solve.py`):

```python
import struct

def build(F1, F2, F3, g1, g2):
    out = b""
    for group in (F1, F2, F3):
        out += struct.pack("<H", len(group))
        for (a,b,c,d) in group:
            out += bytes([a,b,c]) + struct.pack("<d", d)
    out += b"".join(struct.pack("<d", v) for v in (*g1, *g2))
    return out

F1 = [(3,0,1,1.0), (2,1,0,-3.0), (1,0,0,2.0)]
F2 = [(3,2,1,-3.0), (2,3,0,9.0), (2,1,1,-6.0), (1,2,0,12.0), (1,0,1,-3.0), (0,1,0,1.0)]
F3 = [(3,3,1,-1.0), (2,4,0,3.0), (2,2,1,-3.0), (1,3,0,7.0), (1,1,1,-3.0), (0,2,0,4.0), (0,0,1,-1.0)]
g1 = (-1.0, 2.0, -8.0)
g2 = (0.0, 2.0, 16.0)

payload = build(F1, F2, F3, g1, g2)   # 230 bytes
```

2. Verify locally: feeding this payload to the local binary prints the `FLAG` environment variable, confirming both phases pass.

3. Connect to the remote instance over TLS and send the payload. Plain TCP to the edge returns `HTTP/1.1 400 Bad Request` (the platform expects TLS), and a raw `ssl` socket returned raw TLS-record bytes; `pwntools` with `ssl=True` worked:

```python
from pwn import remote
r = remote(host, 1337, ssl=True, sni=host)
r.send(payload)
print(r.recvall())
```

The binary prints the flag.

## Full chain

1. `python3 solve.py` (writes `payload.bin`, 230 bytes).
2. `from pwn import remote; r = remote('<instance>.challs.ctf.thefewchosen.com', 1337, ssl=True, sni=host)`
3. `r.send(open('payload.bin','rb').read()); print(r.recvall())`

## Flag

`TFCCTF{even_math_is_cooked_its_so_joever}`

## Lessons

- A "constant Jacobian + collision" challenge is asking for a Jacobian Conjecture counterexample; search the recent literature for an explicit map instead of trying to construct one (it is an open-problem-class construction).
- Keep coefficients exactly representable in the input type: the Alpöge example happens to be integer-coefficient, so `double`s hold it exactly.
- The platform's netcat endpoints speak TLS; plain TCP hits the HTTP edge and returns `400 Bad Request`, so wrap the socket with SSL/SNI.
