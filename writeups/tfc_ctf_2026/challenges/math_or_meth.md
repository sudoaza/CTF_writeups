# math or meth?

`math or meth?` is a crypto challenge that hides one planted row (the flag, written base-33) inside a mod-`p` linear combination of many random small rows, and gives only the combination vector `h`. Key idea: the Hidden Subset Sum / Nguyen-Stern orthogonal-lattice attack plus an fpylll CVP enumeration recovers the short planted row.

## Recon

`chall.zip` contains the generator and its output.

```
$ unzip -l chall.zip
  chall.py     674
  output.py  29232
```

`chall.py`:

```python
import secrets
from Crypto.Util.number import getPrime, bytes_to_long

msg = b"?"
n = 57
B = 32
base = B + 1
p = getPrime(1084)

x = bytes_to_long(msg)
row = []
while x:
    row.append(x % base)
    x //= base
if not row:
    row = [0]

m = len(row)
assert n < m
a = [secrets.randbelow(p) for _ in range(n)]
A = [[secrets.randbelow(base) for _ in range(m)] for _ in range(n)]
planted_idx = secrets.randbelow(n)
A[planted_idx] = row[:]

h = [
    sum(a[i] * A[i][j] for i in range(n)) % p
    for j in range(m)
]

print(f"n = {n}")
print(f"m = {m}")
print(f"B = {B}")
print(f"p = {p}")
print(f"h = {h}")
```

`output.py` (first lines):

```
n = 57
m = 88
B = 32
p = 119301150720777274933662695501509740955626946602891370528952095970787257560809073288292367865143559336936973095462967247222965437650423417563382328071486279300189707351744667305699725988689530026126081196256491053523236411080046913084536091276773674969854307158177873388849649966368748953843995987112007606098702694877585018259
h = [11062023887251765802399964251475136603372175851181548754372628461006104087951534775426620175951071805254643322355113317939294904812814226772265437714699761509412617388958028065962582753475202225647999679145096096234935978720112790227267979988978198455988845106493761022958767694963180870919042521905303082694223934243597206511, 63538414859256021332309643677428638529453581246940626399699461227208007077662699310185909206913443424067006077752348555266334801880933125163100949835510635641536082819728830923340234557764470668110158494361440569063170542255665442192219598466953766472883386037754180188902458921121298048260353944215109966560292518678449889540, ...]
```

Observation: `h` is a single mod-`p` combination of 57 hidden rows; every hidden row (including the planted flag row) has entries in `[0, 32]`, and the flag row is the base-33 digits of `bytes_to_long(flag)` written least-significant digit first.

## Analysis

Observation -> hypothesis: recover a short integer vector (the planted row) knowing only its image `h` under a hidden mod-`p` linear form. This is the Hidden Subset Sum / Hidden Linear Combination problem (Nguyen-Stern).

Technique (two stages):

1. Orthogonal lattice: build `L0 = {u in Z^m : u . h ≡ 0 mod p}` and LLL it. The first `m-n = 31` short vectors span `L_x^perp` (the lattice orthogonal to all hidden rows). The integer right kernel of that span is a 57-dimensional lattice `C` that contains every hidden row, including the planted one.
2. Short-vector recovery in `C`: LLL `C`, then enumerate all vectors near the center `(16,...,16)` (the midpoint of `[0,32]^88`) with fpylll CVP enumeration; every vector that lands inside the box `[0,32]^88` is a candidate hidden row.

Confirmation: one enumerated row decoded (LSB-first base-33) to printable ASCII, so it is the planted flag row.

## Exploit

1. Orthogonal lattice: build `L0`, LLL, take the first 31 vectors as `U`, compute the integer kernel `C` (`step1.sage`):

```sage
data = json.load(open(base + "/data.json"))
n = data["n"]; m = data["m"]; q = data["p"]; h = data["h"]
hvec = [Integer(x) for x in h]
hm = hvec[m-1]
invhm = inverse_mod(hm, q)
L0 = matrix(ZZ, m, m)
for k in range(m-1):
    L0[k,k] = 1
    L0[k,m-1] = (-invhm * hvec[k]) % q
L0[m-1,m-1] = q
Lred = L0.LLL()
U = matrix(ZZ, m-n, m)
for r in range(m-n):
    U.set_row(r, Lred[r])
C = U.right_kernel_matrix()   # 57 x 88
```

This yields a 31×88 `U` spanning `L_x^perp` and a 57×88 kernel `C`.

2. LLL-reduce the kernel (`step2a.sage`):

```sage
C = load(base + "/C.sobj")
Cred = C.LLL()
Cred.save(base + "/C_lll.sobj")
```

3. Enumerate short vectors around the box center with fpylll (`enum_real.sage`):

```sage
from fpylll import IntegerMatrix, GSO, Enumeration, LLL
C = load(base + "/C.sobj")
Cred = C.LLL()
B = IntegerMatrix.from_matrix([[int(Cred[r,c]) for c in range(Cred.ncols())] for r in range(Cred.nrows())])
LLL.reduction(B)
M = GSO.Mat(B); M.update_gso()
t = tuple([16]*Cred.ncols())
can = M.from_canonical(t)
E = Enumeration(M, nr_solutions=500)
sols = E.enumerate(0, B.nrows, 22528, 0, can)
# multiply each returned coefficient vector by B, keep rows with all entries in [0,32]
```

Result: 57 unique candidate rows inside `[0,32]^88`.

4. Decode each candidate row as base-33 (LSB-first) and keep the printable one:

```python
def decode(vals, base=33):
    x = sum(d * base**i for i, d in enumerate(vals))  # LSB-first digits
    return x.to_bytes((x.bit_length()+7)//8, 'big')
```

The winning row was:

```
[4, 4, 19, 0, 10, 20, 5, 11, 17, 19, 13, 23, 30, 10, 23, 23, 26, 18, 22, 8, 14, 20, 27, 4, 13, 7, 29, 22, 2, 13, 7, 22, 16, 14, 10, 3, 17, 21, 24, 31, 8, 9, 20, 19, 10, 18, 23, 0, 32, 25, 11, 31, 22, 13, 32, 20, 16, 18, 16, 16, 31, 13, 30, 9, 14, 13, 12, 25, 23, 0, 4, 17, 6, 25, 22, 20, 10, 25, 24, 29, 11, 11, 27, 27, 18, 0, 0, 1]
```

which decodes to:

```
this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs
```

## Full chain

1. `unzip chall.zip`, parse `n, m, B, p, h` from `output.py` into `data.json`.
2. `sage step1.sage` (build `L0`, LLL, extract `U`, kernel `C`).
3. `sage step2a.sage` (LLL `C`).
4. `sage enum_real.sage` (fpylll enumeration around `(16,...,16)`, radius^2 = 22528, `nr_solutions=500`).
5. Decode each candidate row base-33 LSB-first; wrap the printable one in `TFCCTF{}`.

## Flag

`TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}`

## Lessons

- A single mod-`p` combination of hidden short rows is the Nguyen-Stern Hidden Subset Sum setup: orthogonal lattice + kernel + short-vector search recovers the planted row.
- Center the CVP/enumeration at the midpoint of the coefficient box (`(B/2,...,B/2)`) — that is where the planted vector is expected to lie.
- Base-`(B+1)` encoding with `B=32` means the flag digits are just bytes in `[0,32]`; decoding LSB-first reverses `bytes_to_long`.
