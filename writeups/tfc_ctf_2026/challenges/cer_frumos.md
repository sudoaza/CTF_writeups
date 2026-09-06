# cer frumos

`cer frumos` is a crypto challenge that leaks 625 partial MT19937 outputs and then AES-CBC-encrypts the flag with a key/nonce derived from the same generator. Key idea: the twist and temper of MT19937 are GF(2)-linear, so the partial `getrandbits(48)` outputs are enough to solve for the full state and predict the key and IV.

## Recon

`challenge.zip` contains the generator and its output.

```
$ unzip -l challenge.zip
  out.txt    9857
  test.py     575
```

`test.py`:

```python
import random
from secret import flag
from hashlib import sha256
from Crypto.Cipher import AES

random.seed(random.randint(0,2**128))
for i in range(625):
    x = random.getrandbits(48)
    random.getrandbits(16)
    print(x)
for i in range(10):
    x = random.getrandbits(32)
key = sha256(str(random.getrandbits(64)).encode()).digest()
nonce = sha256(str(random.getrandbits(64)).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
enc_flag = cipher.encrypt(flag)
print(f'Enc flag: {enc_flag.hex()}')
```

`out.txt` is 625 lines of 48-bit values (first three shown), then the ciphertext:

```
161631808273530
117122746477184
174494467464970
...
Enc flag: 9b26b51ae9e07e3f0f3c2cf2950ad9bb867d144c480bcf8065c42795136c379a6ec283dbd7ad27813a12565c9be7ff64
```

Observation: we get 625 × 48-bit outputs but never a full 32-bit word in one value, and the key/nonce come from two later `getrandbits(64)` calls.

## Analysis

Observation -> hypothesis: Python's `random` is MT19937, and both the twist recurrence and the temper are linear over GF(2), so the observed partial outputs constrain the unknown initial state linearly. Recover the state by linear algebra, then fast-forward to the key/nonce words.

Word accounting (confirmed while writing the solver):

- `getrandbits(48)` returns two MT words: low 32 bits from `w0` and top 16 bits from `w1`, i.e. `((w1 >> 16) << 32) | w0`.
- `getrandbits(16)` consumes one full word.
- One loop iteration therefore consumes 3 words; 625 iterations = 1875 words; the trailing `for i in range(10): getrandbits(32)` adds 10 words -> 1885.
- The first `getrandbits(64)` (key) is words 1885-1886; the second (nonce) is words 1887-1888.

Technique: MT19937 state recovery from partial outputs. Model the generator as a GF(2) linear system over the first 624 state words and solve with Gaussian elimination; no need for 624 consecutive full outputs.

Confirmation (solver numbers): the system had 13312 unknowns (the B/C residues of the first 624 state words) and 23344 equations (all 32 bits of each full A word plus the top 16 bits of each tempered B word). Numpy Gauss-Jordan reported rank 13312, i.e. a unique state, so the state could be recovered and advanced.

## Exploit

1. Parse `out.txt`: split off the 625 48-bit values and the `Enc flag:` hex line.

2. Build the GF(2) system: unknown = the 624-word MT19937 state (13312 residual unknowns); equations = the 32 bits of each full first word plus the top 16 bits of each tempered second word, for all 625 pairs. Solve with Gaussian elimination (numpy); rank 13312 -> unique state.

3. Advance the solved state to the key/nonce words. Fast-forward through the 10 `getrandbits(32)` calls and then temper words 1885..1888 (the two `getrandbits(64)` calls). (Dead end recorded: forgetting to temper the future words before building key/nonce produced garbage plaintext — the fix is to temper `x_1885..x_1888`.)

4. Reconstruct the AES key and IV exactly as the generator does:

```python
key = sha256(str(key64).encode()).digest()          # key64 from words 1885-1886
nonce = sha256(str(nonce64).encode()).digest()[:16] # nonce64 from words 1887-1888
```

5. Decrypt:

```python
from Crypto.Cipher import AES
flag = AES.new(key, AES.MODE_CBC, iv=nonce).decrypt(enc_flag)
```

The plaintext is the flag (CBC with PKCS#7 padding).

## Full chain

1. `unzip challenge.zip`
2. Recover the MT19937 state from the 625 partial outputs (GF(2) linear system over the twist + temper).
3. Temper words 1885-1886 -> `key64`, words 1887-1888 -> `nonce64`.
4. `key = sha256(str(key64).encode()).digest()`, `nonce = sha256(str(nonce64).encode()).digest()[:16]`.
5. `AES.new(key, AES.MODE_CBC, iv=nonce).decrypt(enc_flag)`.

## Flag

`TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}`

## Lessons

- MT19937 is fully linear over GF(2): any partial word output (even a top-16 slice) is a usable linear equation, so you do NOT need 624 consecutive full outputs.
- Count consumed words per call precisely: `getrandbits(48)` is two words, `getrandbits(16)`/`getrandbits(32)` is one, `getrandbits(64)` is two.
- When predicting future MT outputs, apply the temper transform to the reconstructed state words before using them — raw state words are not the values `getrandbits` returns.
