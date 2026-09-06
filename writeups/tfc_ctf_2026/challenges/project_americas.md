# Project Americas

`Project Americas` (410 pts, 13 solves) is a reversing challenge themed as a
"GTA VI L33k!!!" leak. The attachment is a Go 1.26.7 win64 "malware" installer
(PE) that wraps a doubly-encrypted container; the shipped
`challenge_data/flag.txt` is 256 bytes of ciphertext. Key idea: the exe is a
static target — lift its custom block cipher and its Go arithmetic VM into
Python (verifying against the real PE bytes with unicorn) and decrypt both
container layers to reveal the flag.

## Recon

```
$ unzip -l challenge.zip
  Project_Americas_Setup.exe
  bin/oo2core_9_win64.dll
  bin/rage_streaming_x64.dll
  bin/rgsc_socialclub_x64.dll
  challenge_data/flag.txt
  content/patch_06.dat

$ file Project_Americas_Setup.exe
Project_Americas_Setup.exe: PE32+ executable (GUI) x86-64, for MS Windows, 15 sections

$ file bin/rage_streaming_x64.dll
bin/rage_streaming_x64.dll: PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 2 sections

$ xxd -l 64 challenge_data/flag.txt
00000000: 5253 4307 f19a 44c3 0400 3000 f488 6aa3  RSC..D...0...j.
00000010: 1e32 6c3c 3633 2876 65c6 f358 f84d ae44  .2l<63(ve..X.M.D
00000020: 4299 44ea 8f65 42f5 a304 a9c6 b000 0000  B.D..eB.........
00000030: ff81 c6f0 cd40 c5cb 3b63 ed4c 658b 8b3a    .....@..;c.Le..:

$ cat content/patch_06.dat | head -c 16; echo
RPFVM01
+Dk;5];)Bu4!/#Wf(
```

`flag.txt` starts with the container magic `RSC\x07\xf1\x9aD\xc3`. `patch_06.dat`
is `RPFVM01\n` followed by 1223 bytes of ASCII85 (85-char alphabet) that decode
to 978 high-entropy bytes. The Go symbol table shows everything lives in
`pkg tfcctf/americas/internal/challenge` (`cipher.go`, `util.go`, `vm.go`).
Strings include the decoy `AES-256-CBC key=VI_LEAKED_BUILD_2026`, a VIP pattern
`^TFCCTF\{[ -~]{8,160}\}$`, and an id pattern `^AMERICAS-[0-9a-f]{24}$`. Under
wine the GUI is pure narrative ("bring your own debugger") and never decrypts on
its own, so the whole solve is static.

## Analysis

Observation: `decryptFlag` validates the container header, derives a 96-byte
"material" via `deriveMaterial`, checks an HMAC-SHA256 tag, then runs a custom
block cipher with a per-block XOR mixing step and a final PKCS7 unpad. The
container layout (from the lifted `sealContainer`/`decryptFlag`) is:

- `[0:8]`   magic `RSC\x07\xf1\x9aD\xc3`
- `[8:10]`  `0x0004`, `[10:12]` `0x0030`
- `[0xc:0x1c]` salt1 (16 B), `[0x1c:0x2c]` salt2 (16 B)
- `[0x2c:0x30]` datalen (u32 LE; here 176)
- `[0x30:0x30+datalen]` ciphertext, then a 32-byte HMAC-SHA256 tag

The key material is built by `deriveMaterial`: `hashParts` (SHA-256 over
`len||bytes` for each part) chains a constant `register-fold` salt, a 32-byte
seed, and `runProgram` — an 8-register arithmetic bytecode VM whose program is
decoded from `patch_06.dat` and whose seed comes from the three DLL stubs. The
material's first 64 bytes become a 36-entry round schedule; bytes `[64:96]`
become the HMAC key. The cipher itself is a 36-round Feistel over four 32-bit
words (`blockEncrypt`/`blockDecrypt`).

Hypothesis: rather than reverse the whole thing from scratch, **re-lift the
crypto into Python and validate it against the real PE bytes with a unicorn
leaf-runner**. Confirmation: `emulator.py` ran the true `blockEncrypt` /
`blockDecrypt` code bytes and proved `decrypt(encrypt(x)) == x`; the same
approach pinned down the VM. The technique is the knowledge-base
"relift + unicorn PE-leaf runner": execute a target Go function's own bytes with
an explicit register/memory layout, then reproduce that exact semantics in a
pure-Python driver that can decrypt the file without running the binary.

There are two nested containers. Decrypting layer 1 (`flag.txt`) yields a second
container with magic `TFCENC3\x00`; decrypting layer 2 yields the flag.

## Exploit

The complete verified solver is reproduced below (this is `re_assets/lift/solver.py`,
run from the challenge folder). Its stages:

1. `decodeProgram` + `streamXOR` + `ascii85_decode`: strip `RPFVM01\n`, ASCII85-decode
   `patch_06.dat`, XOR with the `TFCCTF/americas/stream/v1` keystream, gunzip,
   reverse, and parse the `MATHVM1\x00` header into VM program words.
2. `extractShard`: each 2048-byte DLL stub carries a `TFCSHARD/V1` shard; XOR the
   three shards together to form the 32-byte seed.
3. `runProgram` + `deriveMaterial`: the arithmetic VM (ops 1..7) and the
   `hashParts` chaining that produce the 96-byte material.
4. `schedule` + `block_decrypt`: the 36-round Feistel and its round schedule.
5. Layer 1: HMAC-verify, block-decrypt + CBC-style XOR against the previous
   ciphertext block plus `mask_enc`, then PKCS7-unpad -> outer container.
6. Layer 2: the same machinery with `mask_dec` -> the flag.

```python
#!/usr/bin/env python3
"""Project Americas (TFC CTF 2026) - full static decrypt of flag.txt.
Pure-Python reimplementation of deriveMaterial -> runProgram + both container layers.
Verified against the real Go PE bytes via unicorn (blockEncrypt/blockDecrypt, runProgram)."""
import hashlib, struct, gzip, hmac, os

MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
BASE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.join(os.path.dirname(os.path.dirname(BASE)), "extracted", "challenge")

def rol32(x, n):
    x &= MASK32; n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x

def rol8(x, n):
    x &= 0xff; n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xff if n else x

def hashParts(parts):
    h = hashlib.sha256()
    for p in parts:
        p = bytes(p)
        h.update(struct.pack("<I", len(p)))
        h.update(p)
    return h.digest()

def runProgram(prog, counter, H):
    reg = [0]*8
    words = struct.unpack("<8I", H)
    c = counter & MASK32
    for i in range(8):
        reg[i] = ((i * 0x6a09e667) ^ words[i] ^ c) & MASK32
    for rnd in range(4):
        for idx, inst in enumerate(prog):
            op, dst, src, src2 = inst & 0xff, (inst >> 8) & 0xff, (inst >> 16) & 0xff, (inst >> 24) & 0xff
            hi = (inst >> 32) & MASK32
            K = ((rnd * 0xc2b2ae35) ^ ((idx * 0x85ebca6b) ^ hi)) & MASK32
            if op == 1:
                reg[dst] = (reg[dst] + rol32(reg[src] ^ K, (K ^ reg[src2]) & 31)) & MASK32
            elif op == 2:
                reg[dst] ^= (rol32(K, reg[src2] & 31) + reg[src]) & MASK32
            elif op == 3:
                reg[dst] = (((reg[src] | 1) * (reg[dst] ^ reg[src2])) + K) & MASK32
            elif op == 4:
                reg[dst] = rol32((reg[dst] + K) & MASK32, (reg[src] ^ reg[src2]) & 31)
            elif op == 5:
                v = rol32(((K ^ reg[src]) * 0xcc9e2d51) & MASK32, 15)
                v = (v * 0x1b873593) & MASK32
                reg[dst] ^= (v ^ reg[src2]) & MASK32
            elif op == 6:
                t = (K ^ reg[src] ^ reg[src2]) & MASK32
                reg[dst] ^= ((t * 2) & MASK32) ^ (0x1b if (t >> 31) else 0)
            elif op == 7:
                tmp = (reg[dst] + reg[src2]) & MASK32
                reg[dst] = (K ^ reg[src]) & MASK32
                reg[src] = tmp
    return struct.pack("<8I", *reg)

def deriveMaterial(idb, part3, prog, seed32, cap):
    H = hashParts([b"TFCCTF/key-ladder/v4", seed32, idb, part3])
    mat = b""
    for k in range((cap + 31) // 32):
        H = hashParts([b"register-fold", H, runProgram(prog, (k ^ 0x564d0000) & MASK32, H)])
        mat += H
    return mat

def schedule(mat):
    return [rol32((i * 0x9e3779b9) ^ struct.unpack_from("<I", mat, (i & 15) * 4)[0], (11 * i) & 31) for i in range(36)]

def block_encrypt(blk, keys, rounds):
    w0, w1, w2, w3 = struct.unpack("<4I", blk)
    for r in range(rounds):
        kk = keys[r] ^ w3
        a = rol32((((r * 0x9e3779b9) & MASK32) ^ kk) + w1, (w2 ^ kk) & 31)
        r11 = rol32(kk, r & 31) ^ w2
        r11 = ((r11 * 0x7f4a7c15) & MASK32) ^ a
        b = (((2 * r) & MASK32) ^ 0x85ebca6b) | 1
        b = b * r11 & MASK32
        b = b ^ (b >> 16)
        r11 = (b * 0xc2b2ae35) & MASK32
        m = rol32(w1 ^ w2, (7 * r) & 31) ^ r11
        m ^= m >> 13
        w0, w1, w2, w3 = w1, w2, w3, w0 ^ m
    return struct.pack("<4I", w0, w1, w2, w3)

def block_decrypt(blk, keys, rounds):
    w0, w1, w2, w3 = struct.unpack("<4I", blk)
    for r in range(rounds - 1, -1, -1):
        kk = keys[r] ^ w2
        a = rol32((((r * 0x9e3779b9) & MASK32) ^ kk) + w0, (w1 ^ kk) & 31)
        r10 = rol32(kk, r & 31) ^ w1
        r10 = ((r10 * 0x7f4a7c15) & MASK32) ^ a
        b = (((2 * r) & MASK32) ^ 0x85ebca6b) | 1
        b = b * r10 & MASK32
        b = b ^ (b >> 16)
        r10 = (b * 0xc2b2ae35) & MASK32
        m = rol32(w0 ^ w1, (7 * r) & 31) ^ r10
        m ^= m >> 13
        m ^= w3
        w0, w1, w2, w3 = m, w0, w1, w2
    return struct.pack("<4I", w0, w1, w2, w3)

def ascii85_decode(d):
    out = bytearray(); i = 0; n = len(d)
    while i + 5 <= n:
        v = 0
        for j in range(5):
            v = v * 85 + (d[i + j] - 33)
        out += bytes([(v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255])
        i += 5
    if i < n:
        rem = n - i; v = 0
        for j in range(5):
            c = d[i + j] if i + j < n else ord("u")
            v = v * 85 + (c - 33)
        for _ in range(rem - 1):
            out.append((v >> 24) & 255); v = (v << 8) & MASK32
    return bytes(out)

def streamXOR(src, key):
    state = (struct.unpack("<Q", hashParts([b"TFCCTF/americas/stream/v1", key])[:8])[0]) | 1
    C = 0x9e3779b97f4a7c15; out = bytearray(len(src)); kl = len(key)
    for i in range(len(src)):
        if (i & 63) == 0:
            v = (state ^ ((i + 1) * C)) & MASK64
            state = ((v << 23) | (v >> 41)) & MASK64
        x = state
        x = (x ^ (x << 13)) & MASK64
        x = (x ^ (x >> 7)) & MASK64
        x = (x ^ (x << 17)) & MASK64
        state = x
        out[i] = src[i] ^ ((x >> 29) & 255) ^ key[i % kl]
    return bytes(out)

def decodeProgram(d):
    assert d[:8] == b"MATHVM1\x00" and len(d) == 16 + d[8] * 8
    assert d[10:16] == hashlib.sha256(d[16:]).digest()[:6]
    return list(struct.unpack("<%dQ" % d[8], d[16:]))

def extractShard(dll, idb, dllname, ip1):
    i = dll.find(b"TFCSHARD/V1\x00")
    key = hashParts([b"Microsoft CodeView RSDS", idb, dllname, bytes([ip1, 71, 84, 65])])
    return bytes(a ^ b for a, b in zip(dll[i + 14:i + 46], key))

def mask_enc(b, j):
    return ((((b >> 4) * 0x2f + 31 * j) ^ 0xa5) + rol8((13 * j) & 255, (b >> 4) & 7)) & 255

def mask_dec(b, j):
    return (((b >> 4) * 0x1d) + 17 * j) & 255

def main():
    ID = b"AMERICAS-20dbcdd7061b4ccabfe947ef"
    patch = open(os.path.join(CHAL, "content", "patch_06.dat"), "rb").read()
    prog = decodeProgram(gzip.decompress(streamXOR(ascii85_decode(patch[8:]), hashParts([b"Project-Americas/stage-1", ID]))[::-1]))
    seed32 = b"\x00" * 32
    for ip1, name in [(1, "rage_streaming_x64.dll"), (2, "rgsc_socialclub_x64.dll"), (3, "oo2core_9_win64.dll")]:
        dll = open(os.path.join(CHAL, "bin", name), "rb").read()
        seed32 = bytes(a ^ b for a, b in zip(seed32, extractShard(dll, ID, ("bin/" + name).encode(), ip1)))
    flagf = open(os.path.join(CHAL, "challenge_data", "flag.txt"), "rb").read()
    salt1, salt2 = flagf[0xc:0x1c], flagf[0x1c:0x2c]
    plen = struct.unpack_from("<I", flagf, 0x2c)[0]
    ct = flagf[0x30:0x30 + plen]
    mat1 = deriveMaterial(ID, b"RSC7/runtime-seal/" + salt1, prog, seed32, 96)
    S1 = schedule(mat1)
    assert hmac.new(mat1[64:96], b"RSC7-AUTH-V4" + flagf[:0x30 + plen], hashlib.sha256).digest() == flagf[0x30 + plen:]
    prev, pl = salt2, bytearray()
    for b in range(0, plen, 16):
        D = block_decrypt(ct[b:b + 16], S1, 36)
        for j in range(16):
            pl.append(D[j] ^ prev[j] ^ mask_enc(b, j))
        prev = ct[b:b + 16]
    X = bytes(pl)[:-pl[-1]]
    assert X[:8] == b"TFCENC3\x00"
    mat2 = deriveMaterial(ID, X[0xc:0x1c], prog, seed32, 96)
    S2 = schedule(mat2)
    assert hmac.new(mat2[64:96], X[:len(X) - 32], hashlib.sha256).digest() == X[len(X) - 32:]
    b2c = X[0x2c]
    ptl = len(X) - b2c - 0x52
    src = X[b2c + 0x32:b2c + 0x32 + ptl]
    prev, out = X[0x1c:0x2c], bytearray()
    for b in range(0, ptl, 16):
        D = block_decrypt(src[b:b + 16], S2, 36)
        for j in range(16):
            out.append(D[j] ^ prev[j] ^ mask_dec(b, j))
        prev = src[b:b + 16]
    flag = bytes(out)[:-bytes(out)[-1]].decode()
    print(flag)
    return flag

if __name__ == "__main__":
    main()
```


The verified run:

```
$ python3 re_assets/lift/solver.py
TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}
```

## Full chain

```
cd /root/prime/ctf/thefewchosen/project_americas_47eef538
python3 re_assets/lift/solver.py
```

## Flag

`TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}`

## Lessons

- For Go reversing, don't run the whole GUI: lift the target functions and
  validate a pure-Python reimplementation against the real PE bytes with a
  unicorn leaf-runner (`decrypt(encrypt(x)) == x` is the quickest correctness
  oracle).
- Reverse the container/header/tag semantics *before* the cipher; a two-layer
  custom container is a sequence of independent stages (decode program, extract
  seed, derive material, block-decrypt, unpad).
- The "AES-256-CBC key" string was a decoy — verify which code path actually
  reads a constant before trusting a leaked string.
