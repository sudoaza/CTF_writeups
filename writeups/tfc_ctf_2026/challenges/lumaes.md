# lumaes

`lumaes` (393 pts, 16 solves) is a reversing challenge built around obfuscation
("I heard CTF players love obfuscation!"). It ships one AArch64 ELF: a 5 MB
control-flow-flattened, MBA-obfuscated "maze" that hides a whitebox AES
implementation. Key idea: the maze is a decoy that only reads the input length;
the real check is a whitebox AES, so recover the AES key with differential fault
analysis (DFA) and decrypt the embedded ciphertext.

## Recon

```
$ file challenge
challenge: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, not stripped

$ strings -a challenge | grep -E 'Correct|Nope'
Correct.
Nope.
```

The binary is cproc-compiled and not stripped. Disassembly shows two code bodies
encrypted with a routine (`enc.body.1`); the decryptor is at `0xb52ef4`.

## Analysis

Observation: there are two `encrt`-encrypted bodies. Reversing the decryptor at
`0xb52ef4` gives a tiny stream cipher:

```
state = (0x1f * keylen + 7) & 0xff        # once
for i in range(len(buf)):
    state = (state + key[i % keylen] + i) & 0xff
    buf[i] ^= state
```

Body 1 decrypts with key `ong-hiumee-is-kinda-skibidi` (the check/maze); body 2
with key `no-key-in-here` (the whitebox AES). After decryption, `main` is:

```
if check(input) != 0: print("Correct.")
else:                 print("Nope.")
```

and `check` calls the decrypted body 1 with the input.

Hypothesis 1: body 1 (a 5 MB control-flow-flattened, mixed-boolean-arithmetic
maze full of bait bytes) directly examines the input. This was **disproved**: it
only calls `wb_strlen(input)` and ignores the content — identical registers and
stack for `'A'*64` versus `'B'*64`, and exactly 65 consecutive input reads (a
`strlen`).

Hypothesis 2 (confirmed): the real check is a **whitebox AES**. `flag_blocks=4`
at `0xc25204` and a 64-byte `flag_ct` at `0xc25208`
(`7151ed9c0f52e1b6...da3e4`). The genuine path is reached for length 63 (not
64): body 1 calls `lumaes_encrypt_block` 4 times, PKCS7-pads the 63-byte input
with `0x01` to 64 bytes, and compares the AES blocks against `flag_ct`.

`lumaes_encrypt_block(out=x0, in=x1)` computes `out = AES_encrypt(in)`. Its
whitebox tables are:

- `wb_tii` (144 x 256 x 4 B), `wb_tiii` (144 x 256 x 4 B) — the T-boxes,
- `wb_xor` (nibble XOR),
- `wb_tv` (16 x 256 x 1 B).

The first 16 `wb_tii` indices are the plaintext bytes in ShiftRows order with
**no input encoding**, which is the handle we need for fault analysis.

## Exploit

1. **Decrypt the two bodies** with the recovered `encrt` routine and keys
   (`ong-hiumee-is-kinda-skibidi`, `no-key-in-here`) so the whitebox code is
   visible.

2. **Confirm the maze ignores content** by running body 1 under emulation with
   different inputs and comparing registers/stack — the check path is length
   63, not the maze logic.

3. **Recover the last AES round key with DFA.** The whitebox has no external
   input encoding, so corrupting one round-9 TII entry perturbs exactly one
   column. Patch the round-9 `wb_tii` entries `128/132/136/140`:

   - each patched entry changes exactly 4 ciphertext bytes (one column),
   - the observed fault spread yields equations for the final round key `K10`.

   This is standard **whitebox AES differential fault analysis**: inject a
   fault into the round-9 T-boxes, observe the 4-byte fault pattern, and solve
   for the last round key.

4. **Invert the AES-128 key schedule** from `K10` to recover the master key:

   ```
   5748bc921fb2c852fba0910529f53abe
   ```

5. **Decrypt `flag_ct`.** `AES_decrypt(flag_ct)` with the master key gives the
   53-char flag plus `0x0b` PKCS7 padding:

   ```
   TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
   ```

6. **Verify**: running the binary with the flag prints `Correct.`.

## Full chain

1. Decrypt body 1 (`ong-hiumee-is-kinda-skibidi`) and body 2 (`no-key-in-here`)
   with the `encrt` stream cipher at `0xb52ef4`.
2. Patch round-9 `wb_tii` entries `128/132/136/140`; record the 4-byte fault
   spread per column; solve for `K10`.
3. Invert the AES-128 key schedule -> master key `5748bc921fb2c852fba0910529f53abe`.
4. `AES_decrypt(flag_ct @ 0xc25208)` -> flag + `0x0b` padding.

## Flag

`TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}`

## Lessons

- A huge control-flow-flattened MBA maze can be a pure decoy that only reads
  the input length; check what the "maze" actually does with the bytes before
  deobfuscating it.
- Whitebox AES without external input encodings is vulnerable to classic DFA:
  fault the round-9 T-boxes and solve for the last round key.
