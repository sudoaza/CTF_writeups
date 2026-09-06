# lumaes

**Flag:** `TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}`

# lumaes — running log

Append-only. Timestamp every entry.

## Hypotheses
- H1: whitebox AES check -> recover key, decrypt flag_ct. (CONFIRMED)
- H2: input content checked by maze directly. (DISPROVED - maze only reads length)

## Findings
- 2026-09-05T13:45Z: `challenge` is AArch64 ELF, cproc-compiled, not stripped. Two encrt-encrypted code bodies (enc.body.1).
- encrt decryption algorithm (from disasm of enccrypt @0xb52ef4): state = (0x1f*keylen+7)&0xff once; per byte state=(state+key[i%keylen]+i)&0xff; buf[i]^=state.
- body1 key "ong-hiumee-is-kinda-skibidi" (check/maze), body2 key "no-key-in-here" (whitebox AES).
- main: check(input)!=0 -> "Correct."; check==0 -> "Nope.". check calls decrypted body1(input).
- flag_blocks=4 @0xc25204, flag_ct (64B) @0xc25208 = 7151ed9c0f52e1b6...da3e4.
- body1 is a 5MB control-flow-flattened MBA maze with bait bytes; it ONLY calls wb_strlen(input) and ignores input CONTENT (verified: identical regs/stack for 'A'*64 vs 'B'*64, and only 65 consecutive input reads = strlen).
- Length 63 (not 64!) takes the real path: body1 calls lumaes_encrypt_block 4x, padding 63-byte input with PKCS7 (0x01) to 64 bytes, compares AES blocks to flag_ct.
- lumaes_encrypt_block(out=x0, in=x1): out = AES_encrypt(in). Whitebox tables: wb_tii (144x256x4B), wb_tiii (144x256x4B), wb_xor (nibble XOR), wb_tv (16x256x1B). First 16 wb_tii indices = plaintext bytes in ShiftRows order (no input encoding).
- DFA key recovery: patch round-9 TII table 128/132/136/140 entry -> exactly 4 ciphertext bytes change per column. Solved final round key K10, inverted AES-128 key schedule.
- Master AES key = 5748bc921fb2c852fba0910529f53abe.
- AES_decrypt(flag_ct) = TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9} + 0x0b padding (53-char flag).
- Verified: binary prints "Correct." for the flag. Submitted ok:true.

## Dead ends
- H2: maze reads input content directly - DISPROVED (unicorn trace + identical stack/regs for different content).
- Static full deobfuscation of the 5MB maze - impractical; skipped in favor of whitebox DFA.

## Limitations
- body2's exact table construction not fully reversed; DFA needed no such detail.

## Next actions
- Done.
