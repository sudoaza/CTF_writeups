# Reversing techniques

## Common styles
- Obfuscated binary/script; game that hides a flag; crackme; VM; JIT (V8).

## Key techniques
1. Recon: `file`, `strings`, `readelf`, `objdump -d`, `checksec`; run with input.
2. Static: Ghidra/rizin/radare2; find main, flag check (strcmp/memcmp), xrefs to "flag"/"correct".
3. Dynamic: gdb breakpoints, ltrace/strace; patch jumps (NOP), keygen the check.
4. Deobfuscation: detect packing (upx -d), control-flow flattening, opaque predicates, string encryption -> decrypt in gdb or reimplement.
5. Python/pyc: `uncompyle6`/`decompyle3`/`pycdc`; JS obfuscation -> de4js/beautify.
6. Game challenges: reverse the win condition or cheat (patch score/level).
7. .NET: dnSpy/ILSpy; Java: jadx/CFR.

## SEARCH
- "<challenge> reversing writeup", "deobfuscate <tool> writeup"

## References
- https://book.hacktricks.wiki/en/reversing-and-exploiting/


## SOLVED case study: TFC 2026 `minigame` / `minigame2`
- Game binaries hide a flag behind a key/ore gate. Static reverse (objdump/ghidra) found the key data and the flag-hash function; gdb `call` of the flag-generation function printed the flag directly (minigame: key 0x1000880 -> fn 0x11ef760 -> flag 0x1406630; minigame2: key 0x10008b0 -> fn 0x11f0d30 gated on ore quotas -> flag 0x140763b).
- Lesson: for game/crackme binaries, locate the flag buffer and the function that writes it, then use gdb `call` to run it with the right args instead of fully reversing the logic.

## White-box AES (LumAES-style) key recovery via DFA
- AArch64 whitebox AES from cproc + encrt: two encrypted bodies. Decrypt encrt in Python: state=(0x1f*keylen+7)&0xff once, then per byte state=(state+key[i%keylen]+i)&0xff, buf[i]^=state.
- Recognize table shape: wb_tii/wb_tiii 144x256x4B (rounds 1-9), wb_xor nibble XOR tables, wb_tv 16x256x1B (final round). First 16 wb_tii indices = plaintext bytes in ShiftRows order (identity input encoding).
- Emulate whitebox with unicorn (map .text + decrypted body + .data + stack; hook rand). out=AES_encrypt(in).
- DFA: patch a round-9 TII table entry (e.g. table 128 idx^1) -> exactly 4 ciphertext bytes change (column pattern {0,13,10,7} etc). Solve K10 with AES inverse-S-box + MixColumns coefficient constraints (gf_mul 2/3), then invert AES-128 key schedule.
- Example flags/keys in lumaes notes.


## SOLVED: TFC CTF 2026 `Project Americas` (Go win64 PE custom container)
- Static-reversed a Go 1.26.7 win64 exe (no container needed). Flag.txt (256B, magic `RSC\x07\xf1\x9aD\xc3`) is a doubly-encrypted container.
- Recovered the manifest id from the stub DLLs: each DLL .rdata holds `!AMERICAS-20dbcdd7061b4ccabfe947ef` -> id = `AMERICAS-20dbcdd7061b4ccabfe947ef`.
- Reimplemented the whole crypto in pure Python (verified blockEncrypt/blockDecrypt and runProgram against the real PE bytes with unicorn):
  - `hashParts(parts)` = SHA256 over concat(le32(len(part)) || part).
  - `runProgram`: 8x u32 VM, 4 passes over a 137-word program (from patch_06.dat: `RPFVM01\n` + ascii85 -> streamXOR(key=hashParts(["Project-Americas/stage-1", id])) -> reverse -> gzip -> `MATHVM1\0` + count + sha256 check). Key K = (pass*0xc2b2ae35) ^ (idx*0x85ebca6b ^ hi32(inst)); 8 ops (add-rotl, xor-rotl, mul-or, rotl, murmur3 mix, xtime, swap). Opcode 7 reads `tmp = reg[dst]+reg[src2]` BEFORE overwrite.
  - `streamXOR`: state seeded from hashParts(["TFCCTF/americas/stream/v1", key]) |1; every 64 bytes state=rol64(state ^ ((i+1)*0x9e3779b97f4a7c15),23); then xorshift64 (^<<13, ^>>7, ^<<17); byte ^= (state>>29) ^ key[i%kl].
  - `deriveMaterial(id, part3, prog, seed32, cap)`: H0=hashParts(["TFCCTF/key-ladder/v4", seed32, id, part3]); then per block H=hashParts(["register-fold", H, runProgram(H, k^0x564d0000, prog)]); material = H-blocks.
  - seed32 = XOR of 3 DLL shards: shard = .rdata[idx("TFCSHARD/V1\0")+14:+46] ^ hashParts(["Microsoft CodeView RSDS", id, dllname, [idx+1,'G','T','A']]).
  - blockEncrypt/Decrypt: 4x u32 Feistel, 36 rounds, keys S[i]=rol32(0x9e3779b9*i ^ material[i&15], (11*i)&31).
  - Container CBC-like mixing (mask XOR prev-block XOR plaintext before block cipher): seal path mask = (((b>>4)*0x2f+31j)^0xa5) + rol8(13j&0xff,(b>>4)&7); flag path mask = (b>>4)*0x1d+17j. NB `ROLL` here is an 8-bit rotate (R11B), not 32-bit.
  - sealContainer: header 0x30B, HMAC-SHA256(key=material[64:96], "RSC7-AUTH-V4"||out[:0x30+padded_len]). decryptFlag outer container ("TFCENC3\0"): HMAC(key=material[64:96], data[:len-32]), part3 = salt1 only, blockDecrypt + salt2 chaining.
- Unseal flag.txt -> outer "TFCENC3" container -> decryptFlag -> `TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}`.


## Partial: TFC 2026 `mccrab3` (custom Rust HTTP proxy + MT game)
- Setup: Rust "proxoxy" deny-list proxy (client->8888->gunicorn 8900) with config rules; Flask /flag needs header brevski==george; game /random_ahh_game gives flag at draw_count==60.
- Reverse: proxy is NOT stripped (symbols). Rule engine http_rule_matches: Eq uses regex (method case-insensitive, path case-sensitive), Contains uses literal byte substring. Fields supported: method/path/body/version/headers.X/cookies.X (headers and cookies are SEPARATE arrays; cookies parsed from Cookie header). Special-cased headers (host/connection/upgrade/content-length/transfer-encoding) stored in dedicated fields, NOT the generic list.
- Key findings: header name/value validation is byte-identical to gunicorn 26.2.0 (proxy lowercases names + '_'->'-'; gunicorn uppercases + DROPS '_' names). CL: proxy comma-splits and requires all parts EQUAL (gunicorn isnumeric+int rejects commas). chunked: proxy stricter. no-CL/no-TE: proxy zero-body vs gunicorn EOF => proxy never consumes MORE => classic smuggling impossible. kind<0 rule-skip only on backend-side codec instance.
- Dead ends confirmed: obs-fold (gunicorn 400), duplicate headers join with ',' (never 'george'), chunked trailers not exposed to WSGI, LF-only rejected, obs-text no discrepancy, underscore header names dropped by gunicorn.
- MT game: 60 distinct draws required (P=2.2e-18); even with full MT prediction the game is unwinnable (cannot skip unsafe picks, CHEAT once/game). Do NOT sink time into MT19937 reconstruction for this challenge.
- Lesson: for "custom proxy + backend" REV, first diff the proxy parser against the exact backend version (gunicorn 26.x added METHOD_BADCHAR_RE rejecting lowercase methods, RFC9110 value validation, header_map=drop for '_'); a planted parser bug may live in response-direction parsing or validate_request_head, not in header value/name handling.
