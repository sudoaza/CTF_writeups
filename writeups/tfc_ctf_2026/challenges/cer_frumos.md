# cer frumos

**Flag:** `TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}`

# cer frumos — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## Hypotheses
- 2026-09-05T11:39:59Z H1: Recover MT19937 state from partial getrandbits(48) outputs via GF(2) linear algebra over the MT recurrence.
## Findings
- 2026-09-05T11:39:59Z Confirmed getrandbits(48) = ((w1>>16)<<32) | w0 (first word low32, second word top16 high); getrandbits(16) consumes one word.
- 2026-09-05T11:39:59Z Per iteration: 3 words (48-bit + 16-bit discard). 625 iters = 1875 words, +10 = 1885, key words 1885-1886, nonce 1887-1888.
- 2026-09-05T11:39:59Z Built GF(2) system: 13312 vars (B,C residues of first 624 state words), 23344 equations (full A words + top16 of tempered B). numpy Gauss-Jordan rank 13312 -> unique state.
- 2026-09-05T11:39:59Z Solved, temper()'d future state words, reconstructed key/nonce, AES-CBC decrypted flag.
- 2026-09-05T11:39:59Z FLAG: TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu} (submitted, ok:true)
## Dead ends
- 2026-09-05T11:39:59Z D1: Forgot to temper future state words before building key/nonce -> garbage plaintext. Fixed by tempering x_1885..x_1888.
## Limitations
- 2026-09-05T11:39:59Z none
## Next actions
- 2026-09-05T11:39:59Z none
