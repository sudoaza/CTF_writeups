# math or meth?

**Flag:** `TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}`

# math or meth? — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05 11:48:22 UTC SOLVED
- Identified the scheme as the Hidden Subset Sum / Hidden Linear Combination problem (Nguyen-Stern).
- Step 1: orthogonal lattice attack. Built L0 = {u : u·h ≡ 0 mod p}, LLL on 88x88 basis, took first m-n=31 vectors -> basis U of L_x^perp; computed integer kernel C (57x88) of U.
- Step 2: LLL on C, then fpylll CVP enumeration around center (16,...,16) with nr_solutions=500 and radius^2=22528 -> 57 unique rows in [0,32]^88.
- Decoded each base-33 row (LSB-first) to bytes; one row was printable ASCII: this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs
- Submitted TFCCTF{...} -> platform returned ok:true.
