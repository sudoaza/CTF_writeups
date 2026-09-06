# minigame

**Flag:** `TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d}`

# minigame — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05 12:05:31 — SOLVED
- Flag: TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d} (accepted by platform, ok:true)
- Method: static analysis + gdb. The flag vault cipher key is the 16-byte array at 0x1000880
  (05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03). Correct lever sequence triggers 0x11ef760,
  which hashes the key and XORs with a table at 0x100f7d5..0x100f7fb to produce 39 flag bytes at 0x1406630.
- Used gdb: break at main, set 0x140661e..0x140662d = key, call 0x11ef760, dump 0x1406630.
- Note: 0x1406657 is set to 0x27 after generation; not part of the flag.
