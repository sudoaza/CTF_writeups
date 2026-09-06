# minigame2

**Flag:** `TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying}`

# minigame2 — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05 12:08:31 — SOLVED
- Flag: TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying} (accepted by platform, ok:true)
- Method: static analysis + gdb. Flag generation is function 0x11f0d30, gated on:
  0x140763a==1, 0x1405239==1 (cipher accepted), mined quotas at 0x1402dfa >= [2,4,4,5] (0x1000840),
  0x1402e02 > 4 (soul quota).
- Cipher key at 0x10008b0 (16 bytes, same as minigame): 05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03,
  stored to 0x1405228..0x1405237 when levers entered correctly.
- 0x11f0d30 hashes the 16 key bytes (obfuscated, constants 0x7defd73b4593394, 0xc3a5c85c97cb3127, lookup
  table 0x11b87a8) and writes 54 flag bytes to 0x140763b..0x1407670. 0x1407671 is set to 0x36 as a marker.
- Used gdb: break at main, set preconditions, call 0x11f0d30, dump 0x140763b (54 bytes).
