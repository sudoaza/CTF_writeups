# minigame2

`minigame2` (367 pts, 21 solves) is the "now more annoying" sequel to `minigame`
— a reversing challenge shipping one statically-linked, stripped x86-64 ELF. It
is the same redstone game with extra gates: ore quotas, gear tiers, and a soul
quota all have to be satisfied before the flag vault opens. Key idea: the flag
routine `0x11f0d30` is gated behind several in-memory preconditions; satisfy
them directly in gdb and `call` the routine.

## Recon

```
$ file minigame2
minigame2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ strings -a minigame2 | grep -iE 'lever|vault|ore|soul|gear|redstone'
FORGE SOUL PICK AND BLADE FIRST
MINE EVERY ORE QUOTA  THEN DEFEAT THE FINAL BOSS TO OPEN THE FLAG VAULT
HARDMODE UNLEASHED  SOUL ORE SPREADS
HARDMODE  MINE SOUL ORE AND FIND CYAN ALTAR
IRON GEAR -> HELLSTONE GEAR -> HARDMODE SOUL GEAR
GEAR ORDER IRON  THEN HELLSTONE  THEN HARDMODE SOUL AND CRYSTAL
MINED COAL  IRON  HELL  CRYS  SOUL
VAULT KEY ACCEPTED  ORE SEAL STILL ACTIVE
WRONG LEVER  SEQUENCE RESET
CIPHER ACCEPTED  VAULT OPEN
REDSTONE
```

The extra difficulty versus `minigame` is visible in the strings: you must mine
ore quotas (`COAL IRON HELL CRYS SOUL`), upgrade gear in order, and only then
does the lever cipher open the vault (`VAULT KEY ACCEPTED  ORE SEAL STILL ACTIVE`
means the key alone is not enough).

## Analysis

Static analysis found that flag generation is the function at `0x11f0d30`, and
it is gated on several conditions that the game normally establishes:

- `0x140763a == 1`
- `0x1405239 == 1` (cipher accepted)
- mined quotas at `0x1402dfa` `>=` `[2,4,4,5]` (the required values live at
  `0x1000840`)
- `0x1402e02 > 4` (soul quota)

The cipher key is the same 16 bytes as `minigame`, at `0x10008b0`:
`05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03`. Entering the levers
correctly stores it to `0x1405228..0x1405237`.

`0x11f0d30` hashes those 16 key bytes — obfuscated, with constants
`0x7defd73b4593394` and `0xc3a5c85c97cb3127` and a lookup table at `0x11b87a8` —
and writes 54 flag bytes to `0x140763b..0x1407670`. `0x1407671` is set to `0x36`
(54) as a marker.

Hypothesis: like `minigame`, the game is only a gate. If we set all the
precondition bytes in memory and call `0x11f0d30`, we get the flag without
playing. Confirmation: doing so in gdb dumps the 54-byte flag. The obfuscated
hash never needs to be understood — we only need to invoke it.

## Exploit

1. **Set the gates.** Break at `main`, run, and satisfy every precondition in
   memory:

   ```
   $ gdb -q ./minigame2
   (gdb) break main
   (gdb) run
   (gdb) set *(unsigned char*)0x140763a = 1
   (gdb) set *(unsigned char*)0x1405239 = 1
   (gdb) set {unsigned char [4]}0x1402dfa = {2,4,4,5}
   (gdb) set *(unsigned char*)0x1402e02 = 5
   ```

2. **Install the cipher key** into the buffer the lever logic fills
   (`0x1405228..0x1405237`):

   ```
   (gdb) set {unsigned char [16]}0x1405228 = {0x05,0x01,0x06,0x02,0x07,0x00,0x03,0x04,0x01,0x07,0x02,0x05,0x00,0x06,0x04,0x03}
   ```

3. **Call the flag routine directly.**

   ```
   (gdb) set $gen = (void (*)(void))0x11f0d30
   (gdb) call $gen()
   ```

4. **Dump the 54 flag bytes.**

   ```
   (gdb) x/54bx 0x140763b
   ```

   The 54 bytes decode to the flag. `0x1407671` is set to `0x36` (54) as a
   marker and is not part of the flag.

## Full chain

```
$ gdb -q ./minigame2
(gdb) break main
(gdb) run
(gdb) set *(unsigned char*)0x140763a = 1
(gdb) set *(unsigned char*)0x1405239 = 1
(gdb) set {unsigned char [4]}0x1402dfa = {2,4,4,5}
(gdb) set *(unsigned char*)0x1402e02 = 5
(gdb) set {unsigned char [16]}0x1405228 = {0x05,0x01,0x06,0x02,0x07,0x00,0x03,0x04,0x01,0x07,0x02,0x05,0x00,0x06,0x04,0x03}
(gdb) set $gen = (void (*)(void))0x11f0d30
(gdb) call $gen()
(gdb) x/54bx 0x140763b
```

## Flag

`TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying}`

## Lessons

- The "more annoying" sequel only added more in-memory gates; the same gdb
  `call` shortcut defeats all of them at once.
- An obfuscated hash (custom constants + lookup table) is irrelevant when you
  can call the function that uses it and dump its output.
