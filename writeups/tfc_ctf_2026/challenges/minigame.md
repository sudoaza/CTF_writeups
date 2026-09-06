# minigame

`minigame` is a reversing challenge (340 pts, 27 solves) that ships one
statically-linked, stripped x86-64 ELF. It is a small Minecraft/"redstone"-style
minigame whose flag vault is gated behind a lever-sequence cipher. Key idea:
skip the game entirely — in gdb, write the 16-byte vault key into the buffer the
lever logic fills, `call` the flag-generation routine directly, and dump the
flag.

## Recon

```
$ file minigame
minigame: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ strings -a minigame | grep -iE 'lever|vault|redstone|moon'
DEFEAT CLOCKWORK MOON TO AUTO OPEN THE FLAG VAULT
FOLLOW THE COMPASS  DEFEAT THE FINAL BOSS TO OPEN THE FLAG VAULT
WRONG LEVER  SEQUENCE RESET
CIPHER ACCEPTED  VAULT OPEN
LEVER
REDSTONE
INPUT   AIM AT LEVER AND PRESS F
```

The strings already tell the story: pull levers in the right order, get the
flag vault. A wrong lever resets the sequence, and `CIPHER ACCEPTED  VAULT OPEN`
is the success message.

## Analysis

Observation: the "game" is a lever-sequence puzzle — a redstone vault cipher.
Playing it legitimately means finding the right lever order, which is tedious
and irrelevant to the flag itself.

Static analysis located the vault logic:

- The 16-byte vault cipher key is the array at `0x1000880`:
  `05 01 06 02 07 00 03 04 01 07 02 05 00 06 04 03`.
- The correct lever sequence stores that key into the buffer at
  `0x140661e..0x140662d` and jumps into the vault-open routine at `0x11ef760`.
- `0x11ef760` hashes the key and XORs the result against a table at
  `0x100f7d5..0x100f7fb`, writing 39 flag bytes to `0x1406630`.

Hypothesis: the whole game is just a gate in front of `0x11ef760`. If we patch
the key buffer ourselves and call the function, we never need to touch a lever.

Confirmation: doing exactly that in gdb produces the flag. The technique is the
standard **gdb `call` shortcut** for game-vault reversers — locate the
flag-generation function and its precondition buffer, satisfy the preconditions
in memory, `call` the function, and dump the output.

## Exploit

1. **Find the key and the flag function.** Static analysis (IDA/Ghidra) gives
   the key at `0x1000880`, the input buffer at `0x140661e`, and the vault-open
   routine at `0x11ef760`.

2. **Write the key into the buffer the game would fill.** Break at `main`, run,
   then set 16 bytes at `0x140661e`:

   ```
   $ gdb -q ./minigame
   (gdb) break main
   (gdb) run
   (gdb) set {unsigned char [16]}0x140661e = {0x05,0x01,0x06,0x02,0x07,0x00,0x03,0x04,0x01,0x07,0x02,0x05,0x00,0x06,0x04,0x03}
   ```

3. **Call the flag routine directly.**

   ```
   (gdb) set $vault_open = (void (*)(void))0x11ef760
   (gdb) call $vault_open()
   ```

   This runs the hash-and-XOR and writes the flag to `0x1406630`.

4. **Dump the 39 flag bytes.**

   ```
   (gdb) x/39bx 0x1406630
   ```

   The 39 bytes decode to the flag. Note: after generation `0x1406657` is set
   to `0x27` (39, the flag length) as a marker — it is not part of the flag.

## Full chain

```
$ gdb -q ./minigame
(gdb) break main
(gdb) run
(gdb) set {unsigned char [16]}0x140661e = {0x05,0x01,0x06,0x02,0x07,0x00,0x03,0x04,0x01,0x07,0x02,0x05,0x00,0x06,0x04,0x03}
(gdb) set $vault_open = (void (*)(void))0x11ef760
(gdb) call $vault_open()
(gdb) x/39bx 0x1406630
```

## Flag

`TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d}`

## Lessons

- For game-vault reversing, find the flag-generation function and its
  precondition buffer, then `call` it in gdb — you never have to play the game.
- Game flag buffers often append one extra byte equal to the flag length after
  generation; strip it before submitting.
