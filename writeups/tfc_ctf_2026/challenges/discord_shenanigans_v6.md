# Discord Shenanigans v6

MISC/OSINT challenge: a hidden word lives in the TFC CTF Discord `#announcements`
channel and must be wrapped as `TFCCTF{...}`. Key idea: the hidden word is an
acrostic spelled by the first letters of an announcement's body lines.

## Recon
- Statement: "You already know. We don't want this challenge to be guessy. Wrap the
  hidden word in TFCCTF{}. It's in #announcements."
- Discord invite: `https://discord.gg/nVYv3mHKUf` (guild "TFC CTF",
  id 860668879953199144).
- v5 of this series used zero-width steganography (U+200B/U+200C); v6 changes the
  wording to "hidden WORD" and "not guessy". A zero-width decoder
  (solve/zw_decode.py) was prepared but the real answer was not zero-width steg.

## Analysis
Observation: the full `#announcements` HTML points to message 1545565347506168059
("Less than half a day until TFC CTF 2026..."), confirmed by replies
1545735245742084096 and 1545756316939591742 ("the flag is hidden here...").
Hypothesis: the "hidden word" is an acrostic — take the first letter of each body
line. Confirmation: the six body lines begin with C, A, S, T, L, E → `CASTLE`.

## Exploit
1. Open `#announcements` and locate message 1545565347506168059.
2. Read the first letter of each of the six body lines:
   C · A · S · T · L · E → `CASTLE`
3. Wrap the word in the flag format.

## Full chain
1. Join https://discord.gg/nVYv3mHKUf
2. Open `#announcements` → message 1545565347506168059
3. Acrostic of the body lines → `CASTLE`

## Flag
TFCCTF{castle}

## Lessons
- "Hidden word" + "not guessy" → try a first-letters acrostic before stego tools.
- When a series increments ("v6"), the previous version's trick (zero-width chars)
  is a red herring; re-read the exact wording ("hidden WORD").
