# Discord Shenanigans v6

**Flag:** `TFCCTF{castle}`

# Discord Shenanigans v6 — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
MISC/OSINT — 50 pts — static — ~185 solves (easiest open).
- Brief: 'You already know. We don't want this to be guessy. Wrap the hidden word in TFCCTF{}. It's in #announcements.'
- Required skills: Discord account, join the TFC CTF Discord, read #announcements history.
- First hypotheses: hidden word embedded in a pinned/announcement message (maybe spoiler/embed/Zalgo); wrap in TFCCTF{...}.
[2026-09-05T15:04:31.760335Z] Start. Retrieved challenge metadata; rules challenge already solved by team (may hold Discord invite).
[2026-09-05T15:06:51.653720Z] Found Discord invite https://discord.gg/nVYv3mHKUf (guild TFC CTF, id 860668879953199144, 3325 members). V5 writeup (jiegec) shows prior technique: hidden U+200B/U+200C zero-width chars in announcement -> binary -> flag. V6 brief says hidden WORD in #announcements, "not guessy".
[2026-09-05T15:06:51.654194Z] Parent offered Discord access. Will request raw #announcements content (topic, pins, recent announcements).
[2026-09-05T15:08:38.250227Z] Prepared solve/zw_decode.py for zero-width steganography decoding. Awaiting parent Discord readout of #announcements.
[2026-09-05T15:15:40.852438Z] Got full #announcements HTML. Flag is in message 1545565347506168059 ("Less than half a day until TFC CTF 2026..."). Confirmed by replies 1545735245742084096 ("Use the reply for DISCORD SHENANIGANS v6") and 1545756316939591742 ("discord flag is hidden here, you don t need to reply to anything").
[2026-09-05T15:15:40.852840Z] v5 technique = zero-width steg. v6 says hidden WORD + "You already know." (likely same zero-width trick). Acrostic hypothesis: first letters of the 6 body lines spell C-A-S-T-L-E = CASTLE; title line adds L -> LCASTLE.
