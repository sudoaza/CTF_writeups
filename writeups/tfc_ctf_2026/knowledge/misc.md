# Misc / OSINT techniques

## Common styles
- Discord/OSINT, rules flag, regex/encoding puzzles, API/graphql, hardware.

## Key techniques
1. OSINT: join the CTF Discord, check #announcements pins for hidden words; Google dorking; username lookup.
2. Rules: read the rules page; the flag is often literally in the rules or in an HTML comment.
3. Encoding: try base64/hex/rot13/url; CyberChef chain; `file` + entropy.
4. Regex: build the exact pattern (e.g. `TFCCTF{...}` in a given grammar).
5. API: probe documented endpoints, GraphQL introspection.
6. Git/web history: `.git` dump, robots.txt, sitemap, backup files (`.bak`, `~`).

## SEARCH
- "<challenge> writeup", "OSINT ctF techniques"

## References
- CyberChef: https://gchq.github.io/CyberChef/


## SOLVED case study: TFC 2026 `Discord Shenanigans v6`
- Static misc/OSINT: the flag word is hidden in the event Discord's #announcements. Find the announcement "Less than half a day until TFC CTF 2026..." and read the message body: the first letters of the body lines form an acrostic (CASTLE) -> wrap in TFCCTF{}.
- Prior years (v5) hid the flag as zero-width chars (U+200B/U+200C) in an announcement or used Twitter steg (holloway.nz/steg). Check both acrostics and invisible chars.
- Lesson: for 'hidden word in #announcements', read the exact raw message text (Discord -> Copy Text -> inspect code points for 8203/8204/65279) AND check first-letters-of-lines acrostics.


## SOLVED case study: TFC 2026 `rules`
- The flag is stated inside the event rules page. Read the rules (web/CTFd rules endpoint) and grep for the TFCCTF{...} literal. No technique.


## SOLVED case study: TFC 2026 `Mid` (misc/game, dynamic netcat)
- The service: 30-char password over [0-9A-Za-z], lexicographic comparison oracle.
  A "mood" is 0 for query_id < switch_at and 1 after (switch_at uniform). Query is
  "<state> <guess>": state==mood -> true smaller/larger/equal (equal prints flag),
  else random smaller/larger.
- KEY gotcha: the attached chall.py said MAX_QUERIES=195, but the live mid2 image
  prints "queries = 220". Always read the live banner; do not trust a stale source.
- Transport: TLS to <deployment>.challs.ctf.thefewchosen.com:1337, PTY echo of each
  input line, CRLF endings, "> " prompt after each answer. Handle the echo line and
  the prompt in the socket reader.
- Strategy: midpoint binary search on state 0 with sparse-early/dense-late probes
  (guess all-zeros on state 0; a "larger" reply is impossible under truthful mood=0,
  so it detects the flip). On detection, roll back to the widest checkpoint that fits
  the remaining budget (size <= 2^R) and finish binary search on state 1.
- Probabilistic: ~93% per attempt at 220 queries; retry fresh connections until
  accepted. (The same idea at 195 queries only reaches ~40% because the info budget
  is far tighter.)
