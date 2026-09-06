# LarpIn

Status: BLOCKED (unsolved). Web — a black-box dynamic HTTP instance of a Flask/Gunicorn
"LinkedIn clone" (same codebase as the larpin2 / larpbrev image). The flag sits behind a
premium gate: `POST /premium/activate` with a per-instance 64-hex token, then `GET /premium`.
Key idea: the intended solve is CSS-only exfiltration of the premium token from a
reported-profile bot view, but this deployment has no report/bot trigger, so the token
never leaks.

## Recon
- No attachment (black-box). Description: "There is no limit to the larp."
- Identified the app as the Flask/Gunicorn LinkedIn clone, **not** the public Rails repo
  `github.com/joeamroo/larpin` (that Rails repo + CVE-2026-66066/KindaRails2Shell are red
  herrings). Static assets are byte-identical to the larpin2 / larpbrev image.
- Session: Flask signed cookie `{"user_id":N}`, HttpOnly, SameSite=Lax. Signing secret not
  in ~500 common guesses.
- CSP on every response (nonce random per request):
  `default-src 'none'; script-src 'self' 'nonce-<random22>'; style-src * 'unsafe-inline';
  img-src * data: 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'self';
  frame-ancestors 'none'`
- Premium: `POST /premium/activate` gates premium; `__USER_CONFIG__.premiumToken` is empty
  for non-premium users; bots (ids 1-14) are premium. Admin bot is id 1 "Trust & Safety".
- `/js/messages.js` uses `innerHTML = sanitizeMessage(raw)` — an XSS sink (the larpin2 build
  switched this to `textContent`).

## Analysis
- Observation: `messages.js` writes message text into `innerHTML` through a flawed regex
  sanitizer (removes `<script>`, `javascript:`, rewrites `on\w+=` to `blocked=`, and strips
  `object/embed/applet/iframe/meta/base`). larpin2 fixed it with `textContent` + a message
  charset whitelist; this first build deliberately kept the sink.
- Hypothesis: stored XSS in messages; have a bot read the message and leak the premium token
  or flag.
- Confirmed then rejected: the sanitizer bypass works locally — `onerr<iframe>or=` becomes
  `onerror=` (iframe removal rejoins the handler). But `<script>` inserted via `innerHTML`
  does not execute, and CSP `script-src 'self' nonce-<random>` blocks all inline handlers
  (verified in Chromium). The sibling's `on&#101;rror` idea fails because HTML5 does not
  decode character references in attribute names. No bot reads messages: the admin bot only
  auto-replies to job applications server-side, and no headless browser was ever observed.
- Conclusion: the messages XSS is a dead end. The flag is behind the premium token, and the
  intended leak (CSS exfiltration through a reported-profile bot) requires a report endpoint
  that is absent in this deployment.

## What we tried
1. XSS in messages: payload `onerr<iframe>or=` -> sanitized to `onerror=`, but CSP nonce
   blocks inline handlers and innerHTML `<script>` never runs; no bot (webhook `<img>` /
   `<svg><style>@import` markers never fired).
2. Premium token brute force: ~200 themed/hash/flags, then 4-digit / 4-hex with fresh-account
   rotation (rate limiter ~99 req/22s is per-session; a new cookie resets the bucket). No hit;
   the token is a per-instance 64-hex value.
3. Token leak hunt: no source maps (`*.js.map` / `*.css.map` -> 404), no token/secret/flag in
   any static asset (`/js/*.js`, `/css/style.css`), no `/premium.js` `/config.js`
   `/manifest.json` `/sw.js`.
4. IDOR / SQLi / SSTI / mass-assignment / session-forge: all negative. CV extension whitelist +
   basename + `text/plain` attachment; CV/applicant views ownership-checked;
   `/premium/activate` mass-assignment leaves `isPremium` false; Flask `SECRET_KEY` not
   recoverable.
5. Report/bot trigger: no `/report` route (`POST /report` -> 405); fuzz of ~300 report-like
   paths (GET/POST/PUT/DELETE/PATCH) all 404/405; no headless bot on apply/DM/connect/like/
   comment.
6. Format oracle on `/premium/activate`: empty -> "Please provide a valid premium token"; any
   non-empty (1..100 chars, hex/decimal/word/upper) -> "Invalid premium token". Flat — no
   length/charset oracle.

## Blocker
The premium token is a per-instance 64-hex value with no observable leak path. The intended
solve (UNbreakable 2026 "larpin" writeup) is CSS-only exfiltration of `premiumToken` from a
rendered profile by a headless report bot, but this deployment has no `/report` route and no
headless browser. Open question: what TFC-specific trigger makes a premium bot browse
attacker-controlled profile/message content (or is there another leak)?

## Lessons
- `innerHTML` + a regex sanitizer is an XSS sink, but a strict CSP (`script-src 'self'
  nonce-random`) plus "no victim" makes it unexploitable — confirm a bot/view exists before
  investing in stored XSS.
- A per-instance 64-hex secret with a flat error oracle is not brute-forceable; you need an
  exfil primitive (CSS/HTML injection + a victim) or a read primitive.
- Business-logic hints can mislead: "no limit" maps to the per-session rate limiter, not the
  actual gated resource.
