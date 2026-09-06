# larpin2

Status: BLOCKED (unsolved). Web — "we can stay here or we can go larp", the 500-pt sequel to
LarpIn, a Flask/Gunicorn "LarpIn" LinkedIn clone (image `larpbrev`) with the same premium-token
gate. Key idea: the intended solve is CSS-only exfiltration of the premium token from a
reported-profile bot view, but (a) the report endpoint is missing and (b) this build's
DOMPurify 3.4.14 strips the HTML `<style>` needed to reach the token's script tag.

## Recon
- Pages: `/`, `/auth`, `/feed`, `/network`, `/jobs`, `/jobs/<id>`, `/jobs/manage`,
  `/jobs/new`, `/messages`, `/premium`, `/profile/<username>`, `/profile/edit`,
  `/connect/<id>`, `/post`, `/post/<id>/comment`, `/post/<id>/like`,
  `/games/{tango,queens,pinpoint}`, `/games/<g>/score`, `/games/leaderboard/<g>`,
  `/notifications/read`, `/logout`.
- Session: Flask signed `{"user_id":N}`; bots ids 1-14 (admin=1 "Trust & Safety"), real users
  15+.
- Validations: username `^[a-zA-Z0-9_]+$`; message content
  `^[a-zA-Z0-9 \s'()*+,-./]+$` (blocks `_ ! ? : ; " < > = { }`); CV ext
  {doc,docx,odt,pdf,rtf,txt}, max 4MB.
- CSP: `script-src 'self' nonce-<random>`; `style-src * 'unsafe-inline'`; `img-src * data:`.
- Profile "about" is rendered by `profile.js`: `decodeURIComponent(data-raw)` ->
  `DOMPurify.sanitize` -> `innerHTML` (DOMPurify 3.4.14).
- vs LarpIn (first): `/js/messages.js` uses `textContent` (safe) + a charset whitelist here;
  DOMPurify upgraded 3.2.4 -> 3.4.14. Other JS identical.

## Analysis
- Observation: the server-side HTML sanitizer for about/experience/education KEEPS `<style>`,
  `<b>`, `<i>`, `<img src>`, `<a>`, `<svg>`, `<div>`, `<math>` and strips `on*`,
  `javascript:`, `xlink:href`, `iframe`, `script`. The profile renders "about" through
  DOMPurify into `innerHTML`. CSP allows `style-src * 'unsafe-inline'` and `img-src * data:`.
- Hypothesis: CSS injection in "about" -> exfiltrate the premium token from a premium bot's
  page.
- Confirmed sink: `<svg><style>@import url(WEBHOOK)</style></svg>` and `<img src=WEBHOOK>`
  survive the server sanitizer + DOMPurify 3.4.14 and fire in local Chromium (webhook hit).
- Intended mechanism (UNbreakable 2026 "larpin"): the page embeds
  `window.__USER_CONFIG__ = {..., premiumToken: "<TOKEN>", ...}` in an inline config
  `<script nonce>`. A CSS-only Fontleak-style extractor (`@font-face` + zero-width glyphs +
  GSUB `calt` ligatures on the known prefix `premiumToken: "` + `anchor-size()`/container
  width -> webhook) leaks the token char-by-char from a reported-profile bot view.
  (`extract_premium_token.py` + `make_ctx_font.py` were recovered and staged in `recon/` and
  `solve/`.)
- Confirmed then rejected: the report trigger is absent — `POST /report` returns 405 on BOTH
  larpin and larpbrev; fuzz of ~300 report-like paths all 404/405. No headless bot was
  observed on apply/DM/connect/like/comment (0 webhook hits). On this build DOMPurify 3.4.14
  strips HTML-namespace `<style>` (needed to target `script#viewer-premium-token`) and only
  keeps SVG-namespace `<style>`, which cannot reach the token's script tag.

## What we tried
1. Bot detection: `<img src=webhook>` + `<svg><style>@import url(webhook)</style></svg>` in
   "about" (both survive sanitizer + DOMPurify 3.4.14) + applying to job 1 -> 0 hits after
   10+ min -> no headless browser bot.
2. Report endpoint hunt: POST/GET/PUT/DELETE/PATCH fuzz on `/report`, `/report/<id>`,
   `/report-profile`, `/report_profile`, `/report-user`, `/flag`, `/abuse`, `/moderation`,
   `/trust`, `/profile/<u>/report`, `/post/<id>/report`, `/api/report*`,
   `/notifications/report`... all 404 (GET) or 405 -> no route. No report button/link/"report"
   in any JS.
3. Premium token: 156+ guesses (themed/hash/patterns) invalid; no length/timing oracle; JSON
   body ignored (form field only); token is per-instance random.
4. SQLi / SSTI / IDOR / upload: all negative (parameterized queries; `{{7*7}}` literal
   everywhere; CV ownership-checked; `../x.pdf` accepted but basename-sanitized and never
   parsed).
5. DOMPurify difference: verified 3.4.14 keeps `<svg><style>@import` but strips HTML
   `<style>`; the SVG style survives and fires in Chromium, but cannot reach the token's HTML
   script tag (needs HTML `<style>` or an mXSS/DOMPurify bypass).

## Blocker
Two compounding gaps: (1) the report/bot trigger endpoint (UNbreakable's `POST /report`) does
not exist in this deployment, so there is no premium victim to browse the injected profile;
and (2) DOMPurify 3.4.14 strips the HTML `<style>` required to target
`script#viewer-premium-token` (the SVG `<style>` that survives cannot reach it). Open
question: the exact TFC trigger that makes the admin/premium bot render a profile, and/or a
DOMPurify 3.4.14 mXSS that yields HTML `<style>`.

## Lessons
- CSS-only exfiltration needs both a surviving style sink AND a victim that renders the secret
  in a reachable node; version bumps (DOMPurify 3.2.4 -> 3.4.14, innerHTML -> textContent) are
  the author's patch signal and reveal the intended vuln.
- `<svg><style>` survives DOMPurify while HTML `<style>` is stripped — namespace matters; test
  both before assuming a CSS-injection sink is useful.
- A report/bot endpoint can be the whole linchpin: without it, a perfect exfil primitive is
  useless.
