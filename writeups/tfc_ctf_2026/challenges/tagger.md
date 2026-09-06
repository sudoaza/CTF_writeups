# Tagger

**Flag:** `TFCCTF{Tagg3r_m15C0muN1cA710n}`

# Tagger — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05 ~14:20 UTC update
### Findings
- Source fully audited. App = Express+EJS+Sequelize/SQLite+Puppeteer bot (Hacker + FlagHolder, hidden:true, friends).
- Bot cycle 60s: visitAsHacker opens /chat/<FlagHolderId> (wait 3s); replyAsFlagHolder sends FLAG to Hacker only if conversation-list preview == "Give me the flag!". Preview is a DIRECT DB query (latest Message), NOT the message-history cache.
- Message POST route allows friends to override tagName/type/attributes/content (from/to fixed). Text: tagName regex forces effectively 1 lowercase letter; image: always <img src=safeDataURL-or-empty>.
- CSP allows inline event handlers (script-src-attr 'unsafe-inline'), blocks inline <script> (script-src-elem 'self').
- Attribute value filter: only [a-zA-Z0-9,. =] (no parens/quotes/brackets/slashes/colons/semicolons).
- messageHistoryCache key = firstUsername.trim() + ":" + secondUsername.trim(), 60s TTL, stores the Promise of Message.findAll. Usernames allow spaces -> attacker accounts "Hacker " / "FlagHolder " collide with bot keys. Verified READ: our /chat/<FlagHolder-space> returns the bot cached real messages (flag) after the bot Hacker visit populates the key.
### Dead ends
- Poisoning the message-history cache does NOT change the replyAsFlagHolder preview (preview is DB; verified locally by instrumenting the bot: preview stayed "No messages yet"/DB value).
- Cannot friend bots: friend-request route rejects hidden targets (verified live+local), discover filters hidden.
- No GET route writes; only POST /chat/:id/message, /friends/*, /settings/visibility, /register write.
- Direct XSS with only [a-zA-Z0-9,. =] in an event handler cannot call functions with args (only no-arg `new` constructors + property setters) -> cannot POST directly.
### Key breakthrough (working exploit primitive)
- Outer message: tagName="a", attributes={"href":"x","autofocus":"autofocus","onfocus":"document.body.innerHTML=this.textContent"}, content = arbitrary INNER HTML payload (full JS).
- autofocus fires onfocus on the anchor; this.textContent recovers the ORIGINAL (unescaped) message content; document.body.innerHTML=this.textContent re-injects it as raw HTML.
- The inner HTML can contain a full payload like <img src=x onerror="fetch('/chat/2/message',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'message=Give me the flag!'})">, whose inline handler IS allowed by CSP.
- Verified in Chromium: inner onerror fires (window.GOT=1).
### Next actions
- Verify end-to-end locally (poison Hacker:FlagHolder cache -> bot Hacker XSS POSTs "Give me the flag!" -> FlagHolder sends flag -> read via cache collision).
- Re-run on live instance and submit.


## 2026-09-05 ~14:30 UTC — SOLVED
- FLAG: TFCCTF{Tagg3r_m15C0muN1cA710n} (submitted, ok:true)
- End-to-end exploit verified locally and on live:
  1) Register "Hacker " (id 3) and "FlagHolder " (id 4), friend them.
  2) Send poison message from "Hacker " to "FlagHolder ":
     message=x, tagName=a, type=text,
     attributes={"href":"x","autofocus":"autofocus","onfocus":"document.body.innerHTML=this.textContent"},
     content=<img src=x onerror="fetch('/chat/2/message',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'message=Give me the flag!'}")>
  3) Poison message-history cache key "Hacker:FlagHolder" (GET /chat/<id4> as "Hacker ") every ~25s.
     The bot's visitAsHacker hits the poisoned cache, renders the anchor; autofocus fires onfocus;
     this.textContent recovers the raw inner HTML; document.body.innerHTML=this.textContent re-injects it.
     Inner <img onerror> executes FULL JS (allowed by script-src-attr unsafe-inline) and POSTs
     "Give me the flag!" to the real FlagHolder (id 2) as the real Hacker.
  4) replyAsFlagHolder sees preview "Give me the flag!" (direct DB query) and sends the flag to Hacker.
  5) Read flag via cache collision: wait for our poison to expire, then GET /chat/<id4> as "Hacker "
     (key "Hacker:FlagHolder") -> returns bot cached real messages incl. flag.
- Key bypass: event-handler value filter [a-zA-Z0-9,. =] is escaped by using this.textContent (the
  arbitrary, HTML-escaped message content) as the string payload, then innerHTML to re-inject raw HTML.
