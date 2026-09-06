# mccrab3

Status: BLOCKED (unsolved). Rev + service — a Rust reverse-proxy ("proxoxy") in front of a
Flask/Gunicorn backend. The flag is `POST /flag` with header `brevski: george`, but the proxy's
deny-list drops any request whose `brevski` header contains "george". Key idea: the challenge is
a proxy-vs-gunicorn HTTP parsing/normalization discrepancy hunt; despite exhaustive differential
testing no bypass was found (the platform showed a handful of solves, so one exists).

## Recon
- Attachment `mccrab3.zip`: `server.py`, `proxoxy` (4.2 MB Rust binary, not stripped, symbols
  present), `config.json`, `Dockerfile`, `entrypoint.sh`.
- `server.py` endpoints:
  - `GET /health` -> `OK`
  - `POST /flag`: `if request.headers.get("brevski") == "george": return FLAG` (otherwise the
    handler returns `None` -> 500)
  - `/random_ahh_game` (GET/PLAY/STOP/CHEAT/RESET/FLAG): flag only if `STOP` with
    `draw_count == 60` (decoy game)
- `config.json`: `codec: "http"`; `allowed_pubkeys: ["<INSERT_PUBKEY>"]`; rules = deny
  `(method == GET AND path == /flag)` OR `(headers.brevski contains "george")`.
- `entrypoint.sh`: `nohup ./proxoxy config.json` then
  `gunicorn -w 1 -k gthread --threads 4 --keep-alive 30 -b 0.0.0.0:8900 server:app`.
- Only port 8888 (proxoxy) is exposed via nodeport; backend 8900 is not reachable from outside.
- `file` / `checksec` / `strings` / radare2: Rust, memory-safe (no overflow angle), crate
  `proxoxy`, custom HTTP/1 parser (`parse_head`, `HeaderBlock::insert`, `http_rule_matches`).

## Analysis
- Reverse of proxoxy:
  - codec dispatch: `"raw"` -> RawCodec (kind = `0x8000000000000000`, negative -> rule check
    skipped); `"http"`/`"http1"`/`"http/1"`/`"http/1.1"` -> Http1Codec (kind = method length
    >= 1). Config fixes `codec=http`; no runtime switch.
  - Rule engine `http_rule_matches`: `Eq{field,value:regex}` (method eq case-insensitive, path
    eq case-sensitive), `Contains{field,value:string}` (header name case-insensitive, value
    substring CASE-SENSITIVE), `And{ops}` (empty->true), `Or{ops}` (empty->false).
    `forward_connection`: if ANY rule matches -> DROP; else forward raw bytes verbatim.
  - `allowed_pubkeys` is loaded + logged but NEVER compared (dead code; no
    `Vec<String>::contains` symbol; no crypto). Pubkey auth is a red herring.
  - Header parsing: name must be tchar (byte-identical to gunicorn `TOKEN_RE`); stored name is
    lowercased + `_`->`-`; value trimmed SP/TAB, printable ASCII 0x21-0x7e + SP/TAB, accepts
    obs-text 0x80-0xff, rejects DEL 0x7f/control; max 127 headers; head cap ~64 KB.
- Backend gunicorn 26.2.0 + werkzeug 3.1.8: uppercases names, drops `_` names (except
  `SCRIPT_NAME`/`PATH_INFO` forwarder_headers), byte-identical value validation, joins
  duplicate headers with `","`.
- The core impossibility: Flask sees `brevski == "george"` iff the raw header name is a pure
  case-variant of "brevski" (`name.upper().replace('-','_') == "BREVSKI"`); the proxy
  lowercases every such variant to "brevski", so rule2 always matches. Value direction: both
  parsers have byte-identical value validation + trim + latin-1, so `contains("george")` is
  true exactly when Flask sees "george".
- Framing: the proxy consumes <= gunicorn in every accept case (CL same digits; chunked proxy
  stricter; no-CL proxy treats as zero-body vs gunicorn EOF-body), so request smuggling to hide
  `brevski: george` from the proxy is impossible.
- Game: `STOP` with `draw_count == 60` needs 60 distinct draws from 1..69 (P ~ 2e-18); even
  full MT19937 prediction doesn't help (only 1 CHEAT re-roll per game); single-threaded Lock;
  no race.

## What we tried
1. Header-name discrepancy (the intended angle): exhaustive single-byte fuzz around "brevski"
   (all 256 bytes at every position) -> 0 flags; 128/128 case variants of "brevski" all
   DROPPED; separators (`brev_ski`, `brev-ski`, `brev ski`, `brev:ski`, `brev.ski`,
   `brev~ski`, trailing dot/space) -> 500 (reach Flask but `HTTP_BREVSKI` unset). Rule2's
   field lookup (`headers.brevski`) is a full-key match with case-insensitive name comparison.
2. Duplicates/truncation: duplicate `brevski` values (`george`+`hello`, `hello`+`george`) all
   DROPPED (proxy scans all values; gunicorn joins with `","` -> Flask `get()` != "george").
   Value `george;x` / `x;george` / `x=george` / `x,george` all DROPPED (raw substring). No scan
   window (blocked with 50/100 dummy headers before it; `'A'*32768+'george'` blocked).
3. Framing/desync: CL+TE rejected by both; duplicate CL same value (proxy accepts, gunicorn
   400); `"5, 5"` (proxy accepts, gunicorn 400); chunked trailers (proxy drops, gunicorn puts
   in `req.trailers` not exposed to WSGI); no-CL/no-TE (proxy zero-body vs gunicorn EOF);
   obs-fold (proxy skips, gunicorn 400); LF-only (proxy InvalidMessage). None yields
   proxy-forward + Flask-sees-george.
4. Codec/auth: no raw-codec switch reachable; `allowed_pubkeys` dead code; no hidden listener,
   no config reload, no magic header.
5. Response direction: proxy parses backend responses (forwards valid, drops invalid);
   `Expect: 100-continue` causes response-context underflow -> connection reset (DoS only, not
   a flag leak).
6. Direct backend: nodeport exposes only 8888; full nodePort scan 30000-32767 -> no 8900;
   direct `:8900`/`:8888`/`:8000`/`:80`/`:443` all timeout.
7. Game/MT19937: analyzed infeasible (see Analysis); local replica + remote fingerprint matched
   (`POST /flag` -> 500; `brevski: george` -> `''` drop; `brevski: GEORGE` -> 500, case-
   sensitive so not blocked).

## Blocker
The deny-list cannot be bypassed through header name/value/framing/codec because the proxy and
gunicorn parsers are byte-for-byte identical for every field Flask consults, and the proxy
consumes <= gunicorn in every framing case. The platform showed a few solves, so a real bypass
exists — the open question is what non-parser trick (or a discrepancy outside the standard
request parser) defeats rule2 and delivers a `POST /flag` that Flask sees as `brevski=george`
while the proxy's `contains("george")` is false.

## Lessons
- Reverse-proxy challenges: the productive axis is parser-normalization discrepancies (name
  case/underscore/hyphen, duplicates, obs-fold, framing), and proving the two parsers are
  identical rules out the whole class.
- Rust proxies are memory-safe: buffer-overflow/fuzz angles are dead; a "deny if ANY" rule with
  a CONTAINS on a raw byte substring is very hard to bypass when both sides normalize
  identically.
- Config "auth" fields (`allowed_pubkeys`) that are loaded but never compared are a classic red
  herring — verify the comparison symbol in the binary before investing.
