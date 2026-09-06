# Web techniques

## Common styles
- Source audit (given source.zip) -> find the flaw, exploit the live app.
- SSRF, command injection, file upload, IDOR, auth bypass, JWT, SQLi, SSTI, prototype pollution, deserialization.

## Key techniques
1. SSRF: hit internal endpoints/cloud metadata (169.254.169.254), bypass filters (127.0.0.1 -> 2130706433, 0x7f000001, [::1], redirect).
2. Auth/JWT: alg=none, weak HS secret, kid path traversal; cookie forging.
3. File upload: double extension, content-type bypass, magic bytes, path traversal in filename (../), zip slip.
4. IDOR: guess object ids, check missing authorization on API.
5. Command injection: ; | & ` $() newline; bypass space (${IFS}), keyword filters (base64, rev shell).
6. SSTI: Jinja `{{7*7}}`, `{{config}}`, RCE via `{{cycler.__init__.__globals__.os.popen('id').read()}}`.
7. Prototype pollution: `__proto__` merge -> pollute to bypass auth/RCE.
8. Deserialization: PHP unserialize gadgets, Java ysoserial, Python pickle.
9. SQLi: union-based, blind (boolean/time), second-order.
10. Path traversal: `../../etc/passwd`, URL-encode bypass, null byte.

## SEARCH
- "<app name> writeup", "SSRF bypass writeup", "JWT alg none writeup", "SSTI jinja rce writeup"

## References
- HackTricks: https://book.hacktricks.wiki/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings


## TCP SYN-payload (TFO-style) desync vs passive traffic capture (TFC CTF 2026 turip)
- Setup: a service records all traffic with tcpdump + Tulip/gopacket reassembly, then grants a flag only if the captured CLIENT stream of the flow carrying a marker header contains no forbidden strings. The client must send a fixed request containing those strings.
- Bypass: gopacket's reassembly delivers the SYN packet's payload as client->server data and advances the stream's next sequence number; the server's Linux kernel (no TCP Fast Open on the listener) ignores the SYN payload. Send a SYN whose payload is benign filler of the SAME length as the real request, complete the handshake, then send the real request at seq=ISN+1. The monitor strips the real request as already-covered bytes; the server delivers it.
- Raw TCP with scapy (root + cap_net_raw). To stop the local kernel from RSTing the spoofed connection: `iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <srcport> -j DROP`.
- Related: Tulip assembler uses gopacket v1.3.0 reassembly; -skipchecksum flag present, FSM-only Accept (no MSS/window/seq checks); IP fragments were dropped en route so IP-frag overlap failed.


## Vaultkeeper (TFC CTF 2026) — lessons (BLOCKED, not solved)
- v2 source audit (zip changed mid-CTF): loopback-gated SSRF chain. fetch_source.php = SSRF sink with NO host filter but Apache Require ip 127.0.0.1. keyring.php -> unseal_ref; vault_unseal.php?ref= -> cap_key_masked = base64(cap_key XOR cap_mask).
- Intended chain: SSRF -> keyring -> vault_unseal -> cap_key_masked + cap_mask -> cap_key -> forge AES-GCM maintainer cap -> restore.php import_db -> second-order SQLi (DROP TABLE `vk_restore`.`$name` without escaping backticks) into vk_app -> UPDATE vaultkeeper.jobs SET role='operator' -> system_restore -> vk_resume_checkpoint HMAC envelope -> unserialize gadget (SnapshotRef->DocFragment->PartialLoader->call_user_func_array) -> copy /flag.txt to webroot.
- Stacked SQLi pattern: PDO MYSQL_ATTR_MULTI_STATEMENTS; '1=1; <stmt> #' (the # comments out the trailing ORDER BY). Later-statement errors are silently ignored; only side effects matter.
- Verified: no FILE/LOAD_FILE/LOCAL INFILE for the vk_restore user; check information_schema.schema_privileges/user_privileges/ENGINES/PLUGINS/ROUTINES to bound SQLi capabilities.
- render_template pipeline: protected-flag taint that propagates through every filter + final str_replace is airtight; don't burn time on it.
- Apache Require ip 127.0.0.1 in <FilesMatch> is not bypassable via XFF/Real-IP/absolute-URI/CONNECT/path-encoding/Host tricks when AcceptPathInfo Off + AllowEncodedSlashes Off + no mod_remoteip/rewrite rules.
- Still-unknown: the actual externally-reachable SSRF trigger (likely platform ingress/topology, not app code).


## SOLVED case study: TFC 2026 `fluxion`
- v2 source zip contains the FCP protocol. Enroll device via `Object.assign` profile merge -> operator enrollment.
- FCP HELLO/KEX/TICK/ARM handshake: sessionKey = HMAC(approvalNonce, serverSalt) -> armToken; resumeHook(hook token + forged Unicode-escape grant + armToken) completes the admin run.
- RCE/flag leak: `mergeDeep` only blocks `__proto__`, so use `constructor.prototype` pollution to set `reportDefaults.presentation.caption` and leak `run._flag` through an E_SCALAR diagnostic.
- Lesson: when `__proto__` is blocked, `constructor.prototype` is the classic prototype-pollution bypass.


## J*B Online Assessment (TFC CTF 2026) — SOLVED: Packet Tracer .pka forge
- .pka (Cisco Packet Tracer 8.2.1 activity) is TwoFish-EAX encrypted, NOT the old XOR-only format. Decrypt order: (1) reverse-XOR: out[i] = in[L-1-i] ^ ((L - i*L) & 0xff); (2) TwoFish-EAX decrypt (key 0x89*16, IV 0x10*16; EAX = CMAC + CTR, tag=N^H^T; skip tag verify for decrypt); (3) forward-XOR: b[i] ^= (len-i) & 0xff; (4) zlib (first 4 bytes = BE uncompressed size). Encrypt is the exact reverse. Python: `pip install twofish` + hand-rolled CMAC/CTR/EAX (Crypto++ EAX uses CMAC subkeys K1=dbl(L),K2=dbl(K1); CTR counter = CMAC(0^16||IV), big-endian increment).
- Decrypted XML has 3 plaintext <PACKETTRACER5> networks: #0 = student initial, #1 = duplicate, #2 = ANSWER network (the full correct solution, in PLAINTEXT). Server grades by comparing student vs answer on N "configuration markers".
- Forge: replace the student <PACKETTRACER5> block with the answer block, re-encrypt, upload. No signing of the answer network itself — copying it defeats the checker.
- Ref tools: https://github.com/axcheron/ptexplorer (v5 XOR+zlib only), https://github.com/mircodz/pka2xml (C++ CryptoPP, 7.3.1 EAX), https://ferib.dev/blog/protecting-Packet-Tracer-myself-because-no-one-gives-a-fuck/ (v7.2.1 stage reverse).


## TFC CTF 2026 `No Hot Water Club` (ML-relay KV-cache audit) — analysis
- App: import persona archive with runtime.kv_cache.cache (base64 safetensors of source-model past_key_values). Chat "continuity audit" -> brain /continue compares SHA256(tensor names+shapes+bytes) against resident KV cache; flag only if accepted.
- Intended path: download Qwen2.5-0.5B-Instruct at pinned revision, encode LOCAL_CONTEXT+HANDOFF (add_special_tokens=False), forward (fp32, sdpa, torch.set_num_threads(4)), dump past_key_values -> safetensors -> base64 -> submit.
- Key gotchas (this host):
  1. The KV digest is CPU-ISA/thread sensitive: thread counts 1..16 give 16 DIFFERENT digests on the same machine (oneDNN GEMM reduction order). core count does not matter (taskset verified); thread count and ISA do.
  2. Reusing a process and changing torch.set_num_threads in a loop after the first forward gives WRONG results for later thread counts (loop contamination). Always fresh process, set threads BEFORE loading the model.
  3. Batch-prefill is NOT valid: batched (M=batch*seq) GEMMs differ from unbatched (M=seq) in float bits. Any KV cache must be computed one sequence per forward.
  4. /messages continuation = model.continue(your message), independent of the resident note (prefix cache is only an optimization) -> the note is NOT recoverable via chat continuation, and continuations are argmax-robust so they do not detect ~1 ulp CPU differences.
  5. The served courier corpus (4097 rows) is a decoy/training set with a different vocabulary; check keyword overlap before assuming it is the candidate set.
- Lesson: byte-exact ML cache reproduction across machines requires identical CPU ISA + torch/oneDNN + thread count + attention impl; if a challenge's accepted-check is SHA256 over float tensors, verify the whole matrix before assuming a logic flaw.


## Vaultkeeper (TFC CTF 2026, hard web) — SOLVED

Flag: TFC{04d4c11ea3641f2ec562b657ea6428b4}

Chain:
1. CVE-2024-38473: `GET /api/fetch_source.php%3Fooo.php` — encoded `?` makes
   Apache's `r->filename` = `fetch_source.php?ooo.php`, so `<FilesMatch
   "^(fetch_source|...)\.php$">Require ip 127.0.0.1` does NOT match, but
   `<FilesMatch "\.php$">SetHandler proxy:fcgi` still matches (ends in .php).
   PHP-FPM strips the `?ooo.php` and executes the real script. Bypasses the
   loopback gate on fetch_source/peer_probe/webhook_test/keyring/vault_unseal.
2. SSRF via fetch_source to 127.0.0.1 (no host filter). Exfil a 200 body with a
   controlled 300-redirect: fetch_source returns `trace`=body only when a hop
   code is non-standard; 300 is followed by PHP but not in its STD list.
3. keyring.php -> unseal_ref; vault_unseal.php?ref=.. -> cap_key_masked.
4. Leak cap.mask via render_template.php error oracle:
   `[[config.cap_mask|at:i|code|sub:K|bar:x]]` -> `str_repeat` throws ValueError
   (raw span) iff ord(mask[i]) < K; binary-search each of 16 chars.
5. cap_key = cap_key_masked XOR mask. Forge `vk_cap_issue('operator')`.
6. request_restore.php -> job; upload .vkb with database.sql =
   `CREATE TABLE `a``;UPDATE jobs SET role='operator';#` (id INT)` and import_db
   with forged operator cap. vk_import_database drops the new table via vk_app:
   `DROP TABLE IF EXISTS `vk_restore`.`$name`` -> table-name SQLi (backtick
   breakout) runs `UPDATE jobs SET role='operator'` as vk_app (multi-statements).
7. system_restore -> vk_resume_checkpoint -> unserialize (objects allowed).
   Gadget: RestorePoint.__destruct -> CacheShard.offsetSet -> DocFragment.
   __toString -> PartialLoader.render -> call_user_func_array('readfile',['/flag.txt']).
   Seal MAC = HMAC('vk-checkpoint-seal.v5|slot|CacheShard', vk_seal_key()).


## No Hot Water Club — fresh re-audit (append, 2026-09-06)
- Digest is SHA-256 over name+shape-str+raw-fp32-bytes per sorted tensor; NO length delimiters, but the only parse of the fixed resident byte-stream that matches is the original (shape strings are str(tuple)), so it is collision-free in practice. No dtype/shape/name forgery via safetensors (tested: dup keys last-wins, __metadata__ skipped, overlapping offsets error, F64 size mismatch error).
- Timing oracle is dead: 64-char str== is ns and generation runs regardless of accepted; you cannot choose your SHA-256 prefix.
- /messages continuation == fresh prefill of the message for ANY match_length>=1 (resident prefix cache is pure optimization); match_length=0 -> chat path. So /messages leaks only 1 bit (does resident start with your first token). It CANNOT recover the resident note.
- Prior corpus brute-force used BATCHED caches -> invalid (batched GEMM bits != unbatched). If the resident were a per-instance corpus row, you'd need UNBATCHED caches (~4035 valid rows, 100-150 tokens).
- Resident is almost certainly LOCAL_CONTEXT (compose default; hot-water theme). Blocker = byte-exact CPU ISA (AVX2-masked QEMU droplet vs non-masked server CPU); fp32 GEMM/RMSNorm accumulation differs across ISA/threads and no software flag bridges it.


## TFC CTF 2026 case study — larpin (Flask, v1) — deep recon (BLOCKED, no flag)
- Flag on GET /premium only when is_premium. POST /premium/activate reads ONLY the 'token' form/JSON field; empty -> "Please provide", any non-empty string -> "Invalid premium token". No length/format validation observable.
- Token is per-user, server-rendered ONLY on /profile/<username> as `window.__USER_CONFIG__ = { userId:<viewer>, username:<viewer>, isPremium:<bool>, premiumToken:"<viewer token or ''>", profileViewed:"<owner>", t:Date.now() }` plus `<script type=application/json id=viewer-premium-token>` cleared by /js/viewer-token.js. No other page carries the config.
- Bots = user ids 1..14, premium. The ONLY bot with behavior: "Trust & Safety" (id 1) processes applications to its own seeded job (id 1) after ~5min and DMs a CANNED rejection that interpolates ONLY full_name and job_title via a Python f-string (tested {{7*7}}/{{config}} -> rendered literally; no SSTI). It is server-side (no headless render; injected CSS in about never fires) and views the escaped applicant-profile view /jobs/<jid>/applicants/<aid>/profile/{compact,full}, which HTML-escapes about/experience/education/cover_letter.
- No report endpoint (fuzzed report/visit/bot/check/review -> 404/405). No source maps, only 8 JS + 1 CSS. No .git/.env/debug console (/console,/__debugger__ 404). 500 from games score integer overflow (score>2^63) is a generic Flask 500 (debug off, no traceback).
- Flask secret is random per instance (restart -> old session invalid, DB reseeded). Session forgery blocked. No SQLi (int converters + parameterized), no mass-assignment (premium_token/is_premium ignored everywhere), no IDOR (CV download 403 cross-job), filename shell-injection sanitized.
- Token not md5/sha256 of bot usernames/names/ids/headlines/common strings, not fixed-RNG seeds. Games reward only a leaderboard score (no currency/premium link; huge/negative scores don't flip is_premium).
- Sinks: profile about/exp/edu rendered client-side via DOMPurify 3.2.4 (keeps <svg><style>, VERIFIED fires), messages use a weak regex sanitizer - but there is no browser bot, so CSS exfil has no victim.
- Remaining untested: RNG/time-seeded token generation, MT state recovery from CSP nonces.


## No Hot Water Club — final (2026-09-06, CTF over, unsolved)
- Definitively established: resident TENANT_CONTEXT is NOT the in-source LOCAL_CONTEXT. Proof via cross-ISA emulation: Intel SDE (sde64 -skx/-clx/-icx/-spr/-tgl) and QEMU TCG (-cpu Skylake-Client/EPYC-Rome/EPYC-Milan) compute the LOCAL_CONTEXT KV digest bit-exactly for each ISA (validated SDE -skl == native AVX2). All rejected: Intel AVX2 7f337531, Intel AVX512 38c0a685, AMD Zen2/3 a7f678.
- Resident is one of the 4097 courier_training.jsonl rows (4035 fit the 100-150 token window); selection opaque, no hint in any file. /messages leaks only 1 bit (does resident start with your first token); the digest is the only oracle, so brute-force is required.
- Feasibility notes: unbatched only (batched GEMM bits differ); compute ~0.5 caches/s on 2 vCPU; the brain/container OOMs after ~35 /continue calls; platform allows 1 instance of this challenge per team concurrently.
- Reusable skill: SDE/QEMU cross-ISA emulation is a legitimate way to reproduce a CPU-specific fp32 KV-cache digest on foreign hardware (SDE is Intel-only; QEMU TCG 8.2/10.0 lacks AVX512, so AMD Zen4 AVX512 remains uncovered).
