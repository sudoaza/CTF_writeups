# No Hot Water Club

# No Hot Water Club — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
WEB — 423 pts — dynamic http — ~11 solves.
- Brief: 'Can you audit the hot water pls?'
- Required skills: web; source/appliance audit; SSRF/injection chain.
- First hypotheses: appliance exposes an audit endpoint; likely SSRF or deserialization to reach an internal service.

## Discovery & ideation (2026-09-05)
FILES: attachment.zip -> Node app (src/server.js, src/archive.js, public/app.js), brain/ (main.py FastAPI + Qwen2.5-0.5B model relay, 27KB), relay-spec.json, courier_training.jsonl (1.6MB), docker-compose.
server.js (full read): /api/v1/import restores a persona archive (restoreArchive) and sets persona.neuralCache from request.body.runtime.kv_cache.cache (a string). /api/personas/:id/chat: message matching /continuity audit/i -> if persona.neuralCache -> POST brain /continue {cache, prompt:'AUDIT RESPONSE:', max_new_tokens:24} -> if continuation.accepted -> reply 'Heat restoration code recovered: <FLAG>'.
relay-spec: source_model Qwen2.5-0.5B-Instruct; transfer_format = Base64 safetensors of source-model past_key_values (layers.<n>.key/.value); then request a continuity audit.
brain/main.py: LOCAL_CONTEXT (Mira's continuity note, given verbatim) = the resident context the cache must match (RadixPrefixCache match_length / digest).
HYPOTHESES (ranked):
1. INTENDED: run the source model locally (Qwen2.5-0.5B-Instruct, ~1GB), encode the LOCAL_CONTEXT, dump past_key_values -> safetensors -> base64 -> submit as runtime.kv_cache.cache in an imported persona -> chat 'continuity audit' -> accepted -> flag. (Heavy but deterministic.)
2. FLAW: read the rest of brain/main.py /continue + RadixPrefixCache.match_length + digest check - maybe an empty/trivial cache (or a crafted short cache) still matches resident_tokens within a threshold, avoiding the model run entirely.
3. archive.js restoreArchive may have a proto-pollution / field-overwrite flaw to set neuralCache without a valid cache.
NEXT: read brain/main.py /continue + /messages + match logic fully; check whether the digest is only computed over resident tokens (which we know) vs the cache.


## Update 2026-09-05 19:17:30Z — deep findings

- Self-check: importing the actual brain/main.py and running initialize_resident_state() on this host gives resident_digest 7f337531... = my cache_t4 (sdpa, 4 threads). So my LOCAL_CONTEXT cache is byte-correct for AVX2+torch2.5.1+sdpa+t4.
- /continue replies (target-model continuation of "AUDIT RESPONSE:") match local byte-for-byte; knife-edge /messages continuations also match. BUT measured logit perturbation for thread-count cache differences is ~2e-5 vs the smallest gap found (0.0024), so all continuations are ROBUST to ~1 ulp float differences -> they do NOT prove CPU identity.
- All sdpa thread counts 1..16 and eager t4 were rejected by /continue. So the remote resident digest != any AVX2 sdpa/eager thread-count variant.
- The 4097-record corpus (courier_training.jsonl) is a DIFFERENT vocabulary world (city courier actions: Gara Obor, ceainaria, cabina telefonica...). ZERO corpus rows contain LOCAL_CONTEXT's building keywords (centrala, contor, vana, cafea, subsol, bloc, scara). So LOCAL_CONTEXT (the building note) is not a corpus row; the corpus is likely TRAINING-data flavor, not the resident-note candidate set.
- Conclusion: deployed TENANT_CONTEXT is almost certainly LOCAL_CONTEXT (the building continuity note), and the rejection is an environment mismatch: the Qwen2.5-0.5B KV cache prefill (M~111) is sensitive to CPU ISA / oneDNN kernel (thread count 1..16 already produces 16 different digests on this host). This droplet is Intel AVX2 with AVX512 masked (QEMU); if the challenge infra exposes AVX512 (or a different vendor/microarchitecture), byte-exact reproduction is impossible here.
- Batch-prefill is NOT a valid shortcut: batched (M=batch*seq) GEMMs produce different float bits than unbatched (M=seq); verified CR-0001 batched digest 2dbe079e != unbatched b2129b0f. So any brute-force over the corpus must be unbatched (~0.14 notes/s -> ~8h for 4035 valid rows) AND would only help if the note were actually a corpus row.

## Next actions
- (parent steer) If a sibling has AVX512-capable or different-vendor compute, retry path A there (LOCAL_CONTEXT, sdpa, 4 threads).
- Otherwise BLOCKED-environment: cannot byte-match the remote KV cache on this AVX2 droplet.


## Update 2026-09-06 07:40Z — fresh-eyes re-audit (ctf-hotwater-fresh)

Re-read brain/main.py, server.js, archive.js, relay-spec.json in full. Verified with local experiments:

1. digest is SHA-256 over, per sorted tensor name: name.encode() + str(tuple(shape)).encode() + tensor.numpy().tobytes(). No length delimiters between fields/tensors, but that does NOT open a forgery: to equal the resident stream byte-for-byte the names/shapes must parse to the same ASCII substrings (shape strings are str(tuple) = "(...)"), so the only valid partition is the original -> exact names+shapes+bytes are required.
2. safetensors edge cases tested locally (safetensors 0.5.2): duplicate header keys -> last wins (still one tensor); __metadata__ skipped; overlapping data_offsets -> InvalidOffset error; zero/negative dims -> error or empty tensor; F64 with mismatched data size -> TensorInvalidInfo. No way to make a different shape/name/dtype hash to the resident digest.
3. Timing oracle is dead: tensor_digest(...) == resident_digest is a 64-char str== (~ns), and we cannot choose our SHA-256 prefix. /continue runs target-model generation regardless of accepted, so response time does not reveal accepted.
4. decode_cache/tensor_digest/cache_from_tensors have no exploitable mismatch; accepted is the only gate to the flag and requires byte-exact tensors.
5. CORRECTION to prior reasoning: /messages continuation = fresh prefill of the message for ANY match_length >= 1 (resident prefix cache is only an optimization), and match_length=0 gives the chat path. So /messages reveals only 1 bit: does the resident's FIRST token match (confirmed: "M", i.e. resident starts "Mira's continuity note: ..."). It does NOT prove resident = LOCAL_CONTEXT.
6. CORRECTION: prior corpus brute-force used BATCHED caches, which produce different float bits than unbatched (re-verified: batched row0 digest != unbatched). Unbatched corpus caches were never tested against the server before now.
7. Live test (instance no-hot-water-team-eacf6a63da247af2): oracle confirms first token "M"; LOCAL_CONTEXT t4 + 10 unbatched corpus caches (CR-0001..0005, 2050,1028,3078,4095,4096) all rejected (accepted=false). Each /continue reply reflects the SUBMITTED cache, not the resident.
8. Conclusion unchanged in substance: the flag requires byte-exact reproduction of the resident KV cache. Resident is almost certainly LOCAL_CONTEXT (compose default TENANT_CONTEXT unset; challenge theme = hot-water building note; corpus = courier training flavor). The blocker is CPU ISA: this droplet is AVX2 with AVX512 masked (QEMU), server is a non-masked CPU. No software determinism trick (threads 1..16, sdpa/eager, mkldnn on/off, deterministic_algorithms) bridges ISAs for fp32 GEMM/RMSNorm accumulation.
9. Remaining (low-probability) path if resident is actually a per-instance corpus row: unbatched brute-force of ~4035 valid corpus rows (local compute ~2.8h + submission ~4-11h). Not launched: low P(resident=corpus) vs theme/default evidence.


## Update 2026-09-06 09:50Z — CPU emulation + corpus brute-force (ctf-hotwater-fresh)

MAJOR: used Intel SDE (sde-external-10.13.1) and QEMU TCG to EMULATE other ISAs in software and compute the LOCAL_CONTEXT KV digest per ISA. Validated bit-exactness: SDE -skl (AVX2) == native AVX2 == QEMU -cpu Skylake-Client == 7f337531.

LOCAL_CONTEXT digests (threads=4, sdpa, fp32, torch 2.5.1+cpu):
- Intel AVX2 (Haswell..RaptorLake, incl adl): 7f3375315b... -> rejected
- Intel AVX512 (skx=clx=icx=spr=tgl): 38c0a68552... -> rejected
- AMD Zen2/Zen3 AVX2 (QEMU EPYC-Rome/Milan): a7f678246a... -> rejected
- AMD Zen4 AVX512: not emulatable here (QEMU 10.0 TCG still lacks avx512f; SDE is Intel-only). Reasoned == Intel AVX512 (oneDNN avx512_core FMA kernel is ISA-keyed) = 38c0a685 -> rejected.

So ALL common GCP x86 ISAs reject LOCAL_CONTEXT -> resident TENANT_CONTEXT is NOT LOCAL_CONTEXT. The relay-spec "reference_corpus_records: 4097" + served courier_training.jsonl (all "Mira's continuity note: Curierul Caca...", 4035 rows in 100-150 token window) => resident is a corpus row.

Correction to earlier note: the prior child's corpus_caches/ ARE unbatched (CR-0001 digest b2129b0f == unbatched), but only 32 rows; they were never submitted as unbatched (brute.py used the earlier BATCHED set).

Brute-force: recomputing all valid corpus rows unbatched (native AVX2, ~0.52/s) and submitting incrementally against live instances. Instance OOMs after ~35 /continue calls (container restart ~1-3 min). One no-hot-water instance per team at a time ("This challenge is already running" for a 2nd). As of 09:50: ~380 rows submitted (CR-0001..~CR-0380), no hit. Continuing.


## Final 2026-09-06 ~10:30Z — CTF ended (ctf-hotwater-fresh)

CTF deadline passed. No flag. Final state:
- Confirmed resident != LOCAL_CONTEXT (LOCAL_CONTEXT rejected on Intel AVX2 / Intel AVX512 / AMD Zen2-Zen3, all computed via bit-exact SDE/QEMU emulation).
- Resident almost certainly one of the 4097 corpus rows (4035 valid in 100-150 token window). No hint found for which row.
- Brute-force (unbatched, native AVX2, sdpa, threads=4) reached ~600 submitted rows (indices 1..~600) before deadline; no hit. Submission bottleneck: container OOMs after ~35 /continue calls; only 1 no-hot-water instance per team concurrently.
- Compute had produced ~2800 unbatched corpus caches (kept in solve/corpus_unbatched/ for any future reuse).
- Digest is airtight: no shape/name/dtype forgery, no timing oracle, no decode_cache/tensor_digest flaw (tested safetensors edge cases).
- Key technique recorded for future: Intel SDE (sde-external-10.13.1-lin, sde64 -skx/-clx/-icx/-spr) and QEMU TCG (qemu-x86_64 -cpu EPYC-Milan/Rome) can EMULATE other x86 ISAs bit-exactly (validated SDE -skl == native AVX2), enabling cross-ISA KV-cache digest reproduction in software.
