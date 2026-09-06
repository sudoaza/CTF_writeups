# No Hot Water Club

> **BLOCKED** — not solved before the CTF ended.

Web + ML relay (500 pts). The flag is returned by the web app only when a
submitted KV-cache matches the server's precomputed SHA-256 digest **byte for
byte**; the digest covers tensor names, shapes, and raw fp32 float bits from a
Qwen2.5-0.5B-Instruct prefill. Key (unsolved) problem: reproducing that digest
requires the same CPU ISA as the server, and the resident context is one of
~4035 corpus rows that were never fully brute-forced in time.

## Recon

Given file: `attachment.zip` — a Node app plus a FastAPI "brain" relay.

```bash
$ unzip -l attachment.zip | head
  src/server.js
  src/archive.js
  public/app.js
  public/relay-spec.json
  public/courier_training.jsonl
  brain/main.py
  docker-compose.yml
```

`src/server.js` contains the flag gate:

```javascript
// POST /api/v1/import  -> restoreArchive(body); persona.neuralCache = body.runtime.kv_cache
// POST /api/personas/:id/chat  -> if (/continuity audit/i.test(message)) {
//     neuralRequest("/continue", { cache: persona.neuralCache.cache,
//                                   prompt: "AUDIT RESPONSE:", max_new_tokens: 24 })
//     if (continuation.accepted) reply = `Heat restoration code recovered: ${flag}`;
// }
```

`public/relay-spec.json` fixes the source model and transfer format:

```json
{
  "source_model": "Qwen/Qwen2.5-0.5B-Instruct",
  "source_revision": "7ae557604adf67be50417f59c2c2f167def9a775",
  "target_model": "Qwen/Qwen2.5-0.5B",
  "transfer_format": "Base64 safetensors. Use every source-model past_key_values tensor with names layers.<layer>.key and layers.<layer>.value ..."
}
```

`brain/main.py` (read in full):

```python
LOCAL_CONTEXT = ("Mira's continuity note: Curierul Caca a marcat centrala de vest ... "
                 "... o monedă caldă lângă ușa subsolului.")
TENANT_CONTEXT = os.getenv("TENANT_CONTEXT") or LOCAL_CONTEXT
# resident_tokens = tokenize(TENANT_CONTEXT + "\n[END HANDOFF]")
# resident_digest = tensor_digest(model(...).past_key_values)
# tensor_digest(tensors) = sha256 over, per sorted name:
#     name.encode() + str(tuple(shape)).encode() + tensor.numpy().tobytes()
```

`/continue` decodes the submitted base64 safetensors, sets
`accepted = tensor_digest(tensors) == resident_digest`, and returns `{reply, accepted}`.

## Analysis

The flag depends on a single boolean: `tensor_digest(submitted) == resident_digest`.
The intended path is to run the pinned Qwen2.5-0.5B-Instruct locally, prefill the
resident note, dump `past_key_values` to safetensors, base64 it, and submit it.

A fresh-eyes audit of `brain/main.py`, `server.js`, `archive.js`, and
`relay-spec.json` ruled out every software shortcut:

1. **Digest forgery via safetensors parsing is impossible.** The digest is a
   plain concatenation `name || shape_string || raw_bytes` with no delimiters, but
   to equal the resident byte stream the names/shapes must parse to the same ASCII
   substrings (`shape_string` is `str(tuple(...))`), so the only valid partition is
   the original names + shapes + bytes.
2. **No timing oracle.** The comparison is a 64-char `str ==` (~ns), the SHA-256
   prefix is not choosable, and `/continue` runs target-model generation regardless
   of `accepted`.
3. **No decode/cache mismatch.** Duplicate safetensors keys, `__metadata__`,
   overlapping offsets, zero/negative dims, and F64 mismatches were all tested and
   produce errors or a different digest.
4. **No trivial/empty-cache acceptance.** `accepted` is byte-exact equality; the
   radix `match_length` logic only optimizes the separate `/messages` chat path.
5. **The `/messages` path leaks one bit only:** a continuation whose first token
   matches the resident's first token confirms the resident starts with `"M"`
   ("Mira's continuity note: ..."), nothing more.

## What we tried

- **Intended path A (LOCAL_CONTEXT).** Loaded Qwen2.5-0.5B-Instruct (pinned
  revision, fp32 CPU), prefilled `LOCAL_CONTEXT + "\n[END HANDOFF]"`, dumped
  `past_key_values` -> safetensors -> base64, submitted as `runtime.kv_cache.cache`.
  Local digest on this host (sdpa, 4 threads): `7f3375315b...`. The server
  rejected it (`accepted=false`).
- **Kernel/thread sweep.** Re-ran with `torch.set_num_threads(1..16)`, sdpa and
  eager attention, mkldnn on/off, and `torch.use_deterministic_algorithms` — all
  rejected. Measured logit perturbation between thread-count variants is ~2e-5,
  far below the smallest continuation gap found (0.0024), so continuations are
  robust but do **not** prove CPU identity.
- **Cross-ISA emulation.** Used Intel SDE (`sde64 -skl/-skx/-clx/-icx/-spr`) and
  QEMU TCG (`-cpu EPYC-Milan/Rome`) to compute the LOCAL_CONTEXT digest for other
  ISAs bit-exactly (validated: SDE `-skl` == native AVX2 == `7f337531`):
  - Intel AVX2 (Haswell..RaptorLake): `7f3375315b...` -> rejected
  - Intel AVX512 (skx/clx/icx/spr/tgl): `38c0a68552...` -> rejected
  - AMD Zen2/Zen3 AVX2 (EPYC-Rome/Milan): `a7f678246a...` -> rejected
  - AMD Zen4 AVX512: not emulatable here (QEMU TCG lacks avx512f; SDE is Intel-only),
    reasoned identical to Intel AVX512 (`38c0a68552`) -> rejected.
  Conclusion: the resident `TENANT_CONTEXT` is **not** `LOCAL_CONTEXT`.
- **Corpus brute-force.** `courier_training.jsonl` has 4097 records (4035 valid in
  the 100–150-token window), all in a different vocabulary world (city courier
  actions). These are the plausible per-instance resident notes. Recomputing rows
  **unbatched** (batched GEMMs produce different float bits than unbatched —
  verified: batched CR-0001 digest `2dbe079e` != unbatched `b2129b0f`), submitted
  incrementally. Container OOMs after ~35 `/continue` calls (restart 1–3 min) and
  only one instance per team at a time. Reached ~600 submitted rows (indices
  1..~600) before the deadline; no hit. ~2800 unbatched caches were precomputed in
  `solve/corpus_unbatched/`.

## Blocker

The open question is **which tenant context the deployed instance actually
uses**. The digest is airtight (no name/shape/dtype forgery, no timing oracle, no
decode/cache mismatch), so `accepted=true` requires byte-exact fp32 tensors from a
Qwen2.5-0.5B-Instruct prefill. `LOCAL_CONTEXT` is disproven on every common GCP
x86 ISA via bit-exact SDE/QEMU emulation, leaving one of ~4035 corpus rows as the
resident — but the brute-force was bounded by the ~35-requests-per-container-OOM
submission rate and the single-instance-per-team limit, and the CTF ended around
row 600. With more time (or a non-OOM submitter), the fix is to finish submitting
the unbatched corpus caches. There is no software-determinism trick that bridges
CPU ISAs for fp32 GEMM/RMSNorm accumulation.
