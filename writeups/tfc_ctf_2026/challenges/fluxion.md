# fluxion

**Flag:** `TFC{5d7096f57f88723bfccc910121b7f9cd}`

# fluxion — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## Hypotheses
- 2026-09-05T14:39:06Z H1: recover private admin hook token via truncated-LCG attack on stepIds; CONFIRMED (works).
- 2026-09-05T14:39:06Z H2: forge approval grant via previewApprovalGrant Unicode-escape regex bypass (act res\u0075me); CONFIRMED.
- 2026-09-05T14:39:06Z H3: leak approvalNonce via searchRuns $startsWith prefix oracle; CONFIRMED (16 hex chars).
- 2026-09-05T14:39:06Z H4 (open): bypass/complete FCP arming handshake (POST /FCP, armToken) — blocker.
- 2026-09-05T14:39:06Z H5 (open): prototype pollution (saveViewPreferences mergeDeep, __proto__) to bypass arming — TESTED, did NOT bypass (arming state likely in Map).

## Findings
- 2026-09-05T14:39:06Z live base: http://fluxion-9ba40d2d339077a6.challs.ctf.thefewchosen.com (slot; expires ~14:05Z)
- 2026-09-05T14:39:06Z admin run: run_KNC37YVWQT4JARV9479MNCGA8E; approvalNonce: 5d80be4fbbfa9c3a
- 2026-09-05T14:39:06Z private hook token (LCG): seGPW13faVE
- 2026-09-05T14:39:06Z stepIds: UOAa,tauU,Wz6Y,la-d,xAEd -> x_low=939262322742 -> token seGPW13faVE (verified)
- 2026-09-05T14:39:06Z resumeHook with valid grant+token -> 'this run is not armed: complete the control-plane arming handshake (POST /fcp) and pass the resulting armToken'
- 2026-09-05T14:39:06Z POST /FCP only reachable via SSRF (nginx blocks /fcp lowercase, /FCP uppercase passes to app)
- 2026-09-05T14:39:06Z GET /FCP returns FCP/1 protocol info: frames HELLO(0x01) KEX(0x02) TICK(0x04) ARM(0x03); binary octet-stream one frame per request; paced TICK/TOCK ladder between KEX and ARM
- 2026-09-05T14:39:06Z new RPC methods found: armRun (deprecated), enrollDevice (always viewer tier), describeEnrollment (validates signed enrollment), controlPlaneStatus (fleet tiers viewer/auditor, approvers sre-oncall/platform-lead), listApprovers
- 2026-09-05T14:39:06Z SSRF primitives: probeTarget/fetchManifest/probeIntegrationEndpoint (GET, body reflected), testNotificationChannel (POST JSON body only, NO body reflection)
- 2026-09-05T14:39:06Z SSRF bypass: localtest.me / [::ffff:127.0.0.1] pass host validation and reach app (GET /FCP via localtest.me:3000)

## Dead ends
- 2026-09-05T14:39:06Z D1: prototype pollution Object.prototype.armed/armToken/armState/<runId> did NOT bypass arming check.

## Limitations
- 2026-09-05T14:39:06Z POST /FCP response body not observable with known primitives; need POST-reflecting SSRF or FCP RPC methods.
- 2026-09-05T14:39:06Z enrollment token signing key unknown (differs from approvals key); enrollDevice only issues viewer.

## Next actions
- 2026-09-05T14:39:06Z find POST-body-reflecting SSRF primitive or FCP RPC methods; reverse /FCP frame protocol.
- 2026-09-05T14:39:06Z consider forging operator enrollment (tier=operator/auditor) via signing oracle if found.


## SOLVED
- 2026-09-05T15:06:16Z FLAG: TFC{5d7096f57f88723bfccc910121b7f9cd} (submitted, API ok:true)
- 2026-09-05T15:06:16Z Final chain: source zip v2 (856e9e4f) has FCP. enrollDevice Object.assign(base, profile) merge bug -> tier operator. FCP HELLO/KEX/TICK/ARM handshake with sessionKey=HMAC(approvalNonce, serverSalt) -> armToken. resumeHook(hook token + forged grant + armToken) completes admin run. Then prototype pollution via constructor.prototype (mergeDeep only blocks __proto__) sets reportDefaults.presentation.caption= ${engine.runs.<runId>._flag} with token=nonce; renderRunReport diagnostic leaks E_SCALAR with the flag.
- 2026-09-05T15:06:16Z v2 renderRunReport scope: engine=require('./world'); resolveScopePath supports Map.get, so path engine.runs.<runId>._flag resolves to p._flag.
