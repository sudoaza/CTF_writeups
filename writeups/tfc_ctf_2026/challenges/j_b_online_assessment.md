# J*B Online Assessment

**Flag:** `TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026}`

# J*B Online Assessment — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions

## Brief / category / skills / hypotheses
WEB — 214 pts — dynamic http — ~68 solves.
- Brief: 'Can you get a j*b in 2026?'
- Required skills: curl/requests, web app testing (authz/IDOR/logic).
- First hypotheses: fake job-application portal; get a 'job' by exploiting an auth/logic/IDOR flaw in the application flow.

## 2026-09-05T15:05:26.312088Z
- Offline recon: no writeups found (event live, ~69 solves, no public writeups yet). No attachment. Knowledge base web.md read.
- Tried start_container('j-b-online-assessment') -> 409 max 3 running instances (slots: fluxion 15:19Z, larpbrev 15:17Z, meshgate 15:29Z).

## 2026-09-05T15:47:53.661025Z
### Findings
- App = "J*B Online Assessment": download job-oa.pka (Cisco Packet Tracer 8.2.1 activity, 2.9MB), complete it 100%, upload to POST /api/submit (octet-stream). Server decrypts and checks "relay state".
- .pka encryption (PT 8.x) REVERSED and implemented in Python: stage1 reverse-XOR (input[L-1-i] ^ (L-i*L)&0xff) -> stage2 TwoFish-EAX decrypt (key 0x89*16, IV 0x10*16; EAX = CMAC+CTR, tag = N^H^T) -> stage3 forward-XOR (b[i]^(L-i)&0xff) -> stage4 zlib (4-byte BE size). Round-trip verified byte-identical.
- Decrypted XML = 73MB, 3 plaintext <PACKETTRACER5> networks: #0 initial (11 dev: Datacenter2-Router/SW1/SW2/SW3/PC), #1 duplicate of #0, #2 ANSWER network (53 dev: Cluj-Gateway, Hub-Edge1-4, CoreSW1-4, ...). Server response to original: "Relay incomplete: 18/122 signed configuration markers recovered."
- Hypothesis: server compares student network vs answer network on 122 config markers. Forge = make student network(s) identical to answer network (#2).
- Built forge variants: exp1 (all 3 blocks = net2), exp2 (net0=net2), exp3 (net1=net2), exp4 (orig+ENABLED=yes), exp5 (all3=net2+ENABLED=yes). All re-encrypt correctly (round-trip verified).
### Dead ends
- First instance (c42a12c8ef0a090b) expired at 15:33 before submission; original-file probe succeeded ("18/122").
### Next actions
- At 15:52:40Z take cadence slot, start container, submit exp1.., stop container.

## 2026-09-05T16:36:36.302513Z — SOLVED
- FLAG: TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026} (submitted to platform, ok:true)
- Technique: .pka = Packet Tracer 8.2.1 activity, TwoFish-EAX encrypted (key 0x89*16, IV 0x10*16). Decrypted to XML with 3 <PACKETTRACER5> networks: #0 student (11 dev), #1 dup, #2 ANSWER network (53 dev, plaintext!). Server compares student vs answer on 122 config markers. Forge = replace student network (#0) with answer network (#2), re-encrypt, upload -> "matched":122.
- Working variant was exp2 (net0 = net2). exp1 got transient SSL EOF on first submit, exp2 succeeded.
- Key step: answer network is stored in PLAINTEXT in the .pka; no signing of the answer — just copy it into the student slot.
