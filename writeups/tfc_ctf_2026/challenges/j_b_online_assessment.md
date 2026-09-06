# J*B Online Assessment

WEB challenge: a fake "J*B" job application hands you a Cisco Packet Tracer
activity (`.pka`) that must be completed 100% and re-uploaded. Key idea: the `.pka`
is encrypted with a static Twofish-EAX key, and the "answer" network is stored in
plaintext inside it — copy it into the student slot and re-encrypt.

## Recon
- No attachment; dynamic http instance.
- `GET /` returns the single-page app (title "J*B Online Assessment"):
  - "Save the finished `.pka` and submit it for review. Only 100% completion will
    be considered."
  - Download: `/downloads/job-oa.pka` (2.9 MiB)
  - Submit: `POST /api/submit` (`application/octet-stream`, max 8 MiB)
- Uploading the original file returns the progress oracle:
  `Relay incomplete: 18/122 signed configuration markers recovered.`

## Analysis
- Observation: the `.pka` is a Cisco Packet Tracer 8.2.1 activity, not plaintext.
- Hypothesis: the server decrypts the `.pka` and compares the student network
  against an answer network on 122 config markers.
- Confirmation: reversed the `.pka` encryption and reimplemented it in Python
  (`solve/ptcrypt.py`):
  - stage1 reverse-XOR: `out[i] = in[L-1-i] ^ ((L - i*L) & 0xff)`
  - stage2 Twofish-EAX decrypt (key = `0x89` repeated 16, IV = `0x10` repeated 16;
    EAX = CMAC + CTR, tag = N^H^T)
  - stage3 forward-XOR: `out[i] = in[i] ^ ((L - i) & 0xff)`
  - stage4 zlib decompress (4-byte big-endian size prefix)
- Decrypted XML is 73 MB with three `<PACKETTRACER5>` networks: #0 student/initial
  (11 devices), #1 duplicate of #0, #2 ANSWER network (53 devices) in **plaintext**.
- The answer is not signed: replace the student network with the answer network and
  re-encrypt.

## Exploit
1. Reimplement the crypto (Twofish with key `0x89*16`, EAX with IV `0x10*16`), then
   decrypt the original:
   ```
   python3 ptcrypt.py dec job-oa.pka out.xml
   ```
2. Make `net0 = net2` (replace the student network block with the answer network
   block). Variants exp1..exp5 tested different block substitutions.
3. Re-encrypt the forged XML:
   ```
   python3 ptcrypt.py enc forged.xml exp2.pka
   ```
4. Submit `exp2.pka` to the instance (`application/octet-stream`):
   ```
   curl -s -X POST https://<instance>.challs.ctf.thefewchosen.com/api/submit \
     -H 'content-type: application/octet-stream' --data-binary @exp2.pka
   ```
   Output (the variant that worked):
   ```
   {"ok":true,"message":"J*B Online Assessment complete. You're hired.","matched":122,"required":122,"flag":"TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026}"}
   ```
   (`exp1` hit a transient SSL EOF on the first submit; `exp2` succeeded.)

## Full chain
1. `python3 ptcrypt.py dec job-oa.pka out.xml`
2. edit `out.xml`: student network (#0) := answer network (#2)
3. `python3 ptcrypt.py enc forged.xml exp2.pka`
4. `curl -X POST <instance>/api/submit -H 'content-type: application/octet-stream' --data-binary @exp2.pka`

## Flag
TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026}

## Lessons
- Proprietary file formats are obfuscation, not security: a static key and a
  plaintext answer inside the file defeat the "completion" check.
- A precise progress counter (`18/122`) is a free oracle — use it to test each forge
  variant until it reports `matched:122`.
