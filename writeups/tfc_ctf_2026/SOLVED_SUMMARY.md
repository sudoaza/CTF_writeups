# TFC CTF 2026 — Final Solve Log (event: thefewchosen)

Team: sudoaza. Backend https://api.ctf.thefewchosen.com. Creds in creds.json.

## Result: 24 flags (dynamic scoring at event end). See WRITEUPS.md for the full 29-challenge writeup incl. the 5 unsolved blockers.

| # | Challenge | Flag | Technique |
|---|-----------|------|-----------|
| 1 | rules | TFCCTF{M4ny_ch4ng3s...m0r3_3ff0rt} | read the rules page |
| 2 | 1+1 | TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3} | AGCD/SDA lattice (LLL) |
| 3 | cer frumos | TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu} | MT19937 partial getrandbits -> GF(2) solve |
| 4 | math or meth? | TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs} | Nguyen-Stern HSSP + fpylll CVP |
| 5 | minigame | TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d} | gdb call flag-hash fn |
| 6 | minigame2 | TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying} | gdb call flag-hash fn |
| 7 | bitdebit³ | TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool} | one-bit _IO_buf_end flip -> House of Apple 2 |
| 8 | unbrevable | TFCCTF{well_known_technique_brudda} | fork_handlers overwrite -> setcontext ROP |
| 9 | turip | TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf} | TCP SYN-payload desync vs gopacket |
| 10 | Tagger | TFCCTF{Tagg3r_m15C0muN1cA710n} | cache-key collision + autofocus/onfocus XSS |
| 11 | The pyjail | TFCCTF{i_hope_this_is_not_the_last_jail} | FileFinder no-parens call + outbound curl |
| 12 | lumaes | TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9} | whitebox AES recovery |
| 13 | fluxion | TFC{5d7096f57f88723bfccc910121b7f9cd} | constructor.prototype pollution + FCP handshake |
| 14 | J*B Online Assessment | TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026} | PT 8.x .pka TwoFish-EAX forge (122/122) |
| 15 | Project Americas | TFCCTF{a_vm_dreams_in_galois_fields_6e91c2} | unicorn PE emulation of Go VM (deriveMaterial) |
| 16 | rivers | TFCCTF{even_math_is_cooked_its_so_joever} | Alpöge JC counterexample (det JF=-2) |
| 17 | Discord Shenanigans v6 | TFCCTF{castle} | acrostic word in #announcements |
| 18 | Fishing not Phishing | TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6} | GFW AIS + vessel ID (STEAUA DE MARE 1) |
| 19 | V8 motor | TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a} | bitFlip one-bit sandbox escape + wasm shellcode |
| 20 | Mid | TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch} | change-point+checkpoint solver (220 queries) |
| 21 | Cadence | TFCCTF{the_encore_resonates_over_gf2_7c4e91ab} | GF(2) linear solve of audio PRF |
| 22 | Ship Me | TFCCTF{parcelables_are_safer_not_safe} | self-a11y + relay to foreground + window read |

| 23 | Vaultkeeper | TFC{04d4c11ea3641f2ec562b657ea6428b4} | CVE-2024-38473: %3F FilesMatch+Require-ip bypass -> SSRF -> cap_key -> forged cap -> SQLi -> unserialize RCE |
| 24 | Ariadne's Tab | TFCCTF{0ne_r3d1rect_aw4y_fr0m_th3_tak30v3r} | open redirect chain to leak the bot session |

## Unsolved (7) — documented blockers
- meshgate (0 solves): 3 secrets in unreachable app source.
- larpin2 (0): premium-token family (same as LarpIn).
- mccrab3 (4): proxy deny-list vs gunicorn; every parser discrepancy disproven; game infeasible.
- Ariadne's Tab (13): a11y (no WRITE_SECURE_SETTINGS) / postMessage (DAL cert) / root (no su) all dead.
- LarpIn (48): premium token 64-hex, no leak path (no bot, no static asset, no issuance).
- No Hot Water Club (48): KV-cache digest requires byte-exact CPU ISA (AVX512) - no matching box.
- Vaultkeeper (76): SSRF loopback trigger unknown; chain fully staged.

## Knowledge base
All 22 solves have techniques in /root/prime/ctf/knowledge/<category>.md.
Full HackTricks + PayloadsAllTheThings mirrored at /root/prime/ctf/references/.

## Infra notes
- Login: POST /auth/login -> access_token. Submit: POST /challenge/submit {flag_id,flag,challenge_id}.
- Dynamic: challenge-manager.management.ctf.thefewchosen.com /isolated (POST start / GET list / DELETE /isolated/<FULL_NAME> stop).
- Android submit: POST https://android.koth.pro/provision (X-Auth=team token, challenge + apk); logs via WS /ws/<session_id> (tag TFCCTF).
- KOTH: game.koth.pro /api/login {token} + POST /api/bots (bot.wasm + loadout). Bot v23/adaptive BBB live.
