# TFC CTF 2026 — Writeups (all 29 challenges)

Team sudoaza. 24 solved / 5 unsolved. Consolidated from notes.md + SOLVED_SUMMARY.md + knowledge/*.md.


## Solved (24)

- **1+1** — `TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3}`
  - AGCD: SDA lattice (LLL) recovers p from x_i = p*q_i + r_i

- **Ariadne's Tab** — `TFCCTF{0ne_r3d1rect_aw4y_fr0m_th3_tak30v3r}`
  - adb-over-TCP root on the emulator -> read the ariadnetab SharedPreferences + Chrome leveldb -> API decrypt of the flag

- **bitdebit³** — `TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}`
  - one-bit _IO_buf_end flip -> FILE overflow -> House of Apple 2 (wide vtable __doallocate=system)

- **Cadence** — `TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}`
  - GF(2) linear solve of the audio PRF (encore.resonates)

- **cer frumos** — `TFCCTF{ursu_ursa_bea_ursus_intrun_urus_verzuliu}`
  - MT19937 state recovery from partial getrandbits(48) via GF(2) linear solve

- **Discord Shenanigans v6** — `TFCCTF{castle}`
  - acrostic word in #announcements

- **Fishing not Phishing** — `TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6}`
  - GFW AIS events + vessel ID (STEAUA DE MARE 1)

- **fluxion** — `TFC{5d7096f57f88723bfccc910121b7f9cd}`
  - constructor.prototype pollution (__proto__ blocked) + FCP handshake

- **J*B Online Assessment** — `TFCCTF{cheating_is_the_only_way_to_get_a_job_in_2026}`
  - Packet Tracer .pka TwoFish-EAX forge: replace student network with answer network

- **lumaes** — `TFCCTF{5kr_5kr_wh173b0x_435_15_k1nd4_fun_095dfj2kpf9}`
  - whitebox AES key recovery

- **math or meth?** — `TFCCTF{this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs}`
  - Nguyen-Stern hidden subset sum: orthogonal lattice + fpylll CVP

- **Mid** — `TFCCTF{w3_l0v3_a_g0od_b1nary_se4rch}`
  - change-point + checkpoint solver (remote actually 220 queries, not 195)

- **minigame** — `TFCCTF{r3dst0n3_c1rcu1t_v4ult_unl0ck3d}`
  - gdb: set vault key, call flag-hash fn 0x11ef760, dump 0x1406630

- **minigame2** — `TFCCTF{a_small_game_now_bigger_hope_it_wasnt_annoying}`
  - gdb: set preconditions, call 0x11f0d30, dump 0x140763b

- **Project Americas** — `TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}`
  - unicorn PE emulation of Go arithmetic VM (deriveMaterial)

- **rivers** — `TFCCTF{even_math_is_cooked_its_so_joever}`
  - Alpöge JC counterexample (det JF=-2)

- **rules** — `TFCCTF{M4ny_ch4ng3s...m0r3_3ff0rt}`
  - read the rules page; grep for the flag literal

- **Ship Me** — `TFCCTF{parcelables_are_safer_not_safe}`
  - self-a11y (WRITE_SECURE_SETTINGS) + relay to foreground me.ship + window read (flagRetrieveInteractiveWindows)

- **Tagger** — `TFCCTF{Tagg3r_m15C0muN1cA710n}`
  - username.trim() cache-key collision + autofocus/onfocus -> innerHTML=textContent XSS

- **The pyjail** — `TFCCTF{i_hope_this_is_not_the_last_jail}`
  - FileFinder no-parens call primitive + outbound curl exfil

- **turip** — `TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}`
  - TCP SYN-payload desync vs gopacket reassembly

- **unbrevable** — `TFCCTF{well_known_technique_brudda}`
  - libc leak + arbitrary write -> fork_handlers overwrite -> setcontext ROP

- **V8 motor** — `TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a}`
  - bitFlip one-bit sandbox escape + wasm RWX shellcode (string in wasm memory)

- **Vaultkeeper** — `TFC{04d4c11ea3641f2ec562b657ea6428b4}`
  - CVE-2024-38473: /api/fetch_source.php%3Fooo.php bypasses FilesMatch Require-ip gate; SSRF -> keyring -> vault_unseal -> cap_key -> forged cap -> SQLi -> unserialize RCE


## Unsolved (5) — blockers + attempted routes

- **LarpIn** — premium token (64-hex) gates the flag. Bot (Trust & Safety) is server-side (no CSS-exfil render). No SQLi/IDOR/mass-assignment/RCE/SSTI; secret random; no source-map/static-asset leak. Blocker: token source unknown.

- **No Hot Water Club** — ML relay; flag gated by sha256(tensor name+shape+bytes) == resident KV digest. Resident is one of 4097 courier rows; byte-exact reproduction needs matching CPU ISA (SDE/QEMU can emulate). Blocker: opaque row selection + 1-instance submission bottleneck; brute-force reached ~600/4035 before the deadline.

- **larpin2** — same premium-token family as LarpIn; CSS injection + premium-token mechanism mapped but no bot/report endpoint. 0 solves.

- **mccrab3** — Rust proxoxy deny-list blocks POST /flag + brevski:george; every header/framing/codec/buffer discrepancy disproven; game win (60 draws) is infeasible. Blocker: the bypass used by the 4 solvers is an unknown infra/non-parser trick.

- **meshgate** — SSO/federation + update center; 3 gates (OAuth client_secret, attestation secret, console token) in unreachable source; cluster SSRF + IdP enumeration + mass-assignment all exhausted. 0 solves.


## Reusable cross-challenge lessons


1. **Fresh-eyes disprove pattern**: when a challenge reaches a converged "blocked" conclusion, spawn a fresh unanchored worker told to DISPROVE it. Yielded Vaultkeeper (CVE-2024-38473), Ariadne's Tab (open redirect), and the hotwater ISA correction.
2. **Instance-slot arbitration**: one parent owns the shared 3-slot dynamic-instance pool; children do offline work first, request a slot, stop containers immediately on flag. (See knowledge + coordination.md.)
3. **%3F Apache FilesMatch bypass** (CVE-2024-38473): an encoded ? in the path makes Apache's r->filename differ from the basename the gate regex sees, while PHP-FPM still executes the .php.
4. **Byte-exact ML reproduction**: torch CPU fp32 KV digests depend on CPU ISA + thread count + attention impl; Intel SDE + QEMU TCG can emulate foreign x86 ISAs bit-exactly (gap: AMD Zen4 AVX512).
5. **Android solver APK**: platform-granted WRITE_SECURE_SETTINGS -> self-enable AccessibilityService; flagRetrieveInteractiveWindows is required for getWindows(); re-launch the exported target activity to force it foreground; D8 must include all .class files.
6. **Dynamic scoring**: points drift as teams solve; re-check /challenge frequently for new challenges and source-file updates mid-event.
