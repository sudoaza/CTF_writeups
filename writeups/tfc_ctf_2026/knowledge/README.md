# CTF Knowledge Base

Persistent technique documentation, consolidated by category. Every CTF task must:
1. Read the matching category file here BEFORE starting.
2. Search the web for writeups of the specific challenge or its technique (see each file's SEARCH section).
3. After solving (or failing), append new techniques/links learned to the matching file.

Categories:
- crypto.md      - RSA, AES modes, PRNG/Mersenne, lattices/LLL, AGCD, hash, ECC
- pyjail.md      - Python sandbox escapes
- web.md         - SSRF, auth, logic bugs, IDOR, command injection, file upload
- xss.md         - stored/reflected XSS, CSP bypass, bot stealing
- pwn.md         - buffer overflow, ROP, format string, heap, ret2libc
- reversing.md   - static/dynamic analysis, deobfuscation, game/flag checks
- forensics.md   - file carving, stego, memory, PCAP
- android.md     - APK analysis, deep links, exported components
- misc.md        - OSINT, Discord, regex/encoding, hardware

Rules: no nmap on infra; only target the CTF platform and its challenge services.


## Local cheat-sheet mirrors (offline)
Full HackTricks (legacy markdown) and PayloadsAllTheThings are cloned at
/root/prime/ctf/references/ (hacktricks-legacy/, payloadsallthethings/).
Search: `grep -ri "<term>" /root/prime/ctf/references/`.
