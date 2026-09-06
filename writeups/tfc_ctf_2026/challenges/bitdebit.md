# bitdebit³

**Flag:** `TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}`

# bitdebit³ — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05T13:36:44.075961+00:00 — RECON + SOLUTION

- Binary: 64-bit PIE, not stripped, debug info. Category is pwn (not crypto despite parent guess).
- Program flow: leak libc base/puts -> "first addr" (u64) -> "first bit" (0-7) -> XOR 1<<bit into byte at addr -> fgets(name,0x100,stdin) -> puts -> return 0.
- setup(): setvbuf _IONBF on stdin/stdout/stderr, so stdin._IO_buf_base=shortbuf(stdin+0x83), _IO_buf_end=shortbuf+1.
- Primitive: one arbitrary single-bit XOR write anywhere (libc base known). Then one fgets.
- Exploit: flip bit 14 of stdin->_IO_buf_end (addr = base+0x21aae1, bit=6) so the unbuffered underflow read length becomes 0x4001. The name fgets triggers one big read(0, shortbuf, 0x4001), overflowing stdin FILE + _IO_wide_data_0 + main_arena + ... up to our sent payload length.
- Payload (0xb65 bytes) forges at libc base+0x21ad00 a fake FILE (vtable=_IO_wfile_jumps, wide_data=fake), fake wide_data (write_base=0,buf_base=0,wide_vtable=fake), fake wide vtable (__doallocate=system), and sets _IO_list_all=fake FILE. Command string " cat flag" at fake FILE start (leading space so _IO_UNBUFFERED/NO_WRITES/CURRENTLY_PUTTING flag bits are clear).
- exit -> _IO_cleanup -> _IO_flush_all_lockp(0) iterates _IO_list_all -> _IO_OVERFLOW -> _IO_wfile_overflow -> _IO_wdoallocbuf -> wide vtable __doallocate (unvalidated) = system(" cat flag").
- House of Apple 2 style wide-vtable bypass (wide vtable is not IO_validate_vtable'd). Works locally with provided ld-2.35.so/libc.so.6.
- Connector: TLS netcat at <deploymentName>.challs.ctf.thefewchosen.com:1337 (ssl, sni=host).


## 2026-09-05T13:43:56.081793+00:00 — SOLVED

- Flag: TFCCTF{this_is_probably_getting_solved_by_AI_but_so_be_it_i_thought_it_was_cool}
- Submission: ok:true (flag_id ce9f56f1-b977-4644-80b3-892f91a94395).
- Remote connection: TLS netcat at <deploymentName>.challs.ctf.thefewchosen.com:1337 (ssl=True, sni=host). deploymentName from start_container('bitdebit3-chal') -> "bitdebit3-chal-b61802662aaecdae".
- Delivery fix: send addr\n + bit\n + payload in ONE send() so the full overflow payload is buffered before the big read; sending the payload after waiting for the name prompt races and truncates (remote got only "See you around traveler").
- Container stopped/slot freed after solve.
