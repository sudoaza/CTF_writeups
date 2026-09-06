# turip

**Flag:** `TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}`

# turip — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05T14:13:20.275369Z SOLVED
- Flag: TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}
- Technique: TCP SYN-payload desync (TCP Fast Open style) against Tulip/gopacket traffic capture.
  - Canonical request: POST /get_flag1337 with exact body {"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}.
  - Server returns X-Traffic-Barrier: <uuid>; /check grants flag only if the captured CLIENT stream has no forbidden needles.
  - gopacket reassembly delivers the SYN packet payload as client data and advances nextSeq; Linux (no TFO on gunicorn) ignores SYN payload.
  - Send SYN with benign payload of SAME length as the canonical request, then complete handshake and send the real request at seq=ISN+1.
    Monitor records only benign SYN payload; server receives canonical request -> marker -> flag.
  - Raw TCP via scapy; drop kernel RST: iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <port> -j DROP.
