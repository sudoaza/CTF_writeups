# Vaultkeeper

**Flag:** `TFC{04d4c11ea3641f2ec562b657ea6428b4}`



## 2026-09-05 16:47:22 — h2c battery on fresh instance (re-armed): NO bypass
- Fresh instance vaultkeeper-89f4543d2ead8b8c; re-leaked mask = ljASkEoMaJV9NaYz (saved to mask.json).
- Confirmed live mod_http2: curl --http2-prior-knowledge -> http_version=2.
- h2c to /api/fetch_source.php|keyring|peer_probe = 403 (Require still applied over h2).
- h2c battery: byte-fuzz 0x00-0xff appends (--path-as-is) => ALL 404; backslash/%252e/%252f/%255c/;/. combos => 403/404; no bypass.
- Custom h2c client (raw socket + HPACK): split :path across HEADERS+CONTINUATION frames at multiple cut points => all 403. CONTINUATION-split does NOT bypass.
- HTTP/1.0 no-Host / Proxy-Connection / CONNECT / absolute-URI => router 404 or 403 (no bypass).
- LOAD DATA LOCAL INFILE re-verified no-op (mysqlnd); INTO OUTFILE 1045 (no FILE).
- CONCLUSION: Apache Require ip 127.0.0.1 holds on h1 AND h2c; no 2.4.56 gate quirk found. SSRF trigger remains the single blocker.
