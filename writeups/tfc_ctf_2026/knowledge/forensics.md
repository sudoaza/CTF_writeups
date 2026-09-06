# Forensics / stego techniques

## Common styles
- Given an image/zip/pcap/disk; flag hidden in metadata, LSB, appended data, or traffic.

## Key techniques
1. Recon: `file`, `strings`, `binwalk -e`, `exiftool`, `foremost`.
2. Zip/archive: zip password crack (john/zip2john), known-plaintext (pkcrack), zip slip, appended data.
3. Images: LSB stego (zsteg), color channels, exif, `steghide`, outguess, image size tamper (CRC/IHDR).
4. Audio: spectrogram (audacity/sox), phase, LSB.
5. PCAP: wireshark/tshark; extract files (File > Export Objects), follow TCP/HTTP, DNS exfil, TLS keys.
6. Memory/disk: volatility for memory dumps; strings + grep "TFCCTF{".
7. Obfuscation: base64/hex/rot/zlib; `file` + entropy; `binwalk -e` repeatedly.

## SEARCH
- "<challenge> forensics writeup", "zsteg writeup", "binwalk extraction writeup"

## References
- https://book.hacktricks.wiki/en/forensics/


## SOLVED case study: TFC 2026 `Fishing not Phishing` (OSINT/AIS)
- Given a vessel photo + 'three years ago this month'. Vessel ID from image: white hull, dark-blue band, yellow crane -> STEAUA DE MARE 1 (IMO 8008709, MMSI 264900119, Romania). Vision models disagreed on the name; cross-referenced candidate names against GFW (Global Fishing Watch) anonymous AIS events (by UUID/polygon for Sept-2023).
- GFW event 2023-09-21 07:17 UTC, port Constanta, haversine port->fishing-start = 15.6 km. Flag = TFCCTF{MMSI_port_DD.MM.YYYY_HH:MM_AM/PM_distance} (lowercase port, UTC 12h).
- Lesson: for AIS/vessel OSINT, enumerate candidate names from the image, then match each against GFW fishing events (not just MarineTraffic); GFW's anonymous events API works by UUID/date.


## OSINT vessel-tracking (AIS) - Fishing not Phishing (TFC CTF 2026)
- Given a vessel photo: reverse image search (Yandex CBIR / Google Lens via Serper) + vision model; low-res hull names may be unreadable, so use ShipSpotting/MarineTraffic/VesselFinder photo galleries or human hints.
- Global Fishing Watch anonymous access (NO API token) works for:
  - POST https://gateway.api.globalfishingwatch.org/v3/events  body: {"datasets":["public-global-fishing-events:v4.0"],"startDate","endDate","vessels":[UUID] or "geometry":Polygon,"flags":[..],"includes":[..]} -> fishing events (start/end/position/bbox/distances).
  - Same with dataset public-global-port-visits-events:v4.0 -> port visits (port_visit.intermediateAnchorage.id/name).
  - /v3/vessels/search needs auth (403); /v3/vessels/{id} only takes GFW UUID (MMSI 404s). Find UUID via Google: globalfishingwatch.org/platform/vessel/ URLs.
  - Playwright: load any GFW vessel page then page.evaluate(fetch) to gateway with Authorization:"Bearer" (empty) + Referer; plain httpx gets 403.
- Flag pattern: TFCCTF{MMSI_PortName_DD.MM.YYYY_HH:MM_AM/PM_distance}. Distance = haversine(GFW port-visit position, fishing-event position centroid), 1 decimal. GFW's own startDistanceFromPortKm is nearest-port distance and can differ.
- Solved: STEAUA DE MARE 1 (IMO 8008709, MMSI 264900119, Romania); port Constanta; fish start 2023-09-21 07:17 UTC; distance 15.6 km.
