# Fishing not Phishing

**Flag:** `TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6}`

# Fishing not Phishing — running log

Append-only. Timestamp every entry.

## Hypotheses
## Findings
## Dead ends
## Limitations
## Next actions


## 2026-09-05 16:19 UTC — deep investigation

### Findings
- Image: 326x200 progressive JPEG, no EXIF/appended data/APP markers. Clean file.
- Vessel: white hull, dark blue lower band, white superstructure, YELLOW hydraulic deck crane, orange lifebuoy, small (~20-40m). Likely research/fisheries vessel. Bow on left.
- Reverse image search (Google Lens via Serper, Yandex CBIR, Bing, TinEye): NO exact match, only generic white/blue research+fishing vessels.
- Vision models read the hull name inconsistently: MARIE/MARIA/MARIEL/MAREE/EMARIE/MIRAGE/EMPIRE/CAPRICE/SAN MARCEL/SAINTE MARIE. Strongest signal: name starts "MAR". Not reliably readable.
- GFW platform: vessel pages server-render IDENTITY. EVENTS are client-fetched anonymously.
- BUILT WORKING GFW access: playwright route-intercepts events requests to change dates, captures fishing + port-visit events for ANY date range.
- GFW anonymous endpoints: /v3/vessels/<UUID>, /v3/events (UUID). /v3/vessels/search needs auth. /v3/vessels/<MMSI> 404s (UUID only).
- CAPRICE (Norway 257619000) checked: 37 fishing + 6 port visits Sept 2023, but blue crane -> NOT match.
- ARNE TISELIUS (Denmark, fishery research): blue hull, white crane -> NOT match.

### Next actions
- Identify vessel: check candidate photos for YELLOW crane + white hull + dark blue band.
- Once identified: get GFW UUID, query Sept 2023 events, compute answer.


## 2026-09-05 17:24 UTC — round 2

### Key findings
- GFW anonymous API access SOLVED: POST /v3/events (fishing events by UUID or GeoJSON polygon, any date range) + GET port-visits by UUID, via playwright route-intercept. No token needed.
- Vessel identification is the blocker. Vision models (gpt-4o/4.1/5/o3, original+RealESRGAN) read the hull name inconsistently:
  - MAR* core (MARIE/MARIA/MAREE/MARE) — most frequent
  - EMPIRE/AMPIRE/EMPRESS (MPIRE core)
  - PERMARE/PERMAAE (o3/gpt-4.1 on upscale)
  - CAPRICE (gpt-4o high-conf once), SAN MARCEL, MIRAGE
  - NOT "MAGU"/"NUEVO MAGU".
- Vessel appearance: WHITE hull, DARK BLUE lower band (B>G, not green), YELLOW crane, orange lifebuoy, small (~20-30m). Likely small fishing trawler.
- NUEVO MAGU hypothesis REJECTED: name mismatch + green hull band (image band is blue). Flag submitted with its perfect Sept-2023 story (Santa Pola dep 29.09 03:16, fish 10:55 UTC) was REJECTED ("invalid flag").
- Reverse image search: no exact match (Google Lens/Yandex/Bing/TinEye). Yandex CBIR top="MAGU" (Santa Pola, similar only).
- Santa Pola Sept-2023 fishing fleet (72 vessels) enumerated via polygon query; "MAR*" names = MARUHA (busy, 7km inshore), MARUFINA (21 evts, 31-37km offshore). No "MARIE"/"MAREA"/"EMPIRE"/"PERMARE" in that set.
- Broad ESP Mediterranean Sept-2023 query (8910 events): only "X Y MARIA" names, no MAREA/EMPIRE/PERMARE/MARIE.

### Flag attempts (all rejected "invalid flag")
- TFCCTF{224096930_santa pola_29.09.2023_10:55_AM_41.7}  (NUEVO MAGU)
- TFCCTF{224096930_santapola_29.09.2023_10:55_AM_41.7}
- TFCCTF{test}

### Next actions
- Pin the name: try Italian MAREA I (MMSI 247095010, 15m) or PERMARE fishing vessels; need GFW UUID (search UI requires auth; Google index spotty).
- Consider August 2023 if "this same month" refers to challenge-writing month.


## 2026-09-05 17:45 UTC — SOLVED

### Answer
- Vessel: STEAUA DE MARE 1 (IMO 8008709, MMSI 264900119, Romania). Ex-DELFIN. 25.67m trawler/research ship, white hull + dark blue band + yellow crane.
- Port of departure: Constanta (GFW port visit rou-constanta, departed 2023-09-21 08:44 UTC).
- Fishing started: 2023-09-21 07:17:06 UTC (first fishing event of Sept 2023), position centroid (44.0637, 28.9227) in the Black Sea.
- Distance: haversine between GFW port position (44.1101, 28.7383) and fishing event position (44.0637, 28.9227) = 15.6 km.
- FLAG: TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6}  (platform returned ok:true)

### Technique
1. Vision models could not read the hull name reliably; parent hints gave "DE MARE" then "STEAUA DE MARE 1 - IMO 8008709".
2. ShipSpotting photo 914734 confirmed identity (white hull, dark blue band, yellow crane — vision model SAME match).
3. GFW anonymous API (POST /v3/events with vessels/polygon, any date range) gave fishing events + port visits.
4. Distance = haversine(GFW port-visit position, fishing-event centroid) -> 15.6 km (NOT GFW's startDistanceFromPortKm 10.95).

### Limitations
- Name not machine-readable from the 326x200 image alone; needed human hints.
- GFW "startDistanceFromPortKm" (nearest-port distance 10.95) was NOT the intended value; the intended value is the straight-line haversine between the shown port position and event position (15.6).
