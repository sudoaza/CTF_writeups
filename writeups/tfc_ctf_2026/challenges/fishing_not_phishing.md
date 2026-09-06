# Fishing not Phishing

OSINT/forensics challenge: identify a vessel from one photo, reconstruct its AIS
tracking from September 2023, and compute the port-to-fishing distance. Key idea:
Global Fishing Watch's anonymous event API gives fishing and port-visit events once
the vessel is identified.

## Recon
- Given: `files/Fishing.jpeg` (326x200 progressive JPEG). No EXIF, no appended data,
  no APP markers — a clean image.
- Visual signature: white hull, dark blue lower band, white superstructure, yellow
  hydraulic deck crane, orange lifebuoy, roughly 20-40 m.
- Flag format:
  `TFCCTF{MMSI_Port Name_DD.MM.YYYY_HH:MM_AM/PM_distance}`
  (port lowercase, time in UTC 12-hour AM/PM, distance in km to 1 decimal).

## Analysis
- Observation: the image alone is not enough for vision models to read the hull
  name reliably (candidates: MARIE/MARIA/CAPRICE/EMPIRE/PERMARE/...). Reverse image
  search found no exact match.
- Hypothesis: reconstruct the vessel via AIS — it departed a port and began fishing
  in September 2023 ("three years ago, during this same month").
- Confirmation: Global Fishing Watch (GFW) exposes anonymous endpoints
  (`POST /v3/events` by vessel UUID or polygon, `GET /v3/port-visits` by UUID) that
  return fishing and port-visit events for any date range without auth.
- Vessel pinned to **STEAUA DE MARE 1** (IMO 8008709, MMSI 264900119, Romania), a
  25.67 m trawler/research ship (white hull + dark blue band + yellow crane);
  ShipSpotting photo 914734 confirmed the identity match.

## Exploit
1. Identify the vessel: STEAUA DE MARE 1, MMSI 264900119.
2. Query GFW for its September 2023 events (by vessel UUID):
   - Port of departure: Constanta (`rou-constanta`).
   - First fishing event of September 2023: 2023-09-21 07:17:06 UTC,
     position centroid (44.0637, 28.9227) in the Black Sea.
3. Compute the straight-line distance between the port position (44.1101, 28.7383)
   and the fishing position:
   ```
   haversine(44.1101, 28.7383, 44.0637, 28.9227) = 15.6 km
   ```
4. Assemble the flag (distance to 1 decimal, port name lowercase).

## Full chain
1. Identify vessel → STEAUA DE MARE 1, MMSI 264900119
2. GFW `POST /v3/events` (vessel UUID, Sept 2023) → fishing events
3. GFW `GET /v3/port-visits` (vessel UUID) → Constanta departure
4. `haversine(port_pos, first_fishing_pos)` → 15.6 km
5. Flag = `TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6}`

## Flag
TFCCTF{264900119_constanta_21.09.2023_07:17_AM_15.6}

## Lessons
- AIS archives (GFW) answer "when did a vessel fish" questions that MarineTraffic
  alone cannot; GFW's event endpoints work anonymously by vessel UUID + date range.
- The required distance is the haversine between the port position and the fishing
  position, not GFW's own nearest-port distance metric.
