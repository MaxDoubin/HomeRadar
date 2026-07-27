# Architecture

## Overview

Home Radar runs as a set of Python services on a repurposed machine sitting on the
family's LAN. It never sits inline between devices and the router — it observes and
proxies DNS, but the internet keeps working even if Home Radar is unplugged.

```
backend/
├── main.py              FastAPI app + background discovery loop
├── config.py             Environment-driven settings
├── discovery/            ARP scanning, mDNS listening, port scanning, fingerprinting
├── dns/                   DNS proxy + blocklist management (Phase 2)
├── monitor/               Traffic analysis, threat intel, trust scoring (Phase 2-4)
├── alerts/                Notifications + weekly email digest (Phase 4)
├── api/                   REST routes (WebSocket added in Phase 3)
└── db/                    SQLite schema + thin data-access layer
```

## Discovery pipeline (Phase 1+, implemented)

1. `arp_scanner.py` actively identifies LAN hosts and stable MAC addresses.
2. `neighbor_scanner.py` reads the operating system's ARP/neighbor cache, providing a
   no-root fallback and finding devices the active broadcast may miss.
3. `mdns_scanner.py` browses common DNS-SD services advertised by printers, AirPlay,
   Cast, Sonos, HomeKit/Matter, cameras, NAS devices, and smart-home hubs.
4. `ssdp_scanner.py` sends a standard UPnP discovery request and captures device types,
   product/server strings, and stable identifiers from routers, media devices, cameras,
   and consoles.
5. `scan_runner.py` correlates all four sources by IP and MAC, fingerprints hosts
   concurrently, persists results, and raises detailed first-seen alerts.
6. `device_fingerprint.py` scores independent vendor, name/model, port, mDNS, and SSDP
   evidence. It stores the winning category, confidence, competing scores, and evidence
   rather than returning an unexplained guess.
7. `main.py` runs this pipeline on a timer (`HOMERADAR_ARP_SCAN_INTERVAL`, default 60s)
   and also exposes `POST /scan` to trigger a pass on demand.

## Data model

Single SQLite file (`backend/data/homeradar.db` by default), five tables:
`devices`, `events`, `alerts`, `traffic_logs`, `trust_scores`. See
`backend/db/schema.sql` for the full definitions. SQLite was chosen deliberately over a
client-server database — it's zero-config and keeps the whole appliance a single
portable file, matching the "plug in and go" pitch.

Device records include advertised model, services, discovery sources, fingerprint
confidence, and JSON evidence. Startup performs additive schema migration so existing
Phase 1 databases gain these fields without losing inventory or authorization state.

## Why passive + DNS proxy, not inline

Being inline (bridge/router mode) would give deeper visibility but means any Home Radar
crash takes the family's internet down with it — unacceptable for a $0 appliance nobody
is paid to maintain. Passive ARP/mDNS discovery plus acting as the LAN's DNS server (via
DHCP) gives most of the same visibility (every device, every DNS query) with a trivial
failure mode: DNS proxy dies → clients fall back to the router's DNS after a timeout,
nothing else breaks.
