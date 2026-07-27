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

## Discovery pipeline (Phase 1, implemented)

1. `discovery/arp_scanner.py` broadcasts ARP requests across the local subnet and
   collects `{ip, mac}` pairs for every host that responds.
2. `discovery/device_fingerprint.py` enriches each host: `oui_lookup.py` resolves the MAC
   vendor, `port_scanner.py` probes a curated list of consumer/IoT ports, and a
   hostname reverse-lookup is attempted. A small rule-based classifier turns those
   signals into a device category (phone, smart_tv, iot_camera, printer, computer,
   unknown).
3. `discovery/scan_runner.py` orchestrates one full pass: scan → fingerprint → persist
   via `db/models.py` → raise a `new_device` alert the first time a MAC is seen.
4. `main.py` runs this pipeline on a timer (`HOMERADAR_ARP_SCAN_INTERVAL`, default 60s)
   and also exposes `POST /scan` to trigger a pass on demand.

## Data model

Single SQLite file (`backend/data/homeradar.db` by default), five tables:
`devices`, `events`, `alerts`, `traffic_logs`, `trust_scores`. See
`backend/db/schema.sql` for the full definitions. SQLite was chosen deliberately over a
client-server database — it's zero-config and keeps the whole appliance a single
portable file, matching the "plug in and go" pitch.

## Why passive + DNS proxy, not inline

Being inline (bridge/router mode) would give deeper visibility but means any Home Radar
crash takes the family's internet down with it — unacceptable for a $0 appliance nobody
is paid to maintain. Passive ARP/mDNS discovery plus acting as the LAN's DNS server (via
DHCP) gives most of the same visibility (every device, every DNS query) with a trivial
failure mode: DNS proxy dies → clients fall back to the router's DNS after a timeout,
nothing else breaks.
