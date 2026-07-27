# HomeRadar

Turn any old laptop into a free, open-source home network security appliance.

Every family has an old laptop collecting dust and a home network they can't see into.
Home Radar turns the former into a fix for the latter: plug it into your router and get
device discovery, DNS-level threat blocking, and real-time alerts - for **$0**.

Built for the [Congressional App Challenge](https://www.congressionalappchallenge.us/) 2026, NV-03.

## Status

**Phase 1 foundation complete; advanced discovery is implemented.** Home Radar now
combines ARP, the operating-system neighbor cache, mDNS/DNS-SD, SSDP/UPnP, reverse DNS,
MAC vendor data, and targeted service-port checks. It is still development software and
is not yet ready to replace a production security appliance.
See [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md) for the full roadmap.

## Quick start (development)

```bash
cd backend
pip install -r requirements.txt
sudo python3 main.py   # sudo/CAP_NET_RAW needed for ARP scanning
```

The API comes up at `http://localhost:8000`. Try `GET /status`, `GET /devices`,
`GET /inventory/summary`, `GET /alerts`, or `POST /scan` to trigger a discovery pass.

## How it works

Home Radar runs alongside your devices - never inline between them and the internet. It
combines ARP and the host neighbor cache with mDNS/DNS-SD and SSDP/UPnP advertisements,
then enriches each device with its MAC vendor, hostname, model hints, open services, a
device category, a confidence score, and the evidence behind the decision.

The classifier recognizes phones, tablets, computers, servers, virtual machines, routers,
access points, switches, printers, cameras, doorbells, TVs, streaming devices, consoles,
smart speakers, smart-home hubs, plugs, thermostats, wearables, NAS devices, media
servers, and generic IoT devices. Unknown remains a valid result when the evidence is
weak - Home Radar does not invent an identity.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.
See [docs/DEVICE_FINGERPRINTING.md](docs/DEVICE_FINGERPRINTING.md) for the signal model.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
