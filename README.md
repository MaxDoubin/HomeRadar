# Home Radar

Turn any old laptop into a free, open-source home network security appliance.

Every family has an old laptop collecting dust and a home network they can't see into.
Home Radar turns the former into a fix for the latter: plug it into your router and get
device discovery, DNS-level threat blocking, and real-time alerts — for **$0**.

Built for the [Congressional App Challenge](https://www.congressionalappchallenge.us/) 2026, NV-03.

## Status

Early development (Phase 1 — Foundation). Not yet ready for real-world deployment.
See [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md) for the full roadmap.

## Quick start (development)

```bash
cd backend
pip install -r requirements.txt
sudo python3 main.py   # sudo/CAP_NET_RAW needed for ARP scanning
```

The API comes up at `http://localhost:8000`. Try `GET /status`, `GET /devices`, `GET /alerts`,
or `POST /scan` to trigger a discovery pass on demand.

## How it works

Home Radar runs passively on your LAN — it never sits inline between your devices and the
internet, so it can never break your family's connection. It uses ARP scanning and passive
listening (mDNS/SSDP) to build a live device inventory, and (in later phases) becomes your
network's DNS server to see and block malicious domains.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
