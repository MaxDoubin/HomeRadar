# HomeRadar

Turn any old laptop into a free, open-source home network security appliance.

Every family has an old laptop collecting dust and a home network they can't see into.
Home Radar turns the former into a fix for the latter: plug it into your router and get
device discovery, DNS-level threat blocking, and real-time alerts - for **$0**.

Built for the [Congressional App Challenge](https://www.congressionalappchallenge.us/) 2026, NV-03.

## About

HomeRadar is an open-source home network security appliance built with a Python backend, a React frontend dashboard, an Electron-based cross-platform desktop application, and native iOS (SwiftUI) and Android (Kotlin) companion apps.

## Status

**The integrated MVP foundation is implemented.** Home Radar combines advanced device
discovery with a local DNS firewall, community blocklists, optional reputation feeds,
behavior-based trust scoring, real-time alerts, weekly digests, and a responsive React
dashboard. Per-device internet pauses, quiet-hour schedules, custom domain rules, and
non-invasive service-exposure findings add family controls without attempting passwords
or exploit probes. Docker, systemd, kiosk, and Debian live-ISO build paths are included,
as well as native iOS (SwiftUI) and Android (Kotlin) companion apps for mobile push notifications.
Experimental ML-based anomaly detection using scikit-learn is now included, as well as an active deauth defense mechanism.


It remains development software until it completes real-network, old-hardware, DNS
failover, and week-long reliability testing.
See [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md) for the full roadmap.

## Quick start

You can download the standalone desktop application for Windows, macOS, or Linux directly from the [GitHub Releases](https://github.com/homeradar/homeradar/releases) page. It bundles the backend and dashboard into one easy-to-run app.

Alternatively, Docker on a Linux appliance gives discovery and DNS access to the real LAN:

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

Open `http://<appliance-ip>:8000`. After verifying the dashboard, point your router's
DHCP DNS setting to the appliance IP to enable household-wide DNS logging and blocking.

For backend development:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/pip install -r backend/requirements-dev.txt
PYTHONPATH=. .venv/bin/python3 -m backend.main
```

To run backend tests, execute `python3 -m pytest tests/` after activating the virtual environment.

For frontend development, execute `cd frontend && npm install && npm run dev`.
To run frontend tests, execute `cd frontend && npm install && npm run test`.
To build the frontend, execute `cd frontend && npm install && npm run build`.

The frontend can be built and run in a standalone interactive 'Demo Mode' (using mock data without a backend) by setting the `VITE_DEMO_MODE=true` environment variable before executing frontend tests or build commands (e.g., `VITE_DEMO_MODE=true npm run build`).

To build and package the Electron desktop application, navigate to `desktop/`, run `npm install`, execute `bash build.sh` (to build the frontend and package the backend), and then run `npm run build`. The Electron app bundles the Python backend into a standalone executable using PyInstaller. Database and data directories are automatically redirected to the OS user data directory to avoid permission issues.

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

DNS requests pass through an independent local proxy that returns `NXDOMAIN` for
blocklisted domains, refuses DNS for household-blocked devices, forwards allowed
requests to the configured upstream resolver, and records only security metadata.
Optional passive flow observation and AbuseIPDB checks add outbound-connection context.
All security decisions remain explainable and local.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.
See [docs/DEVICE_FINGERPRINTING.md](docs/DEVICE_FINGERPRINTING.md) for the signal model.
See [docs/SECURITY_PIPELINE.md](docs/SECURITY_PIPELINE.md) for DNS, intelligence, and trust scoring.
See [docs/OPEN_SOURCE_INSPIRATION.md](docs/OPEN_SOURCE_INSPIRATION.md) for cited prior art.
See [docs/OLD_LAPTOP_GUIDE.md](docs/OLD_LAPTOP_GUIDE.md) for a guide on repurposing an old laptop to run Home Radar.

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
