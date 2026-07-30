<div align="center">

# Home Radar

### Turn an old computer into a private home-network security appliance.

Device discovery, DNS threat blocking, trust scores, real-time alerts, family controls, and a polished local dashboard. No subscription. No cloud account. Open source.

[![Tests](https://github.com/MaxDoubin/HomeRadar/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/MaxDoubin/HomeRadar/actions/workflows/tests.yml)
[![Downloads](https://github.com/MaxDoubin/HomeRadar/actions/workflows/desktop.yml/badge.svg?branch=main)](https://github.com/MaxDoubin/HomeRadar/actions/workflows/desktop.yml)
[![Latest release](https://img.shields.io/github/v/release/MaxDoubin/HomeRadar?include_prereleases&label=latest)](https://github.com/MaxDoubin/HomeRadar/releases/tag/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-39e6a2)](LICENSE)

**Built for the 2026 Congressional App Challenge, Nevada District 3.**

</div>

---

## Download Home Radar

The links below always point to the newest successful build from `main`.

| Platform | Recommended download | Notes |
|---|---|---|
| **Windows 10/11, 64-bit** | **[Download Windows installer](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Windows-x64-Setup.exe)** | Guided installer with Start Menu and optional desktop shortcuts. |
| **Mac, Apple Silicon** | **[Download for M1, M2, M3, M4, or newer](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-macOS-Apple-Silicon.dmg)** | Native ARM64 build. |
| **Mac, Intel processor** | **[Download for Intel Mac](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-macOS-Intel.dmg)** | Native x86_64 build. |
| **Linux, portable** | **[Download AppImage](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Linux-x86_64.AppImage)** | Works across most modern 64-bit desktop distributions. |
| **Ubuntu or Debian** | **[Download DEB package](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Linux-amd64.deb)** | Installs through the system package manager. |
| **Android 8 or newer** | **[Download Android APK](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Android.apk)** | Companion application. Pair it with a running appliance. |
| **iPhone or iPad developers** | **[Download Xcode source](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-iOS-Xcode-Source.tar.gz)** | Apple requires signing for direct device installation. Open and sign in Xcode. |
| **Checksums** | **[Download SHA-256 checksums](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/SHA256SUMS.txt)** | Verify every application download. |

[View all releases and assets](https://github.com/MaxDoubin/HomeRadar/releases)

> **Desktop application or full appliance?** The Windows, macOS, and Linux desktop applications are the easiest way to explore Home Radar locally. For always-on household DNS protection, LAN-wide discovery, and an appliance other devices can connect to, use the Docker or dedicated-Linux installation below.

### Or skip the download entirely: install it from the browser

Every running appliance also serves itself as an installable **Progressive Web App** — no download, no certificate, no app store. Open the dashboard's own address (e.g. `http://<appliance-ip>:8000`) in Chrome, Edge, or Safari and use the browser's **Install app** / **Add to Home Screen** option. The app shell keeps working offline once installed, though live data still needs a network connection to the appliance. This is an additional way to run the dashboard, not a replacement for any of the downloads above.

Service worker registration (and therefore installability/offline support) requires a secure browsing context — HTTPS, or `http://localhost`. It silently does nothing on a plain `http://<lan-ip>:8000` address, which is how most households reach their appliance; the dashboard itself works identically either way, with or without the installable layer.

### Just want to see it running, with nothing to set up?

[`render.yaml`](render.yaml) deploys the real Home Radar appliance to Render's free tier for exactly this: a public link for a demo or presentation, no local network required. It turns on `HOMERADAR_DEMO_MODE`, which adds a **Simulate an attack** panel to Settings — one click fires a real, dashboard-visible alert (a Wi-Fi deauth attempt or a malicious connection) through the same code a genuine detection would use, without needing real attack traffic. It's off by default everywhere else; a real appliance should never be able to fabricate its own alerts.

### First launch notes

Home Radar builds are currently open-source community builds and are not yet signed with commercial Apple or Microsoft certificates.

- **macOS:** Open the DMG, drag Home Radar to Applications, then right-click the app and choose **Open**. If macOS blocks it, use **System Settings → Privacy & Security → Open Anyway**.
- **Windows:** Microsoft SmartScreen may show an unrecognized-app warning. Verify the checksum, choose **More info**, then **Run anyway**.
- **Linux AppImage:** Run `chmod +x HomeRadar-Linux-x86_64.AppImage`, then open it.
- **Android:** Enable installation from the browser or file manager you used to download the APK. The companion app must be paired with a Home Radar appliance.

---

## Fastest full-appliance installation

### Option 1: Docker Compose

Requirements: a Linux computer, Docker Engine, and the Docker Compose plugin.

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
cp .env.example .env
docker compose -f docker/docker-compose.yml up -d
```

Open `http://<appliance-ip>:8000` from the appliance itself. Home Radar will guide you through setup. Other browsers and mobile devices must enter a one-time pairing code generated by the appliance or an already paired device.

### Option 2: Published Docker image

```bash
docker run -d \
  --name homeradar \
  --restart unless-stopped \
  --init \
  --network host \
  --cap-drop ALL \
  --cap-add NET_RAW \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  -v homeradar-data:/data \
  ghcr.io/maxdoubin/homeradar:latest
```

### Option 3: Native Debian service

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
sudo ./scripts/setup.sh
```

The installer builds the dashboard, stores data in `/var/lib/homeradar`, installs systemd services, and creates `/etc/homeradar/homeradar.env` for optional email and threat-intelligence settings.

See the complete [installation and rollback guide](docs/INSTALL.md) and the beginner-friendly [old laptop guide](docs/OLD_LAPTOP_GUIDE.md).

---

## What Home Radar does

### See every device

Home Radar combines ARP discovery, the operating system neighbor cache, mDNS/DNS-SD, SSDP/UPnP, MAC-vendor information, hostnames, observed services, and confidence scoring. It identifies phones, computers, routers, access points, printers, cameras, doorbells, smart TVs, consoles, speakers, hubs, plugs, thermostats, wearables, NAS devices, servers, virtual machines, and unknown devices without inventing an identity when evidence is weak.

### Block dangerous domains

The local DNS proxy supports UDP and TCP, upstream failover, caching, community blocklists, custom DNS records, device-level pauses, quiet hours, allowlists, and blocklists. Requests to blocked malware, phishing, and tracking domains are denied and recorded as local security metadata.

### Explain risk instead of producing mystery scores

Every device receives an explainable trust score based on identity confidence, known-bad destinations, unusual behavior, service exposure, and historical patterns. The dashboard shows the reasons behind each score and creates actionable alerts.

### Keep control inside the home

Network history and device inventory stay in the appliance's local SQLite database. AbuseIPDB checks and email delivery are optional. The dashboard now requires pairing for every remote browser, mobile client, backup download, settings change, device policy, and WebSocket session.

---

## Included features

- Responsive React dashboard with overview, device inventory, topology map, traffic, alerts, settings, backups, pairing, and first-run setup
- Installable Progressive Web App served directly by the appliance — browser-only install with no certificates or app stores, plus offline app-shell caching
- Native Windows, macOS Intel, macOS Apple Silicon, Linux, Android, and iOS companion code
- Local DNS firewall with blocklists, custom records, caching, TCP fallback, and multiple upstream resolvers
- Multi-signal device fingerprinting with confidence and evidence
- Explainable device trust scores and a household security score
- New-device, malicious-destination, DNS-block, anomaly, and service-exposure alerts
- Per-device internet pause, quiet-hour schedules, custom allowlists, and blocklists
- Weekly email digest, browser notifications, mobile notifications, and real-time WebSockets
- Optional AbuseIPDB reputation checks and local CISA Known Exploited Vulnerabilities catalog
- Passive traffic observation and experimental anomaly detection, with per-device bandwidth sparklines on the Devices page
- Daily integrity-checked SQLite backups, retention cleanup, and health diagnostics
- Docker, native Debian, kiosk, desktop, and live-ISO build paths
- Demo mode for presenting the interface without scanning a real network, plus an opt-in live attack simulator (`HOMERADAR_DEMO_MODE=true`) that fires a real, dashboard-visible alert on demand for presentations

---

## Security model

Home Radar is a security appliance, so its management interface is deliberately not open to every device on the LAN.

1. A browser running directly on the appliance can securely bootstrap the first management token.
2. Remote browsers and companion apps enter a six-digit, single-use pairing code.
3. Pairing codes expire after ten minutes and lock temporarily after repeated failures.
4. Sensitive reads and every modifying operation require the long random pairing token.
5. WebSocket snapshots and database backups use the same authentication boundary.
6. Cross-origin browser access is disabled by default.
7. The Docker deployment drops all capabilities except raw-network discovery and binding the DNS port, uses a read-only filesystem, and persists only `/data`.

Home Radar does not attempt passwords, exploit devices, or perform invasive vulnerability scans. Service exposure findings are based on deliberately limited, common home-network ports.

Read [SECURITY.md](SECURITY.md) before exposing the interface beyond a trusted home LAN. Home Radar is not designed to be published directly to the internet.

---

## Network position and limitations

Home Radar runs alongside other devices rather than inline between the router and internet. Clients use it as their DNS resolver, while discovery observes the local network.

- DNS blocking cannot stop traffic sent directly to a hard-coded IP address.
- A switched network may not expose every device's unicast packets without port mirroring.
- ARP discovery is IPv4-specific; other discovery sources still provide additional evidence.
- If the appliance is unavailable, clients configured only with its DNS address may temporarily lose name resolution. Keep the router's original resolver documented for rollback.
- The desktop applications run without elevated privileges by default, so raw-packet discovery and port-53 DNS service may be limited. A Linux appliance is the recommended protection mode.

---

## Safe DNS activation

Do not point the whole household at Home Radar immediately.

1. Confirm `/health` reports a healthy database and service.
2. Run discovery and review the device inventory.
3. Configure one test client to use the appliance IP as DNS.
4. Verify normal domains resolve and a known test block is denied.
5. Update the router's DHCP DNS setting only after the test succeeds.
6. Keep the original DNS setting ready as a rollback option.

---

## Development

### Backend

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
.venv/bin/python -m pytest tests/
.venv/bin/python -m backend.main
```

On Windows, replace `.venv/bin/` with `.venv/Scripts/`.

### Frontend

```bash
cd frontend
npm ci
npm test
npm run dev
```

### Desktop packaging

```bash
cd desktop
bash build.sh
npm run build
```

### Android

```bash
cd mobile/android
gradle :core:test :app:assembleDebug
```

Every pull request runs backend tests on Python 3.11 and 3.12, frontend tests and production build, Electron syntax validation, Android tests and APK compilation, iOS static analysis and a simulator build, and a complete Docker build — plus a separate security/quality pipeline covering CodeQL, Ruff, Mypy, Bandit, `pip-audit`/`npm audit`, ESLint, and shell/Dockerfile/secret scanning. A third workflow packages full, installable desktop builds for Windows, macOS (Intel and Apple Silicon), and Linux on every pull request too, ahead of publishing them from `main`.

---

## Project status

The integrated software foundation is implemented, including discovery, DNS filtering, dashboard, pairing, trust scoring, alerts, backups, mobile clients, desktop packaging, Docker publishing, and release automation.

Before Home Radar is described as production-ready, it still needs documented real-network validation on multiple old machines, physical ISO boot testing, DNS-failure drills, and at least one uninterrupted week-long household reliability test. Those validation tasks are tracked in [the project plan](docs/PROJECT_PLAN.md).

---

## Documentation

- [Installation and DNS rollback](docs/INSTALL.md)
- [Old laptop setup guide](docs/OLD_LAPTOP_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Device fingerprinting](docs/DEVICE_FINGERPRINTING.md)
- [Security pipeline](docs/SECURITY_PIPELINE.md)
- [Open-source inspiration and prior art](docs/OPEN_SOURCE_INSPIRATION.md)
- [Project plan](docs/PROJECT_PLAN.md)
- [Contributing](docs/CONTRIBUTING.md)

## License

Home Radar is released under the [MIT License](LICENSE).
