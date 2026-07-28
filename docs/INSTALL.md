# Install Home Radar

Home Radar can run as a desktop application for evaluation or as a dedicated Linux appliance for full household DNS protection and LAN discovery.

## Desktop downloads

These stable links always point to the newest successful build from `main`:

- [Windows 64-bit installer](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Windows-x64-Setup.exe)
- [macOS for Apple Silicon](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-macOS-Apple-Silicon.dmg)
- [macOS for Intel processors](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-macOS-Intel.dmg)
- [Linux AppImage](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Linux-x86_64.AppImage)
- [Debian or Ubuntu DEB](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Linux-amd64.deb)
- [Android companion APK](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-Android.apk)
- [iOS Xcode source package](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/HomeRadar-iOS-Xcode-Source.tar.gz)
- [SHA-256 checksums](https://github.com/MaxDoubin/HomeRadar/releases/download/latest/SHA256SUMS.txt)

The desktop application binds only to `127.0.0.1`, stores data in the operating system's application-data directory, and disables port-53 DNS service by default. Use a dedicated Linux installation when other household devices need Home Radar as their DNS resolver.

The public builds are not yet commercially code-signed. Verify the checksum before bypassing an Apple Gatekeeper or Microsoft SmartScreen warning.

## Docker Compose appliance

Requirements: Linux, Docker Engine, and the Compose plugin.

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
cp .env.example .env
docker compose -f docker/docker-compose.yml up -d
```

Open `http://<appliance-ip>:8000` on the appliance itself. The first local browser securely receives the management token. A remote browser or mobile application must enter a one-time code generated from **Settings → Device pairing** on an already paired session.

The container:

- uses host networking so ARP, mDNS, SSDP, and DNS can reach the LAN;
- drops every Linux capability except `NET_RAW` and `NET_BIND_SERVICE`;
- runs with a read-only root filesystem and a temporary `/tmp`;
- persists the database, blocklists, and backups in the `homeradar-data` volume;
- leaves passive packet capture disabled by default.

Enabling passive traffic capture may require adding `NET_ADMIN`. Do not grant that capability unless the feature is intentionally enabled and understood.

## Published Docker image

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

## Native Debian service

On Debian 12 or newer:

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
sudo ./scripts/setup.sh
```

The installer builds the dashboard, creates `/opt/homeradar`, stores runtime data in `/var/lib/homeradar`, installs the systemd service and blocklist timer, and creates `/etc/homeradar/homeradar.env`.

Edit the environment file for optional email or AbuseIPDB credentials, then restart:

```bash
sudo systemctl restart homeradar
sudo systemctl status homeradar
```

## Secure first-run flow

1. Open the dashboard directly on the appliance.
2. Complete household name, DNS resolver, optional digest address, and notification settings.
3. Run discovery and review detected devices.
4. From Settings, generate a six-digit code for each remote browser or mobile device.
5. Enter the code on that device. The code expires after ten minutes and is single-use.
6. Rotate the access token from Settings if a paired device is lost or compromised.

Do not expose port 8000 directly to the public internet. Home Radar is intended for a trusted home LAN or a properly secured private VPN.

## DNS activation

Do not change router DNS until the service and one test client work correctly.

1. Confirm `http://<appliance-ip>:8000/health` reports a healthy database and service.
2. Configure one test client to use `<appliance-ip>` as its DNS server.
3. Confirm ordinary domains resolve.
4. Confirm a known test entry in the local blocklist is denied.
5. Configure the router's DHCP DNS server as `<appliance-ip>`.
6. Keep the router or provider resolver documented as the rollback setting.

Port 53 requires `NET_BIND_SERVICE`; ARP discovery requires `NET_RAW`. DNS filtering still works when optional passive traffic capture is disabled.

## Health, retention, and backups

`GET /health` remains public so container and systemd health checks can operate. Inventory, alerts, settings, traffic, backups, and all modifying endpoints require a paired session when accessed remotely.

Home Radar retains DNS and traffic metadata for 30 days and resolved alerts for 180 days by default. It creates one integrity-checked SQLite backup per day and retains the latest seven. Backup downloads require authentication.

## Live ISO

The live-build configuration is in `iso/`. Build on Debian with `live-build` and `rsync` installed:

```bash
cd iso
sudo ./build-iso.sh
```

The script creates Debian Bookworm hybrid images for amd64 and i386. These images still require physical boot, networking, graphics, and DNS testing on target hardware before they should be published as supported downloads.

## Safety and privacy

- Home Radar stores network metadata locally in SQLite.
- AbuseIPDB is optional and sends only public destination IP addresses to that provider.
- Blocking a device affects DNS requests handled by Home Radar; it is not a router firewall rule and cannot block hard-coded IP traffic.
- Passive visibility depends on topology. Normal switches may hide unicast traffic unless a mirror port is configured.
- Remote management requires a pairing token, including WebSocket snapshots and database backups.
- Cross-origin browser access is disabled unless the operator explicitly configures trusted origins.
