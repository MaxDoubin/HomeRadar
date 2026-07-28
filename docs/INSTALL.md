# Install Home Radar

Home Radar is designed for a dedicated Linux laptop connected by Ethernet (or Wi-Fi, provided your network does not enforce AP/client isolation). Do not change
your router's DNS settings until the dashboard and proxy are healthy.

If you are setting this up on an old laptop, you might want to start with our beginner-friendly guide:
[Repurposing an Old Laptop with Home Radar](OLD_LAPTOP_GUIDE.md).

## Docker Compose

Requirements: Linux, Docker Engine, and the Compose plugin.

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build -d
```

Open `http://<appliance-ip>:8000`. The container uses host networking and the minimum
network capabilities needed for discovery and DNS. Runtime data is kept in the named
`homeradar-data` volume.

The first-run wizard collects the household name, optional digest address, upstream DNS,
and browser-notification preference. It deliberately does not change the router. Follow
the staged DNS activation checklist after setup.

## Native Debian service

On Debian 12 or newer:

```bash
git clone https://github.com/MaxDoubin/HomeRadar.git
cd HomeRadar
sudo ./scripts/setup.sh
```

The installer builds the dashboard, creates `/opt/homeradar`, stores runtime data in
`/var/lib/homeradar`, installs the systemd service and daily blocklist timer, and creates
`/etc/homeradar/homeradar.env`. Edit that file for email or AbuseIPDB credentials, then
run `sudo systemctl restart homeradar`.

## DNS activation

1. Confirm `http://<appliance-ip>:8000/status` reports a healthy service.
2. Use a single test client with `<appliance-ip>` as its DNS server.
3. Verify allowed domains resolve and a known test entry in the local blocklist is denied.
4. Configure the router's DHCP DNS server as `<appliance-ip>`.
5. Keep the router/provider resolver documented as the rollback setting.

Port 53 requires root or `CAP_NET_BIND_SERVICE`. ARP and passive capture require
`CAP_NET_RAW`; capture may require `NET_ADMIN`. DNS still works if passive capture is
disabled.

## Health, retention, and backups

`GET /health` reports SQLite integrity, disk capacity, DNS configuration, blocklist
freshness, backup count, and warnings. Home Radar retains DNS/traffic metadata for 30
days and resolved alerts for 180 days by default; both windows are configurable.

The appliance creates one integrity-checked SQLite backup per day and keeps the latest
seven. Create, list, and download backups from Settings or the `/backups` API. Backups
share the persistent `/data` volume in Docker and `/var/lib/homeradar/backups` natively.

## Live ISO

The reproducible ISO build configuration is in `iso/`. Build on Debian with `live-build`
and `rsync` installed:

```bash
cd iso
sudo ./build-iso.sh
```

This produces a Debian Bookworm hybrid ISO containing Home Radar, the dashboard, systemd
services, and a Chromium kiosk session. The image still requires physical boot testing
across target machines before public release.

## Safety and privacy

- Home Radar stores metadata locally in SQLite; it does not upload household DNS history.
- AbuseIPDB is optional. Enabling it sends public destination IPs to that provider.
- Blocking a device applies to DNS requests handled by Home Radar. It is not a firewall
  rule on the router and cannot stop hard-coded IP traffic.
- Passive visibility depends on network topology. A normal switched LAN may not expose
  every device's unicast packets unless the switch mirrors traffic; DNS attribution still
  works when clients use Home Radar as their resolver.
