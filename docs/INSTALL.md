# Install

Home Radar is in Phase 1 of development — the bootable ISO (Phase 5) doesn't exist yet.
For now, run it directly on any Linux machine or via Docker.

## Option A: Docker (recommended for now)

```bash
git clone https://github.com/maxdoubin/homeradar.git
cd homeradar
docker compose -f docker/docker-compose.yml up --build
```

The dashboard/API will be reachable at `http://<machine-ip>:8000`.

## Option B: Run from source

```bash
git clone https://github.com/maxdoubin/homeradar.git
cd homeradar/backend
pip install -r requirements.txt
sudo python3 main.py
```

`sudo` (or `CAP_NET_RAW` on the Python binary) is required because ARP scanning crafts
raw Ethernet frames.

## Coming in later phases

- Bootable USB ISO (Debian-minimal, Phase 5) — flash and boot, no OS install needed
- First-run setup wizard in the dashboard
- Kiosk status display for the appliance's own screen
