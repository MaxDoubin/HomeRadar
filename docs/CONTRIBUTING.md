# Contributing to Home Radar

Home Radar is open source (MIT) and built in public as part of the Congressional App
Challenge 2026. Contributions, bug reports, and ideas are welcome.

## Development setup

```bash
git clone https://github.com/maxdoubin/homeradar.git
cd homeradar/backend
pip install -r requirements.txt
python3 -m pytest ../tests/          # run the test suite
sudo python3 main.py                 # run the API (root/CAP_NET_RAW needed for ARP scans)
```

## Ground rules

- Keep the MVP feature list (see `docs/PROJECT_PLAN.md`) as the source of truth for scope
  — stretch features live under "2.0" until the MVP milestones are done.
- Home Radar must never require the family to put it inline (no bridging/routing). Any
  change to network positioning needs a clear failure-mode story if the change breaks.
- New discovery/monitoring code should degrade gracefully without root privileges or a
  live LAN (tests run in CI without either).
- Add or update tests under `tests/` for any change to `backend/discovery` or
  `backend/db`.

## Reporting issues

Open a GitHub issue with steps to reproduce, your OS/hardware, and relevant logs. For
security-relevant findings (e.g. a way to bypass the DNS proxy or spoof a trusted
device), please open an issue and flag it clearly as security-related.
