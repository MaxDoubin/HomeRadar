# Contributing to Home Radar

Home Radar is open source (MIT) and built in public as part of the Congressional App
Challenge 2026. Contributions, bug reports, and ideas are welcome.

## Development setup

```bash
git clone https://github.com/maxdoubin/homeradar.git
cd homeradar

python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
.venv/bin/python -m pytest tests/          # run the backend test suite
sudo .venv/bin/python -m backend.main      # run the API (root/CAP_NET_RAW needed for ARP scans)
```

`backend/requirements-dev.txt` pulls in `backend/requirements.txt` plus pytest and
the other test-only dependencies; `pip install -r backend/requirements.txt` alone is
not enough to run the test suite.

```bash
cd frontend
npm ci
npm test          # Vitest unit/integration tests
npm run dev       # dashboard at http://localhost:5173
```

`npm run dev` does not proxy API calls to the backend. Either set
`VITE_API_ROOT=http://localhost:8000` (and `VITE_WS_ROOT=ws://localhost:8000`) as env
vars before running `npm run dev`, and add `http://localhost:5173` to
`HOMERADAR_CORS_ORIGINS` when starting the backend, or just run `npm run build` and let
the backend serve the built dashboard from the same origin (its default behavior).

## Ground rules

- Keep the MVP feature list (see `docs/PROJECT_PLAN.md`) as the source of truth for scope
  - stretch features live under "2.0" until the MVP milestones are done.
- Home Radar must never require the family to put it inline (no bridging/routing). Any
  change to network positioning needs a clear failure-mode story if the change breaks.
- New discovery/monitoring code should degrade gracefully without root privileges or a
  live LAN (tests run in CI without either).
- Add or update tests under `tests/` for any change to `backend/discovery` or
  `backend/db`.
- Before pushing, run what CI runs: `python -m pytest tests/`, `npm test` and
  `npm run build` in `frontend/`, and `npx eslint .` for JavaScript changes. The
  `deep-audit.yml` workflow additionally runs Ruff, Mypy, Bandit, `pip-audit`/
  `npm audit`, CodeQL, and shell/Dockerfile/secret scanning on every pull request.

## Reporting issues

Open a GitHub issue with steps to reproduce, your OS/hardware, and relevant logs. For
security-relevant findings (e.g. a way to bypass the DNS proxy or spoof a trusted
device), please open an issue and flag it clearly as security-related.
