"""Apply exact, reviewable fixes that are awkward through the contents API.

This file is executed once by ``audit-codemod.yml`` and removes itself and the
one-time workflow after updating the branch.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_exact(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {relative}, found {count}")
    path.write_text(text.replace(old, new))


replace_exact(
    "backend/db/models.py",
    '        default = {} if field == "fingerprint" else []\n',
    '        default: dict | list = {} if field == "fingerprint" else []\n',
)

replace_exact(
    "backend/dns/proxy.py",
    '''        with self._inflight_lock:
            event = self._inflight.get(key)
            owner = event is None
            if owner:
                event = self._inflight[key] = threading.Event()
        if not owner:
            event.wait(config.DNS_TIMEOUT_SECONDS * max(1, len(self._upstreams())))
''',
    '''        with self._inflight_lock:
            event = self._inflight.get(key)
            if event is None:
                event = threading.Event()
                self._inflight[key] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait(config.DNS_TIMEOUT_SECONDS * max(1, len(self._upstreams())))
''',
)

replace_exact(
    "backend/discovery/mdns_scanner.py",
    "from typing import Any\n\nfrom backend import config\n",
    "from typing import Any\n\nfrom zeroconf import ServiceListener\n\nfrom backend import config\n",
)
replace_exact(
    "backend/discovery/mdns_scanner.py",
    "class _Listener:\n",
    "class _Listener(ServiceListener):\n",
)

replace_exact(
    "backend/pairing.py",
    '''    code = models.get_setting(conn, _CODE_KEY)
    expires_at = _parse_iso(models.get_setting(conn, _CODE_EXPIRES_KEY))
    valid = (
        bool(code)
        and expires_at is not None
        and _now() < expires_at
        and bool(presented_code)
        and hmac.compare_digest(presented_code, code)
    )
    if not valid:
        _register_failure(conn)
        return None
''',
    '''    code = models.get_setting(conn, _CODE_KEY)
    expires_at = _parse_iso(models.get_setting(conn, _CODE_EXPIRES_KEY))
    if not code or expires_at is None or _now() >= expires_at or not presented_code:
        _register_failure(conn)
        return None
    if not hmac.compare_digest(presented_code, code):
        _register_failure(conn)
        return None
''',
)

replace_exact(
    "backend/main.py",
    '''    dns_proxy = None
    dns_thread = None
    traffic_monitor = None
    traffic_thread = None
''',
    '''    dns_proxy: DNSProxy | None = None
    dns_thread: threading.Thread | None = None
    traffic_monitor: PassiveTrafficMonitor | None = None
    traffic_thread: threading.Thread | None = None
''',
)

replace_exact(
    ".github/workflows/desktop.yml",
    "          sha256sum * > SHA256SUMS.txt\n",
    "          sha256sum -- ./* > SHA256SUMS.txt\n",
)

replace_exact(
    ".github/workflows/deep-audit.yml",
    "        run: npm install --no-save eslint@9 @eslint/js globals\n",
    "        run: npm install --no-save eslint@9 @eslint/js globals eslint-plugin-react\n",
)

package_path = ROOT / "desktop/package.json"
package = json.loads(package_path.read_text())
package["overrides"] = {"brace-expansion": "5.0.8"}
package_path.write_text(json.dumps(package, indent=2) + "\n")

(ROOT / ".github/workflows/audit-codemod.yml").unlink()
Path(__file__).unlink()
