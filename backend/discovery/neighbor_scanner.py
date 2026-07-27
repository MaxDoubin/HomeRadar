"""Read the operating system's neighbor cache as a no-root discovery fallback."""
from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger("homeradar.neighbors")

_MAC = r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
_IP_NEIGH_RE = re.compile(rf"^(?P<ip>\d+\.\d+\.\d+\.\d+).*?\blladdr\s+{_MAC}\b")
_ARP_RE = re.compile(rf"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+{_MAC}\b")


def parse_neighbor_output(output: str) -> list[dict]:
    """Parse Linux `ip neigh` or BSD/macOS `arp -an` output."""
    devices: dict[str, dict] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = _IP_NEIGH_RE.search(line) or _ARP_RE.search(line)
        if not match:
            continue
        mac = match.group("mac").upper()
        if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E"):
            continue
        devices[mac] = {"ip": match.group("ip"), "mac": mac, "source": "neighbor_cache"}
    return list(devices.values())


def scan() -> list[dict]:
    """Return devices already known to the host's ARP/neighbor cache."""
    for command in (("ip", "-4", "neigh", "show"), ("arp", "-an")):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return parse_neighbor_output(completed.stdout)
    logger.debug("No supported neighbor-cache command was available")
    return []
