"""Read the operating system's neighbor cache as a no-root discovery fallback."""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import sys

logger = logging.getLogger("homeradar.neighbors")

# macOS `arp -an` drops leading zeros ("0:11:22:3:44:55"); Windows uses dashes.
_MAC = r"(?P<mac>(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})(?![0-9a-fA-F:-])"
_IP_NEIGH_RE = re.compile(rf"^(?P<ip>\d+\.\d+\.\d+\.\d+).*?\blladdr\s+{_MAC}")
_ARP_RE = re.compile(rf"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+{_MAC}")
_WINDOWS_ARP_RE = re.compile(rf"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+{_MAC}")

_COMMANDS: tuple[tuple[str, ...], ...]
if sys.platform == "win32":
    _COMMANDS = (("arp", "-a"),)
    # Keep the packaged desktop app from flashing a console window per scan.
    _CREATIONFLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)
else:
    _COMMANDS = (("ip", "-4", "neigh", "show"), ("arp", "-an"))
    _CREATIONFLAGS = 0


def normalize_mac(value: str) -> str:
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", value)).upper()


def _is_ignored_mac(mac: str) -> bool:
    return mac in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"} or mac.startswith("01:00:5E")


def parse_neighbor_output(output: str) -> list[dict]:
    """Parse Linux `ip neigh`, BSD/macOS `arp -an`, or Windows `arp -a` output."""
    devices: dict[str, dict] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "incomplete" in line.lower():
            continue
        match = _IP_NEIGH_RE.search(line) or _ARP_RE.search(line) or _WINDOWS_ARP_RE.search(line)
        if not match:
            continue
        mac = normalize_mac(match.group("mac"))
        if _is_ignored_mac(mac):
            continue
        ip = match.group("ip")
        if ipaddress.ip_address(ip).is_multicast:
            continue
        devices[mac] = {"ip": ip, "mac": mac, "source": "neighbor_cache"}
    return list(devices.values())


def scan() -> list[dict]:
    """Return devices already known to the host's ARP/neighbor cache."""
    for command in _COMMANDS:
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
                creationflags=_CREATIONFLAGS,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return parse_neighbor_output(completed.stdout)
    logger.debug("No supported neighbor-cache command was available")
    return []
