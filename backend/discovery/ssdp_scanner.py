"""SSDP/UPnP discovery for routers, TVs, consoles, cameras, and IoT devices."""
from __future__ import annotations

import logging
import socket
import time
from collections import defaultdict

from backend import config

logger = logging.getLogger("homeradar.ssdp")

SSDP_ADDRESS = ("239.255.255.250", 1900)
M_SEARCH = (
    'M-SEARCH * HTTP/1.1\r\n'
    'HOST: 239.255.255.250:1900\r\n'
    'MAN: "ssdp:discover"\r\n'
    'MX: 1\r\n'
    'ST: ssdp:all\r\n'
    '\r\n'
).encode("ascii")


def parse_response(payload: bytes) -> dict[str, str]:
    """Parse a UPnP response into lower-case HTTP-style headers."""
    text = payload.decode("utf-8", "replace")
    lines = text.replace("\r\n", "\n").split("\n")
    headers: dict[str, str] = {}
    if lines and lines[0].strip():
        headers["_status"] = lines[0].strip()
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def discover(timeout: float = config.SSDP_DISCOVERY_TIMEOUT_SECONDS) -> dict[str, dict]:
    """Send an SSDP M-SEARCH and return observations keyed by IPv4 address."""
    results: dict[str, dict] = defaultdict(
        lambda: {"ssdp_types": set(), "server": None, "usn": None, "location": None}
    )
    deadline = time.monotonic() + max(0.05, timeout)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(min(0.25, max(0.05, timeout)))
        try:
            sock.sendto(M_SEARCH, SSDP_ADDRESS)
        except OSError:
            logger.warning("SSDP discovery could not send on the local network", exc_info=True)
            return {}

        while time.monotonic() < deadline:
            try:
                payload, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            headers = parse_response(payload)
            result = results[address[0]]
            if headers.get("st"):
                result["ssdp_types"].add(headers["st"])
            for key in ("server", "usn", "location"):
                if headers.get(key) and not result.get(key):
                    result[key] = headers[key][:512]

    return {
        ip: {**observation, "ssdp_types": sorted(observation["ssdp_types"])}
        for ip, observation in results.items()
    }
