"""Privilege-free active LAN discovery.

Home Radar primes the operating system's neighbor cache with ordinary UDP
traffic and then reads the cache through the platform tools in
``neighbor_scanner``. This works without root, raw sockets, or packet-capture
permissions on Linux, macOS, and Windows hosts.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from backend.discovery.neighbor_scanner import scan as neighbor_scan

logger = logging.getLogger("homeradar.active_scanner")


def detect_local_subnet() -> str | None:
    """Detect the primary IPv4 subnet, preserving the interface prefix on Linux."""
    try:
        completed = subprocess.run(
            ("ip", "-o", "-4", "addr", "show", "scope", "global"),
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if completed.returncode == 0:
            candidates = re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", completed.stdout)
            if candidates:
                return str(ipaddress.ip_interface(candidates[0]).network)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    # UDP connect performs only a routing-table lookup; it does not send data.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect(("192.0.2.1", 9))
            local_ip = route_socket.getsockname()[0]
        if ipaddress.ip_address(local_ip).is_loopback:
            return None
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except OSError:
        logger.warning("Could not auto-detect local subnet")
        return None


def _probe_host(address: str) -> None:
    """Trigger normal neighbor resolution without requiring a privileged socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.2)
            probe.sendto(b"\x00", (address, 9))
    except OSError:
        # The packet is only used to populate the neighbor table. A closed port or
        # unreachable host is expected and is not a scan failure.
        return


def scan(subnet: str | None = None, timeout: float = 1.0) -> list[dict]:
    """Actively populate and read the OS neighbor cache for an IPv4 subnet."""
    target_subnet = subnet or detect_local_subnet()
    if not target_subnet:
        return []

    try:
        network = ipaddress.ip_network(target_subnet, strict=False)
    except ValueError:
        logger.error("Invalid LAN subnet: %s", target_subnet)
        return []
    if network.version != 4:
        logger.error("Active discovery only supports IPv4 subnets")
        return []
    if network.num_addresses > 4096:
        logger.error(
            "Refusing to probe %s addresses at once; set HOMERADAR_LAN_SUBNET "
            "to a /20 or smaller network",
            network.num_addresses,
        )
        return []

    addresses = [str(address) for address in network.hosts()]
    if addresses:
        with ThreadPoolExecutor(max_workers=min(64, len(addresses))) as pool:
            list(pool.map(_probe_host, addresses))
        time.sleep(max(0.05, min(timeout, 2.0)))

    devices: dict[str, dict] = {}
    for device in neighbor_scan():
        try:
            address = ipaddress.ip_address(device["ip"])
        except (KeyError, ValueError):
            continue
        if address not in network:
            continue
        mac = str(device.get("mac", "")).upper()
        if not mac:
            continue
        devices[mac] = {
            "ip": str(address),
            "mac": mac,
            "source": "active_neighbor",
        }
    return sorted(devices.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
