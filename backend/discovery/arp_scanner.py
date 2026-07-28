"""Active IPv4 LAN discovery with a privilege-free fallback.

When raw packet access is available, Home Radar sends a conventional ARP
broadcast through Scapy. On locked-down desktop systems it instead primes the
operating system neighbor cache with ordinary UDP traffic and reads the cache
through platform tools. The fallback never needs root, packet-capture access, or
special capabilities.
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

logger = logging.getLogger("homeradar.arp_scanner")


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

    # UDP connect performs a routing-table lookup without transmitting payload.
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
        # Closed ports and unreachable hosts are expected; the routing attempt is
        # enough to ask the operating system to resolve a local neighbor.
        return


def _active_neighbor_scan(network: ipaddress.IPv4Network, timeout: float) -> list[dict]:
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
        if address.version != 4 or address not in network:
            continue
        mac = str(device.get("mac", "")).upper()
        if not mac:
            continue
        devices[mac] = {
            "ip": str(address),
            "mac": mac,
            "source": "active_neighbor",
        }
    return list(devices.values())


def _raw_arp_scan(network: ipaddress.IPv4Network, timeout: float) -> list[dict]:
    try:
        from scapy.error import Scapy_Exception
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError:
        logger.info("Scapy is unavailable; using active neighbor discovery")
        return []

    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            timeout=timeout,
            verbose=False,
        )
    except (PermissionError, OSError, Scapy_Exception) as exc:
        logger.info("Raw ARP discovery unavailable (%s); using neighbor-cache fallback", exc)
        return []

    devices: dict[str, dict] = {}
    for _sent, received in answered:
        try:
            address = ipaddress.ip_address(received.psrc)
            mac = str(received.hwsrc).upper()
        except (AttributeError, ValueError):
            continue
        if address.version == 4 and address in network and mac:
            devices[mac] = {"ip": str(address), "mac": mac, "source": "arp"}
    return list(devices.values())


def scan(subnet: str | None = None, timeout: float = 1.0) -> list[dict]:
    """Discover IPv4 devices using raw ARP plus a no-root neighbor fallback."""
    target_subnet = subnet or detect_local_subnet()
    if not target_subnet:
        return []

    try:
        parsed = ipaddress.ip_network(target_subnet, strict=False)
    except ValueError:
        logger.error("Invalid LAN subnet: %s", target_subnet)
        return []
    if not isinstance(parsed, ipaddress.IPv4Network):
        logger.error("ARP discovery only supports IPv4 subnets")
        return []
    if parsed.num_addresses > 4096:
        logger.error(
            "Refusing to scan %s addresses at once; set HOMERADAR_LAN_SUBNET "
            "to a /20 or smaller network",
            parsed.num_addresses,
        )
        return []

    merged: dict[str, dict] = {}
    for device in _active_neighbor_scan(parsed, timeout):
        merged[device["mac"]] = device
    # Prefer direct ARP observations when both paths find the same device.
    for device in _raw_arp_scan(parsed, timeout):
        merged[device["mac"]] = device
    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
