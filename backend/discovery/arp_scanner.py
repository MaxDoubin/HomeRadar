"""ARP-based LAN device discovery.

Broadcasts an ARP "who-has" request across the local subnet and collects
who-is-at replies. Requires raw socket access (root, or CAP_NET_RAW on the
Python interpreter) because it crafts Ethernet/ARP frames directly.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess

logger = logging.getLogger("homeradar.arp_scanner")


def detect_local_subnet() -> str | None:
    """Detect the primary IPv4 subnet, preserving the interface's real prefix."""
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

    # Portable fallback when `iproute2` is unavailable.
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except OSError:
        logger.warning("Could not auto-detect local subnet")
        return None


def scan(subnet: str | None = None, timeout: float = 3.0) -> list[dict]:
    """Send an ARP broadcast over `subnet` and return [{"ip": ..., "mac": ...}, ...].

    `subnet` is CIDR notation, e.g. "192.168.1.0/24". If None, it is
    auto-detected from the default network interface.
    """
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        logger.error("scapy is not installed; ARP scanning is unavailable")
        return []

    target_subnet = subnet or detect_local_subnet()
    if not target_subnet:
        return []

    try:
        network = ipaddress.ip_network(target_subnet, strict=False)
    except ValueError:
        logger.error("Invalid LAN subnet: %s", target_subnet)
        return []
    if network.version != 4:
        logger.error("ARP discovery only supports IPv4 subnets")
        return []
    if network.num_addresses > 4096:
        logger.error(
            "Refusing to ARP-scan %s addresses at once; set HOMERADAR_LAN_SUBNET "
            "to a /20 or smaller network",
            network.num_addresses,
        )
        return []

    arp_request = ARP(pdst=str(network))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except PermissionError:
        logger.error("ARP scan requires root/CAP_NET_RAW privileges; using neighbor cache fallback")
        return []
    except OSError:
        logger.exception("ARP scan failed")
        return []

    devices = {}
    for _sent, received in answered:
        mac = received.hwsrc.upper()
        devices[mac] = {"ip": received.psrc, "mac": mac, "source": "arp"}
    return sorted(devices.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
