"""ARP-based LAN device discovery.

Broadcasts an ARP "who-has" request across the local subnet and collects
who-is-at replies. Requires raw socket access (root, or CAP_NET_RAW on the
Python interpreter) because it crafts Ethernet/ARP frames directly.
"""
from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("homesentry.arp_scanner")


def detect_local_subnet() -> str | None:
    """Guess the local IPv4 subnet (e.g. '192.168.1.0/24') from the default route."""
    import socket
    try:
        # No packets are actually sent for a UDP socket connect; this just asks
        # the OS which local interface would be used to reach the internet.
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

    arp_request = ARP(pdst=target_subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except PermissionError:
        logger.error("ARP scan requires root/CAP_NET_RAW privileges")
        return []

    devices = []
    for _sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc.upper()})
    return devices
