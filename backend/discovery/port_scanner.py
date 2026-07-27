"""Lightweight TCP-connect port scanner.

Deliberately avoids a system `nmap` dependency (not guaranteed present on
a family's repurposed laptop) in favor of plain sockets against a curated
list of ports common on consumer/IoT devices. Good enough for device
fingerprinting; not a substitute for a real vulnerability scanner.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from backend import config


def _is_port_open(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan_ports(ip: str, ports: list[int] | None = None,
                timeout: float = config.PORT_SCAN_TIMEOUT_SECONDS) -> list[int]:
    """Return the subset of `ports` that are open on `ip`."""
    ports = config.COMMON_PORTS if ports is None else ports
    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        results = pool.map(lambda p: (p, _is_port_open(ip, p, timeout)), ports)
    return [port for port, is_open in results if is_open]
