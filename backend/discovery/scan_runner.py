"""Orchestrates one discovery pass: ARP-scan the LAN, fingerprint each host,
persist it, and raise an alert the first time a device is seen."""
from __future__ import annotations

import logging

from backend.db import models
from backend.discovery.arp_scanner import scan as arp_scan
from backend.discovery.device_fingerprint import fingerprint_device

logger = logging.getLogger("homesentry.scan_runner")


def run_discovery_scan(conn) -> list[dict]:
    """Perform one full discovery pass and return the fingerprinted devices found."""
    hosts = arp_scan()
    logger.info("ARP scan found %d host(s)", len(hosts))

    results = []
    for host in hosts:
        info = fingerprint_device(host["ip"], host["mac"])
        existing = conn.execute("SELECT id FROM devices WHERE mac = ?", (info["mac"],)).fetchone()
        is_new = existing is None

        device_id = models.upsert_device(
            conn,
            mac=info["mac"],
            ip=info["ip"],
            hostname=info["hostname"],
            vendor=info["vendor"],
            device_type=info["device_type"],
            open_ports=info["open_ports"],
        )
        info["id"] = device_id
        results.append(info)

        if is_new:
            models.create_alert(
                conn,
                device_id=device_id,
                severity="warning",
                title="New device connected",
                description=f"Unrecognized device joined the network: {info['mac']} ({info['ip']})",
            )

    return results
