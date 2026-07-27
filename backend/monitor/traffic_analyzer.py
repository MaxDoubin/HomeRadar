"""Record outbound connection observations and raise reputation-based alerts."""
from __future__ import annotations

import ipaddress
import logging
import threading
from collections import defaultdict

from backend import config
from backend.db import get_conn, models
from backend.monitor.threat_intel import check_ip

logger = logging.getLogger("homeradar.traffic")


def record_connection(
    conn,
    *,
    source_ip: str,
    destination_ip: str,
    bytes_sent: int = 0,
    bytes_received: int = 0,
) -> dict:
    device = models.find_device_by_ip(conn, source_ip)
    reputation = check_ip(conn, destination_ip)
    level = "critical" if reputation.malicious and reputation.confidence >= 90 else (
        "warning" if reputation.malicious else "none"
    )
    models.log_traffic(
        conn,
        device_id=device["id"] if device else None,
        dest_ip=destination_ip,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        threat_level=level,
        threat_reason=reputation.detail if reputation.malicious else None,
    )
    if reputation.malicious:
        models.create_alert_once(
            conn,
            device_id=device["id"] if device else None,
            severity=level,
            title=f"Suspicious connection: {destination_ip}",
            description=(
                f"{source_ip} contacted {destination_ip}; "
                f"{reputation.source} confidence {reputation.confidence}%."
            ),
        )
    return {
        "device_id": device["id"] if device else None,
        "destination_ip": destination_ip,
        "reputation": reputation,
        "threat_level": level,
    }


class PassiveTrafficMonitor:
    """Aggregate observed IPv4 flows before writing compact connection metadata."""

    def __init__(self, interface: str | None = config.TRAFFIC_INTERFACE):
        self.interface = interface
        self._flows: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def _packet(self, packet) -> None:
        try:
            from scapy.layers.inet import IP

            if IP not in packet:
                return
            source, destination = packet[IP].src, packet[IP].dst
            if not ipaddress.ip_address(source).is_private:
                return
            if ipaddress.ip_address(destination).is_private:
                return
            with self._lock:
                self._flows[(source, destination)][0] += len(packet)
        except (ValueError, TypeError):
            return

    def _flush(self) -> None:
        with self._lock:
            flows, self._flows = self._flows, defaultdict(lambda: [0, 0])
        if not flows:
            return
        with get_conn() as conn:
            for (source, destination), (sent, received) in flows.items():
                record_connection(
                    conn,
                    source_ip=source,
                    destination_ip=destination,
                    bytes_sent=sent,
                    bytes_received=received,
                )

    def run(self) -> None:
        try:
            from scapy.sendrecv import AsyncSniffer

            sniffer = AsyncSniffer(iface=self.interface, prn=self._packet, store=False)
            sniffer.start()
            logger.info("Passive traffic monitor started on %s", self.interface or "default interface")
            while not self._stop.wait(max(5, config.TRAFFIC_FLUSH_SECONDS)):
                self._flush()
            sniffer.stop()
            self._flush()
        except Exception:
            logger.exception("Passive traffic monitor failed")

    def stop(self) -> None:
        self._stop.set()
