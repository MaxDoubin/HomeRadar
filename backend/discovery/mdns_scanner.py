"""mDNS/DNS-SD discovery for devices that advertise services on the LAN.

ARP tells us that a host exists; mDNS often tells us what it is. Browsing a
curated set of service types reveals printers, AirPlay targets, Google Cast
devices, HomeKit accessories, media servers, workstations, and smart-home hubs
without sending device-specific probes.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

from zeroconf import ServiceListener

from backend import config

logger = logging.getLogger("homeradar.mdns")

SERVICE_TYPES = (
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_smb._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_rtsp._tcp.local.",
    "_axis-video._tcp.local.",
    "_plexmediasvr._tcp.local.",
    "_amzn-wplay._tcp.local.",
    "_matter._tcp.local.",
    "_matterc._udp.local.",
    "_hue._tcp.local.",
    "_home-assistant._tcp.local.",
)


def _decode_properties(properties: dict[Any, Any] | None) -> dict[str, str]:
    decoded: dict[str, str] = {}
    for raw_key, raw_value in (properties or {}).items():
        key = raw_key.decode("utf-8", "replace") if isinstance(raw_key, bytes) else str(raw_key)
        value = raw_value.decode("utf-8", "replace") if isinstance(raw_value, bytes) else str(raw_value)
        decoded[key.lower()] = value
    return decoded


def _model_from_properties(properties: dict[str, str]) -> str | None:
    for key in ("model", "modelname", "md", "am", "ty", "product"):
        value = properties.get(key)
        if value:
            return value[:160]
    return None


class _Listener(ServiceListener):
    def __init__(self, zeroconf, results: dict[str, dict], lock: threading.Lock):
        self.zeroconf = zeroconf
        self.results = results
        self.lock = lock

    def add_service(self, zeroconf, service_type: str, name: str) -> None:
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=750)
            if info is None:
                return
            addresses = info.parsed_scoped_addresses()
            properties = _decode_properties(info.properties)
            for ip in addresses:
                if ":" in ip:  # IPv6 device correlation is not stored yet.
                    continue
                with self.lock:
                    result = self.results[ip]
                    result["mdns_services"].add(service_type)
                    result["service_names"].add(name.removesuffix(f".{service_type}"))
                    result["properties"].update(properties)
                    model = _model_from_properties(properties)
                    if model and not result.get("model"):
                        result["model"] = model
        except Exception:
            logger.debug("Could not resolve mDNS service %s", name, exc_info=True)

    def update_service(self, zeroconf, service_type: str, name: str) -> None:
        self.add_service(zeroconf, service_type, name)

    def remove_service(self, zeroconf, service_type: str, name: str) -> None:
        return


def discover(timeout: float = config.MDNS_DISCOVERY_TIMEOUT_SECONDS) -> dict[str, dict]:
    """Return mDNS observations keyed by IPv4 address."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        logger.warning("zeroconf is not installed; mDNS discovery is unavailable")
        return {}

    raw_results: dict[str, dict] = defaultdict(
        lambda: {
            "mdns_services": set(),
            "service_names": set(),
            "properties": {},
            "model": None,
        }
    )
    lock = threading.Lock()
    zeroconf = None
    browsers = []
    try:
        zeroconf = Zeroconf()
        listener = _Listener(zeroconf, raw_results, lock)
        browsers = [ServiceBrowser(zeroconf, service_type, listener) for service_type in SERVICE_TYPES]
        time.sleep(max(0.05, timeout))
    except OSError:
        logger.warning("mDNS discovery could not bind to the local network", exc_info=True)
    finally:
        for browser in browsers:
            browser.cancel()
        if zeroconf is not None:
            zeroconf.close()

    return {
        ip: {
            **observation,
            "mdns_services": sorted(observation["mdns_services"]),
            "service_names": sorted(observation["service_names"]),
        }
        for ip, observation in raw_results.items()
    }
