"""Device classification: MAC OUI + hostname + open ports -> a human category.

This is a deliberately simple rule-based classifier for the MVP. It's meant
to get "phone / smart TV / IoT camera / laptop / unknown" right often enough
to be useful in the dashboard -- not to be a definitive identity oracle.
"""
from __future__ import annotations

import socket

from backend.discovery.oui_lookup import lookup_vendor
from backend.discovery.port_scanner import scan_ports

_CAMERA_PORTS = {554, 8000, 8080, 8443}
_PRINTER_PORTS = {9100, 631}
_MEDIA_PORTS = {8008, 8009, 32400}
_COMPUTER_PORTS = {22, 139, 445, 3389}

_VENDOR_HINTS = {
    "apple": "apple_device",
    "samsung": "smart_tv",
    "sonos": "smart_speaker",
    "nest": "smart_home",
    "philips": "smart_home",
    "amazon": "smart_speaker",
    "raspberry pi": "computer",
    "google": "smart_home",
}


def lookup_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def classify(vendor: str | None, hostname: str | None, open_ports: list[int]) -> str:
    """Best-guess device category from available signals."""
    port_set = set(open_ports)
    vendor_lower = (vendor or "").lower()
    hostname_lower = (hostname or "").lower()

    for hint, category in _VENDOR_HINTS.items():
        if hint in vendor_lower:
            return category

    if port_set & _CAMERA_PORTS or "cam" in hostname_lower:
        return "iot_camera"
    if port_set & _PRINTER_PORTS:
        return "printer"
    if port_set & _MEDIA_PORTS or "tv" in hostname_lower or "roku" in hostname_lower or "chromecast" in hostname_lower:
        return "smart_tv"
    if port_set & _COMPUTER_PORTS:
        return "computer"
    if "iphone" in hostname_lower or "android" in hostname_lower or "phone" in hostname_lower:
        return "phone"

    return "unknown"


def fingerprint_device(ip: str, mac: str) -> dict:
    """Run all available fingerprinting signals for a single discovered host."""
    vendor = lookup_vendor(mac)
    hostname = lookup_hostname(ip)
    open_ports = scan_ports(ip)
    device_type = classify(vendor, hostname, open_ports)
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "open_ports": open_ports,
        "device_type": device_type,
    }
