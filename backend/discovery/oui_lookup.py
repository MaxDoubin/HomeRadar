"""MAC OUI (Organizationally Unique Identifier) vendor lookup.

Tries the `mac-vendor-lookup` package's bundled IEEE database first (works
fully offline once its local cache is present). Falls back to a small
built-in table of common consumer-device vendors so Home Radar still
labels the obvious cases (phones, smart-home hubs, etc.) with zero
dependencies and zero network calls.
"""
from __future__ import annotations

from functools import lru_cache
import re

_FALLBACK_OUI = {
    "F0:18:98": "Apple",
    "AC:BC:32": "Apple",
    "3C:06:30": "Apple",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "18:B4:30": "Nest Labs",
    "FC:A1:83": "Amazon",
    "44:65:0D": "Amazon",
    "68:37:E9": "Amazon",
    "A0:02:DC": "Samsung",
    "00:16:6C": "Samsung",
    "70:88:6B": "Samsung",
    "00:17:88": "Philips (Hue)",
    "EC:B5:FA": "Sonos",
    "5C:AA:FD": "Sonos",
    "B0:C5:54": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:11:32": "Synology",
    "24:0A:C4": "Espressif",
    "24:6F:28": "Espressif",
    "30:AE:A4": "Espressif",
    "84:F3:EB": "Espressif",
    "78:8A:20": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "00:14:22": "Dell",
}

_mac_lookup = None


def _get_backend():
    global _mac_lookup
    if _mac_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
        except ImportError:
            _mac_lookup = False
    return _mac_lookup


def normalize_mac(mac: str) -> str | None:
    compact = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(compact) != 12:
        return None
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).upper()


@lru_cache(maxsize=4096)
def lookup_vendor(mac: str) -> str | None:
    """Best-effort vendor name for a MAC address, or None if unknown."""
    normalized = normalize_mac(mac)
    if normalized is None:
        return None
    first_octet = int(normalized[:2], 16)
    if first_octet & 0x01:
        return None  # multicast/broadcast addresses do not identify a vendor
    if first_octet & 0x02:
        return "Private / randomized MAC"

    backend = _get_backend()
    if backend:
        try:
            return backend.lookup(normalized)
        except Exception:
            pass  # fall through to the offline table

    prefix = normalized[:8]
    return _FALLBACK_OUI.get(prefix)
