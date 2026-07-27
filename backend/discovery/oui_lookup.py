"""MAC OUI (Organizationally Unique Identifier) vendor lookup.

Tries the `mac-vendor-lookup` package's bundled IEEE database first (works
fully offline once its local cache is present). Falls back to a small
built-in table of common consumer-device vendors so HomeSentry still
labels the obvious cases (phones, smart-home hubs, etc.) with zero
dependencies and zero network calls.
"""
from __future__ import annotations

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


def lookup_vendor(mac: str) -> str | None:
    """Best-effort vendor name for a MAC address, or None if unknown."""
    backend = _get_backend()
    if backend:
        try:
            return backend.lookup(mac)
        except Exception:
            pass  # fall through to the offline table

    prefix = mac.upper().replace("-", ":")[:8]
    return _FALLBACK_OUI.get(prefix)
