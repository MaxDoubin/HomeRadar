"""Household insight reports built from data Home Radar already records."""
from __future__ import annotations


def device_display_name(device: dict | None) -> str:
    """Mirror the dashboard's naming so reports and UI agree."""
    if not device:
        return "Unrecognized device"
    return device.get("hostname") or device.get("model") or device.get("vendor") or "Unknown device"
