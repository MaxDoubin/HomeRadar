"""Which devices have a bedtime, and when their internet turns off or back on."""
from __future__ import annotations

from datetime import datetime, time

from backend.db import models
from backend.dns.policy import (
    household_now,
    in_window,
    is_valid_clock,
    next_schedule_change,
    schedule_window,
    timezone_for,
)
from backend.insights import device_display_name


def _clock(value: time | datetime) -> str:
    hour = value.hour % 12 or 12
    return f"{hour}:{value.minute:02d} {'AM' if value.hour < 12 else 'PM'}"


def timezone_info(conn) -> tuple[str, str]:
    """Return ``(timezone name, source)`` exactly as the DNS proxy resolves it."""
    _, name, source = timezone_for(models.get_setting(conn, "household_timezone"))
    return name, source


def device_bedtime(policy: dict, device: dict, now: datetime) -> dict | None:
    """Describe one device's bedtime, or None when it has no schedule or pause."""
    paused = not policy.get("internet_enabled", True)
    window = schedule_window(policy)
    configured = policy.get("block_start") or policy.get("block_end")
    invalid = bool(configured) and not (
        is_valid_clock(policy.get("block_start")) and is_valid_clock(policy.get("block_end"))
    )
    if not paused and not window and not invalid:
        return None
    entry = {
        "device_id": device["id"],
        "name": device_display_name(device),
        "block_start": policy.get("block_start") if window else None,
        "block_end": policy.get("block_end") if window else None,
        "internet_enabled": not paused,
        "active_now": paused,
        "next_change_at": None,
        "schedule_valid": not invalid,
    }
    if paused:
        entry["summary"] = "Internet paused"
        return entry
    if invalid:
        entry["block_start"] = policy.get("block_start")
        entry["block_end"] = policy.get("block_end")
        entry["summary"] = "Bedtime isn't working: the times aren't valid"
        return entry
    if window is None:
        return None
    start, end = window
    active = in_window(start, end, now.time().replace(tzinfo=None))
    change = next_schedule_change(start, end, now)
    entry["active_now"] = active
    entry["next_change_at"] = change.isoformat()
    entry["summary"] = f"Offline until {_clock(change)}" if active else f"Goes offline at {_clock(start)}"
    return entry


def list_bedtimes(conn, now: datetime | None = None) -> dict:
    name, source = timezone_info(conn)
    now = now or household_now(models.get_setting(conn, "household_timezone"))
    rows = conn.execute(
        """SELECT devices.*, device_policies.device_id AS policy_device_id
           FROM device_policies JOIN devices ON devices.id = device_policies.device_id"""
    ).fetchall()
    entries = []
    for row in rows:
        device = dict(row)
        entry = device_bedtime(models.get_device_policy(conn, device["id"]), device, now)
        if entry:
            entries.append(entry)
    entries.sort(key=lambda item: (not item["active_now"], item["name"]))
    return {"timezone": name, "timezone_source": source, "now": now.isoformat(), "devices": entries}
