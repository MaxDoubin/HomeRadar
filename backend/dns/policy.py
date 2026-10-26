"""Per-device DNS internet policy with custom domains and quiet-hour schedules."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, time, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from backend.dns.blocklists import normalize_domain

logger = logging.getLogger("homeradar.policy")


@dataclass(frozen=True)
class PolicyDecision:
    blocked: bool
    reason: str | None = None


def _domain_matches(domain: str, entries: list[str]) -> bool:
    normalized = normalize_domain(domain)
    if not normalized:
        return False
    labels = normalized.split(".")
    parents = {".".join(labels[index:]) for index in range(len(labels) - 1)}
    return any(normalize_domain(entry) in parents for entry in entries)


def _parse_time(value: str | None) -> time | None:
    if not value:
        return None
    try:
        return time.fromisoformat(value)
    except ValueError:
        return None


def is_valid_clock(value: str | None) -> bool:
    """True for a real wall-clock time such as "21:00" or "07:30:00"."""
    return _parse_time(value) is not None


def schedule_window(policy: dict | None) -> tuple[time, time] | None:
    """Return a policy's (start, end) quiet hours, or None if it has none.

    Equal start and end times describe an empty window rather than a 24-hour
    one; pausing a device all day is what ``internet_enabled = false`` is for.
    """
    if not policy:
        return None
    start = _parse_time(policy.get("block_start"))
    end = _parse_time(policy.get("block_end"))
    if start is None or end is None or start == end:
        return None
    return start, end


def in_window(start: time, end: time, current: time) -> bool:
    """True when ``current`` falls in [start, end), wrapping past midnight."""
    if start < end:
        return start <= current < end
    return current >= start or current < end


def resolve_timezone(name: str | None) -> tzinfo | None:
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        logger.warning("Unknown household timezone %r; using the system clock", name)
        return None


def household_now(timezone_name: str | None = None) -> datetime:
    """Current time in the household's timezone.

    Quiet hours are wall-clock times ("21:00"), so they must be read in the
    family's timezone. A container's system clock is often UTC, so an explicit
    household setting (or HOMERADAR_TIMEZONE) wins over the system timezone.
    """
    zone = timezone_for(timezone_name)[0]
    return datetime.now(zone) if zone else datetime.now().astimezone()


def timezone_for(timezone_name: str | None = None) -> tuple[tzinfo | None, str, str]:
    """Resolve ``(zone, name, source)``: household setting, then
    HOMERADAR_TIMEZONE, then TZ, then the system clock.

    TZ is resolved through zoneinfo (backed by the bundled tzdata package)
    rather than trusted to libc, because slim container images often lack the
    system zone files and would silently fall back to UTC.
    """
    candidates = (
        (timezone_name, "household"),
        (os.environ.get("HOMERADAR_TIMEZONE"), "environment"),
        (os.environ.get("TZ"), "environment"),
    )
    for name, source in candidates:
        zone = resolve_timezone(name) if name else None
        if zone is not None:
            return zone, str(name), source
    return None, str(datetime.now().astimezone().tzname()), "system"


def next_schedule_change(start: time, end: time, now: datetime) -> datetime:
    """When the quiet-hours window next opens or closes, in ``now``'s timezone."""
    active = in_window(start, end, now.time().replace(tzinfo=None))
    boundary = end if active else start
    candidate = now.replace(
        hour=boundary.hour, minute=boundary.minute, second=boundary.second, microsecond=0
    )
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def evaluate_policy(policy: dict | None, domain: str, now: datetime | None = None) -> PolicyDecision:
    if not policy:
        return PolicyDecision(False)
    if not policy.get("internet_enabled", True):
        return PolicyDecision(True, "internet paused for device")
    if _domain_matches(domain, policy.get("allowed_domains", [])):
        return PolicyDecision(False)
    if _domain_matches(domain, policy.get("blocked_domains", [])):
        return PolicyDecision(True, "custom device domain rule")

    window = schedule_window(policy)
    if window:
        start, end = window
        current = (now or household_now()).time().replace(tzinfo=None)
        if in_window(start, end, current):
            return PolicyDecision(True, f"scheduled pause {start.isoformat()}-{end.isoformat()}")
    return PolicyDecision(False)
