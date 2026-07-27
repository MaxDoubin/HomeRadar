"""Per-device DNS internet policy with custom domains and quiet-hour schedules."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time

from backend.dns.blocklists import normalize_domain


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


def evaluate_policy(policy: dict | None, domain: str, now: datetime | None = None) -> PolicyDecision:
    if not policy:
        return PolicyDecision(False)
    if not policy.get("internet_enabled", True):
        return PolicyDecision(True, "internet paused for device")
    if _domain_matches(domain, policy.get("allowed_domains", [])):
        return PolicyDecision(False)
    if _domain_matches(domain, policy.get("blocked_domains", [])):
        return PolicyDecision(True, "custom device domain rule")

    start = _parse_time(policy.get("block_start"))
    end = _parse_time(policy.get("block_end"))
    if start and end:
        current = (now or datetime.now().astimezone()).time().replace(tzinfo=None)
        in_window = start <= current < end if start < end else current >= start or current < end
        if in_window:
            return PolicyDecision(True, f"scheduled pause {start.isoformat()}-{end.isoformat()}")
    return PolicyDecision(False)
