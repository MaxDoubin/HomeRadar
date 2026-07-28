"""Cached IP/domain reputation checks with an optional AbuseIPDB provider."""
from __future__ import annotations

import ipaddress
import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend import config

logger = logging.getLogger("homeradar.threat_intel")
_ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


@dataclass(frozen=True)
class Reputation:
    indicator: str
    indicator_type: str
    malicious: bool
    confidence: int
    source: str
    detail: str = ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )
    except ValueError:
        return False


def _cached(conn, indicator: str, indicator_type: str, source: str) -> Reputation | None:
    row = conn.execute(
        """SELECT * FROM threat_cache
           WHERE indicator = ? AND indicator_type = ? AND source = ?
             AND julianday(expires_at) > julianday(?)""",
        (indicator, indicator_type, source, _now().isoformat()),
    ).fetchone()
    if not row:
        return None
    return Reputation(
        indicator,
        indicator_type,
        bool(row["is_malicious"]),
        row["confidence"],
        source,
        row["detail"] or "",
    )


def _store(conn, reputation: Reputation) -> None:
    now = _now()
    expires = now + timedelta(hours=config.THREAT_CACHE_HOURS)
    conn.execute(
        """INSERT INTO threat_cache (
               indicator, indicator_type, is_malicious, confidence, source,
               detail, expires_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(indicator, indicator_type, source) DO UPDATE SET
               is_malicious = excluded.is_malicious,
               confidence = excluded.confidence,
               detail = excluded.detail,
               expires_at = excluded.expires_at,
               updated_at = excluded.updated_at""",
        (
            reputation.indicator,
            reputation.indicator_type,
            int(reputation.malicious),
            reputation.confidence,
            reputation.source,
            reputation.detail,
            expires.isoformat(),
            now.isoformat(),
        ),
    )


def _abuseipdb_url(ip: str) -> str:
    endpoint = urllib.parse.urlsplit(_ABUSEIPDB_ENDPOINT)
    if endpoint.scheme != "https" or endpoint.hostname != "api.abuseipdb.com":
        raise RuntimeError("invalid AbuseIPDB endpoint configuration")
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
    return f"{_ABUSEIPDB_ENDPOINT}?{query}"


def check_ip(conn, ip: str) -> Reputation:
    """Check a public IP. Without an API key, return a transparent neutral result."""
    if not _is_public_ip(ip):
        return Reputation(ip, "ip", False, 0, "local", "private or non-routable address")
    source = "abuseipdb"
    cached = _cached(conn, ip, "ip", source)
    if cached:
        return cached
    if not config.ABUSEIPDB_API_KEY:
        return Reputation(ip, "ip", False, 0, source, "API key not configured")

    request = urllib.request.Request(
        _abuseipdb_url(ip),
        headers={
            "Accept": "application/json",
            "Key": config.ABUSEIPDB_API_KEY,
            "User-Agent": "HomeRadar/0.3",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # nosec B310: fixed HTTPS host
            data = json.load(response)["data"]
        confidence = int(data.get("abuseConfidenceScore", 0))
        detail = (
            f"{data.get('totalReports', 0)} reports; "
            f"country={data.get('countryCode') or 'unknown'}; "
            f"usage={data.get('usageType') or 'unknown'}"
        )
        result = Reputation(
            ip,
            "ip",
            confidence >= config.ABUSEIPDB_MIN_CONFIDENCE,
            confidence,
            source,
            detail,
        )
        _store(conn, result)
        return result
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return Reputation(ip, "ip", False, 0, source, f"lookup failed: {exc}")


def cache_feed_indicators(
    conn,
    indicators: set[str],
    *,
    indicator_type: str,
    source: str,
    confidence: int = 100,
    detail: str = "community threat feed",
) -> int:
    """Import known-bad indicators from a curated local or downloaded feed."""
    for indicator in indicators:
        _store(
            conn,
            Reputation(indicator, indicator_type, True, confidence, source, detail),
        )
    return len(indicators)
