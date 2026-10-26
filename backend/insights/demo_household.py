"""Seed clearly-labeled simulated household activity for demonstrations.

Demo mode only. Adds a smart TV, a kid's tablet, and (if the inventory has none) a router, with 24 hours of DNS
lookups (including real, well-known tracking hosts from insights.trackers),
puts the tablet on a 9 PM to 7 AM bedtime, and, only when the CISA catalog has
never been downloaded, stores a verbatim excerpt of it. Every simulated DNS row
carries the same ``threat_reason`` marker so re-seeding replaces it instead of
duplicating it.
"""
from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend.db import models
from backend.insights.kev_sample import KEV_SAMPLE
from backend.insights.trackers import match_tracker

DEMO_MARKER = "Simulated household activity"

# (domain, relative weight, blocked by Home Radar's blocklists)
_TV_DOMAINS = (
    ("log-ingestion.samsungacr.com", 26, False),
    ("acr-us.samsungacr.com", 14, False),
    ("config.samsungads.com", 10, True),
    ("ad.samsungadhub.com", 8, True),
    ("googleads.g.doubleclick.net", 9, True),
    ("ssl.google-analytics.com", 6, True),
    ("ichnaea.netflix.com", 7, False),
    ("www.netflix.com", 30, False),
    ("nflxvideo.net", 34, False),
    ("www.youtube.com", 24, False),
    ("googlevideo.com", 28, False),
    ("www.hulu.com", 9, False),
)
_TABLET_DOMAINS = (
    ("app-measurement.com", 20, False),
    ("googleads.g.doubleclick.net", 14, True),
    ("d.applovin.com", 12, True),
    ("config.unityads.unity3d.com", 10, True),
    ("t.appsflyer.com", 8, False),
    ("analytics.tiktok.com", 6, True),
    ("firebase-settings.crashlytics.com", 7, False),
    ("device-metrics-us.amazon.com", 9, False),
    ("aax.amazon-adsystem.com", 8, True),
    ("www.roblox.com", 30, False),
    ("www.youtube.com", 26, False),
    ("www.khanacademy.org", 18, False),
    ("www.minecraft.net", 14, False),
)

@dataclass(frozen=True)
class _DemoDevice:
    key: str
    mac: str
    hostname: str
    vendor: str
    device_type: str
    last_octet: int
    domains: tuple[tuple[str, int, bool], ...]
    queries: int


# Vendor names are the IEEE registry entries for each MAC prefix.
_DEVICES = (
    _DemoDevice(
        "tv", "8C:79:F5:5E:71:20", "Living room TV", "Samsung Electronics Co.,Ltd", "smart_tv",
        60, _TV_DOMAINS, 320,
    ),
    _DemoDevice(
        "tablet", "FC:A1:83:2B:9C:41", "Kids' tablet", "Amazon Technologies Inc.", "tablet",
        61, _TABLET_DOMAINS, 420,
    ),
)
_ROUTER = {"mac": "A0:40:A0:4C:21:01", "hostname": "Wi-Fi router", "vendor": "NETGEAR"}


def _household_network(conn) -> ipaddress.IPv4Network:
    for row in conn.execute("SELECT ip FROM devices WHERE ip IS NOT NULL ORDER BY last_seen DESC"):
        try:
            network = ipaddress.ip_network(f"{row['ip']}/24", strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and network.is_private:
            return network
    return ipaddress.IPv4Network("192.168.1.0/24")


def _seed_queries(conn, device_id: int, domains, total: int, rng: random.Random) -> tuple[int, int]:
    conn.execute(
        "DELETE FROM traffic_logs WHERE device_id = ? AND threat_reason = ?",
        (device_id, DEMO_MARKER),
    )
    names = [domain for domain, _, _ in domains]
    weights = [weight for _, weight, _ in domains]
    blocked = {domain for domain, _, is_blocked in domains if is_blocked}
    now = datetime.now(timezone.utc)
    rows = []
    trackers = 0
    for _ in range(total):
        domain = rng.choices(names, weights=weights)[0]
        is_blocked = domain in blocked
        trackers += bool(match_tracker(domain))
        created = now - timedelta(minutes=rng.uniform(1, 24 * 60 - 1))
        rows.append(
            (
                device_id, domain, rng.randint(60, 90), 0 if is_blocked else rng.randint(90, 400),
                int(is_blocked), "warning" if is_blocked else "none", DEMO_MARKER, "A",
                created.isoformat(),
            )
        )
    conn.executemany(
        """INSERT INTO traffic_logs (
               device_id, domain, bytes_sent, bytes_received, was_blocked,
               threat_level, threat_reason, query_type, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    return total, trackers


def _seed_kev_sample(conn) -> int:
    if conn.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0]:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        """INSERT OR IGNORE INTO cisa_kev (
               cve_id, vendor_project, product, vulnerability_name, date_added,
               due_date, ransomware_use, required_action, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                item["cve_id"], item["vendor_project"], item["product"],
                item["vulnerability_name"], item["date_added"], item["due_date"],
                item["ransomware_use"], item["required_action"], now,
            )
            for item in KEV_SAMPLE
        ],
    )
    models.set_settings(conn, {"cisa_kev_demo_sample": "true"})
    return len(KEV_SAMPLE)


def _seed_router(conn, network: ipaddress.IPv4Network) -> dict | None:
    """Add a router only when the inventory has none, so the vulnerability
    check has the household's most important device to look at."""
    if conn.execute("SELECT 1 FROM devices WHERE device_type = 'router' LIMIT 1").fetchone():
        return None
    taken = {row["ip"] for row in conn.execute("SELECT ip FROM devices").fetchall()}
    gateway = str(network.network_address + 1)
    ip = gateway if gateway not in taken else str(network.network_address + 254)
    device_id = models.upsert_device(
        conn,
        mac=_ROUTER["mac"],
        ip=ip,
        hostname=_ROUTER["hostname"],
        vendor=_ROUTER["vendor"],
        device_type="router",
        confidence=0.9,
        discovery_sources=["demo"],
        fingerprint={"simulated": True, "evidence": ["Simulated demonstration device"]},
    )
    models.set_device_authorization(conn, device_id, 1)
    return {"device_id": device_id, "name": _ROUTER["hostname"], "key": "router"}


def seed_household_activity(conn, seed: int | None = None) -> dict:
    rng = random.Random(seed)  # nosec B311: demo data, not security-sensitive
    network = _household_network(conn)
    seeded: list[dict] = []
    dns_total = tracker_total = 0
    for spec in _DEVICES:
        ip = str(network.network_address + spec.last_octet)
        device_id = models.upsert_device(
            conn,
            mac=spec.mac,
            ip=ip,
            hostname=spec.hostname,
            vendor=spec.vendor,
            device_type=spec.device_type,
            confidence=0.9,
            discovery_sources=["demo"],
            fingerprint={"simulated": True, "evidence": ["Simulated demonstration device"]},
        )
        models.set_device_authorization(conn, device_id, 1)
        queries, trackers = _seed_queries(conn, device_id, spec.domains, spec.queries, rng)
        dns_total += queries
        tracker_total += trackers
        seeded.append({"device_id": device_id, "name": spec.hostname, "key": spec.key})

    router = _seed_router(conn, network)
    if router:
        seeded.append(router)

    tablet_id: int = next(item["device_id"] for item in seeded if item["key"] == "tablet")
    current = models.get_device_policy(conn, tablet_id)
    models.set_device_policy(
        conn,
        tablet_id,
        internet_enabled=True,
        block_start="21:00",
        block_end="07:00",
        blocked_domains=current.get("blocked_domains") or [],
        allowed_domains=current.get("allowed_domains") or [],
    )
    return {
        "simulated": True,
        "devices": [{"device_id": item["device_id"], "name": item["name"]} for item in seeded],
        "dns_queries": dns_total,
        "tracker_requests": tracker_total,
        "bedtime": {"device_id": tablet_id, "block_start": "21:00", "block_end": "07:00"},
        "kev_sample_added": _seed_kev_sample(conn),
        "note": "All data added here is simulated for demonstration.",
    }
