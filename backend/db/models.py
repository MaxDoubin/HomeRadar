"""Thin SQLite data-access layer. No ORM by design -- Home Radar's DB is meant
to stay a single portable file a family never has to think about."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend import config

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

_DEVICE_COLUMNS = {
    "model": "TEXT",
    "fingerprint_confidence": "REAL DEFAULT 0",
    "services": "TEXT",
    "discovery_sources": "TEXT",
    "fingerprint": "TEXT",
}

_TRAFFIC_COLUMNS = {
    "threat_level": "TEXT DEFAULT 'none'",
    "threat_reason": "TEXT",
    "query_type": "TEXT",
}

_JSON_DEVICE_FIELDS = ("open_ports", "services", "discovery_sources", "fingerprint")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str = config.DB_PATH) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text())
        existing = {
            row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        for column, definition in _DEVICE_COLUMNS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")
        traffic_existing = {
            row[1] for row in conn.execute("PRAGMA table_info(traffic_logs)").fetchall()
        }
        for column, definition in _TRAFFIC_COLUMNS.items():
            if column not in traffic_existing:
                conn.execute(f"ALTER TABLE traffic_logs ADD COLUMN {column} {definition}")


@contextmanager
def get_conn(db_path: str = config.DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_device(
    conn,
    mac: str,
    ip: str,
    hostname: str | None,
    vendor: str | None,
    *,
    model: str | None = None,
    device_type: str = "unknown",
    confidence: float = 0.0,
    open_ports: list[int] | None = None,
    services: list[str] | None = None,
    discovery_sources: list[str] | None = None,
    fingerprint: dict | None = None,
) -> int:
    now = _now()
    mac = mac.upper()
    row = conn.execute(
        "SELECT id, ip, device_type FROM devices WHERE mac = ?",
        (mac,),
    ).fetchone()
    ports_json = json.dumps(open_ports or [])
    services_json = json.dumps(services or [])
    sources_json = json.dumps(discovery_sources or [])
    fingerprint_json = json.dumps(fingerprint or {})
    if row is None:
        cur = conn.execute(
            """INSERT INTO devices (
                   mac, ip, hostname, vendor, model, device_type,
                   fingerprint_confidence, open_ports, services, discovery_sources,
                   fingerprint, first_seen, last_seen
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                mac, ip, hostname, vendor, model, device_type, confidence,
                ports_json, services_json, sources_json, fingerprint_json, now, now,
            ),
        )
        device_id = cur.lastrowid
        conn.execute(
            "INSERT INTO events (device_id, event_type, detail, created_at) VALUES (?, 'new_device', ?, ?)",
            (device_id, f"First seen at {ip}", now),
        )
        return device_id

    device_id = row["id"]
    if row["ip"] and row["ip"] != ip:
        conn.execute(
            "INSERT INTO events (device_id, event_type, detail, created_at) VALUES (?, 'ip_changed', ?, ?)",
            (device_id, f"{row['ip']} -> {ip}", now),
        )
    if (
        device_type != "unknown"
        and row["device_type"] != device_type
        and row["device_type"] != "unknown"
    ):
        conn.execute(
            "INSERT INTO events (device_id, event_type, detail, created_at) VALUES (?, 'type_changed', ?, ?)",
            (device_id, f"{row['device_type']} -> {device_type}", now),
        )

    conn.execute(
        """UPDATE devices SET
               ip = ?,
               hostname = COALESCE(?, hostname),
               vendor = COALESCE(?, vendor),
               model = COALESCE(?, model),
               device_type = CASE WHEN ? = 'unknown' THEN device_type ELSE ? END,
               fingerprint_confidence = CASE
                   WHEN ? = 'unknown' THEN fingerprint_confidence ELSE ?
               END,
               open_ports = ?,
               services = ?,
               discovery_sources = ?,
               fingerprint = ?,
               last_seen = ?
           WHERE id = ?""",
        (
            ip, hostname, vendor, model, device_type, device_type,
            device_type, confidence,
            ports_json, services_json, sources_json, fingerprint_json, now, device_id,
        ),
    )
    return device_id


def _device_dict(row) -> dict:
    device = dict(row)
    for field in _JSON_DEVICE_FIELDS:
        default: dict | list = {} if field == "fingerprint" else []
        try:
            device[field] = json.loads(device.get(field) or json.dumps(default))
        except (TypeError, json.JSONDecodeError):
            device[field] = default
    return device


def list_devices(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    return [_device_dict(row) for row in rows]


def get_device(conn, device_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    return _device_dict(row)


def inventory_summary(conn) -> dict:
    """Return counts used by dashboards without loading every device."""
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    by_type = {
        row["device_type"]: row["count"]
        for row in conn.execute(
            """SELECT COALESCE(device_type, 'unknown') AS device_type, COUNT(*) AS count
               FROM devices GROUP BY COALESCE(device_type, 'unknown')
               ORDER BY count DESC"""
        ).fetchall()
    }
    by_vendor = [
        {"vendor": row["vendor"], "count": row["count"]}
        for row in conn.execute(
            """SELECT COALESCE(vendor, 'Unknown') AS vendor, COUNT(*) AS count
               FROM devices GROUP BY COALESCE(vendor, 'Unknown')
               ORDER BY count DESC, vendor LIMIT 20"""
        ).fetchall()
    ]
    return {"total": total, "by_type": by_type, "top_vendors": by_vendor}


def create_alert(conn, device_id: int | None, severity: str, title: str, description: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO alerts (device_id, severity, title, description, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (device_id, severity, title, description, _now()),
    )
    return cur.lastrowid


def create_alert_once(
    conn,
    device_id: int | None,
    severity: str,
    title: str,
    description: str = "",
    *,
    window_minutes: int = 60,
) -> int | None:
    """Create an alert unless an equivalent open alert was recently recorded."""
    existing = conn.execute(
        """SELECT id FROM alerts
           WHERE device_id IS ? AND title = ? AND is_resolved = 0
             AND julianday(created_at) >= julianday('now', ?)
           ORDER BY created_at DESC LIMIT 1""",
        (device_id, title, f"-{max(1, window_minutes)} minutes"),
    ).fetchone()
    if existing:
        return None
    return create_alert(conn, device_id, severity, title, description)


def list_alerts(conn, unresolved_only: bool = False) -> list[dict]:
    query = "SELECT * FROM alerts"
    if unresolved_only:
        query += " WHERE is_resolved = 0"
    query += " ORDER BY created_at DESC"
    return [dict(row) for row in conn.execute(query).fetchall()]


def resolve_alert(conn, alert_id: int, resolved: bool = True) -> bool:
    cur = conn.execute(
        "UPDATE alerts SET is_resolved = ? WHERE id = ?",
        (int(resolved), alert_id),
    )
    return cur.rowcount > 0


def set_device_authorization(conn, device_id: int, state: int) -> bool:
    if state not in {0, 1, 2}:
        raise ValueError("authorization state must be 0, 1, or 2")
    cur = conn.execute(
        "UPDATE devices SET is_authorized = ? WHERE id = ?",
        (state, device_id),
    )
    if cur.rowcount:
        labels = {0: "pending", 1: "authorized", 2: "blocked"}
        conn.execute(
            """INSERT INTO events (device_id, event_type, detail, created_at)
               VALUES (?, 'authorization_changed', ?, ?)""",
            (device_id, labels[state], _now()),
        )
    return cur.rowcount > 0


def find_device_by_ip(conn, ip: str) -> dict | None:
    row = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
    return _device_dict(row) if row else None


def log_traffic(
    conn,
    *,
    device_id: int | None,
    domain: str | None = None,
    dest_ip: str | None = None,
    was_blocked: bool = False,
    threat_level: str = "none",
    threat_reason: str | None = None,
    query_type: str | None = None,
    bytes_sent: int = 0,
    bytes_received: int = 0,
) -> int:
    cur = conn.execute(
        """INSERT INTO traffic_logs (
               device_id, domain, dest_ip, bytes_sent, bytes_received, was_blocked,
               threat_level, threat_reason, query_type, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            device_id, domain, dest_ip, bytes_sent, bytes_received, int(was_blocked),
            threat_level, threat_reason, query_type, _now(),
        ),
    )
    return cur.lastrowid


def list_traffic(
    conn,
    *,
    device_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    limit = max(1, min(limit, 1000))
    query = """
        SELECT traffic_logs.*, devices.hostname, devices.vendor
        FROM traffic_logs
        LEFT JOIN devices ON devices.id = traffic_logs.device_id
    """
    params: list = []
    if device_id is not None:
        query += " WHERE traffic_logs.device_id = ?"
        params.append(device_id)
    query += " ORDER BY traffic_logs.created_at DESC LIMIT ?"
    params.append(limit)
    return [dict(row) for row in conn.execute(query, params).fetchall()]


def traffic_summary(conn, hours: int = 24) -> dict:
    hours = max(1, min(hours, 24 * 30))
    modifier = f"-{hours} hours"
    totals = conn.execute(
        """SELECT COUNT(*) AS queries,
                  COALESCE(SUM(was_blocked), 0) AS blocked,
                  COALESCE(SUM(bytes_sent), 0) AS bytes_sent,
                  COALESCE(SUM(bytes_received), 0) AS bytes_received
           FROM traffic_logs WHERE julianday(created_at) >= julianday('now', ?)""",
        (modifier,),
    ).fetchone()
    top_domains = [
        dict(row) for row in conn.execute(
            """SELECT domain, COUNT(*) AS count, SUM(was_blocked) AS blocked
               FROM traffic_logs
               WHERE julianday(created_at) >= julianday('now', ?) AND domain IS NOT NULL
               GROUP BY domain ORDER BY count DESC LIMIT 12""",
            (modifier,),
        ).fetchall()
    ]
    timeline = [
        dict(row) for row in conn.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) AS bucket,
                      COUNT(*) AS queries, SUM(was_blocked) AS blocked
               FROM traffic_logs
               WHERE julianday(created_at) >= julianday('now', ?)
               GROUP BY bucket ORDER BY bucket""",
            (modifier,),
        ).fetchall()
    ]
    return {**dict(totals), "top_domains": top_domains, "timeline": timeline, "hours": hours}


def set_trust_score(conn, device_id: int, score: int, reason: str) -> None:
    score = max(0, min(100, int(score)))
    current = conn.execute(
        "SELECT trust_score FROM devices WHERE id = ?", (device_id,)
    ).fetchone()
    if current is None:
        return
    if current["trust_score"] != score:
        conn.execute(
            "UPDATE devices SET trust_score = ? WHERE id = ?",
            (score, device_id),
        )
        conn.execute(
            """INSERT INTO trust_scores (device_id, score, reason, created_at)
               VALUES (?, ?, ?, ?)""",
            (device_id, score, reason, _now()),
        )


def trust_history(conn, device_id: int, limit: int = 100) -> list[dict]:
    return [
        dict(row) for row in conn.execute(
            """SELECT * FROM trust_scores WHERE device_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (device_id, max(1, min(limit, 500))),
        ).fetchall()
    ]


def get_setting(conn, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_settings(conn, settings: dict[str, str]) -> None:
    now = _now()
    conn.executemany(
        """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value,
           updated_at = excluded.updated_at""",
        [(key, str(value), now) for key, value in settings.items()],
    )


def get_settings(conn) -> dict[str, str]:
    return {
        row["key"]: row["value"]
        for row in conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
    }


def get_device_policy(conn, device_id: int) -> dict:
    row = conn.execute(
        "SELECT * FROM device_policies WHERE device_id = ?", (device_id,)
    ).fetchone()
    if row is None:
        return {
            "device_id": device_id,
            "internet_enabled": True,
            "block_start": None,
            "block_end": None,
            "blocked_domains": [],
            "allowed_domains": [],
        }
    policy = dict(row)
    policy["internet_enabled"] = bool(policy["internet_enabled"])
    for field in ("blocked_domains", "allowed_domains"):
        try:
            policy[field] = json.loads(policy[field] or "[]")
        except json.JSONDecodeError:
            policy[field] = []
    return policy


def set_device_policy(
    conn,
    device_id: int,
    *,
    internet_enabled: bool = True,
    block_start: str | None = None,
    block_end: str | None = None,
    blocked_domains: list[str] | None = None,
    allowed_domains: list[str] | None = None,
) -> dict:
    if get_device(conn, device_id) is None:
        raise LookupError("device not found")
    conn.execute(
        """INSERT INTO device_policies (
               device_id, internet_enabled, block_start, block_end,
               blocked_domains, allowed_domains, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id) DO UPDATE SET
               internet_enabled = excluded.internet_enabled,
               block_start = excluded.block_start,
               block_end = excluded.block_end,
               blocked_domains = excluded.blocked_domains,
               allowed_domains = excluded.allowed_domains,
               updated_at = excluded.updated_at""",
        (
            device_id,
            int(internet_enabled),
            block_start,
            block_end,
            json.dumps(sorted(set(blocked_domains or []))),
            json.dumps(sorted(set(allowed_domains or []))),
            _now(),
        ),
    )
    return get_device_policy(conn, device_id)


def list_findings(
    conn,
    *,
    device_id: int | None = None,
    unresolved_only: bool = True,
) -> list[dict]:
    query = """
        SELECT exposure_findings.*, devices.hostname, devices.ip, devices.vendor
        FROM exposure_findings
        JOIN devices ON devices.id = exposure_findings.device_id
        WHERE 1 = 1
    """
    params = []
    if device_id is not None:
        query += " AND exposure_findings.device_id = ?"
        params.append(device_id)
    if unresolved_only:
        query += " AND exposure_findings.is_resolved = 0"
    query += """
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                 last_seen DESC
    """
    rows = []
    for row in conn.execute(query, params).fetchall():
        finding = dict(row)
        try:
            finding["evidence"] = json.loads(finding["evidence"] or "[]")
        except json.JSONDecodeError:
            finding["evidence"] = []
        rows.append(finding)
    return rows
