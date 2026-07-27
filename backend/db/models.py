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
        default = {} if field == "fingerprint" else []
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


def list_alerts(conn, unresolved_only: bool = False) -> list[dict]:
    query = "SELECT * FROM alerts"
    if unresolved_only:
        query += " WHERE is_resolved = 0"
    query += " ORDER BY created_at DESC"
    return [dict(row) for row in conn.execute(query).fetchall()]
