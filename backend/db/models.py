"""Thin SQLite data-access layer. No ORM by design -- HomeSentry's DB is meant
to stay a single portable file a family never has to think about."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from backend import config

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str = config.DB_PATH) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text())


@contextmanager
def get_conn(db_path: str = config.DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_device(conn, mac: str, ip: str, hostname: str | None, vendor: str | None,
                   device_type: str = "unknown", open_ports: list[int] | None = None) -> int:
    now = _now()
    row = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
    ports_json = json.dumps(open_ports or [])
    if row is None:
        cur = conn.execute(
            """INSERT INTO devices (mac, ip, hostname, vendor, device_type, open_ports, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (mac, ip, hostname, vendor, device_type, ports_json, now, now),
        )
        device_id = cur.lastrowid
        conn.execute(
            "INSERT INTO events (device_id, event_type, detail, created_at) VALUES (?, 'new_device', ?, ?)",
            (device_id, f"First seen at {ip}", now),
        )
        return device_id

    device_id = row["id"]
    conn.execute(
        """UPDATE devices SET ip = ?, hostname = ?, vendor = ?, device_type = ?,
           open_ports = ?, last_seen = ? WHERE id = ?""",
        (ip, hostname, vendor, device_type, ports_json, now, device_id),
    )
    return device_id


def list_devices(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    devices = []
    for row in rows:
        d = dict(row)
        d["open_ports"] = json.loads(d["open_ports"] or "[]")
        devices.append(d)
    return devices


def get_device(conn, device_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["open_ports"] = json.loads(d["open_ports"] or "[]")
    return d


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
