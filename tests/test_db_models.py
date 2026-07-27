import tempfile
import sqlite3
from pathlib import Path

from backend.db import models


def test_upsert_and_list_devices():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        models.init_db(db_path)

        with models.get_conn(db_path) as conn:
            device_id = models.upsert_device(
                conn, mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.50",
                hostname="test-host", vendor="TestVendor",
                model="Test Model", device_type="computer", confidence=0.91,
                open_ports=[22, 80], services=["_workstation._tcp.local."],
                discovery_sources=["arp", "mdns"],
                fingerprint={"evidence": ["name/model: workstation"]},
            )
            devices = models.list_devices(conn)

        assert len(devices) == 1
        assert devices[0]["id"] == device_id
        assert devices[0]["open_ports"] == [22, 80]
        assert devices[0]["services"] == ["_workstation._tcp.local."]
        assert devices[0]["discovery_sources"] == ["arp", "mdns"]
        assert devices[0]["fingerprint_confidence"] == 0.91
        assert devices[0]["model"] == "Test Model"


def test_new_device_creates_event_and_second_seen_does_not_duplicate():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        models.init_db(db_path)

        with models.get_conn(db_path) as conn:
            models.upsert_device(conn, mac="11:22:33:44:55:66", ip="192.168.1.10",
                                  hostname=None, vendor=None)
            models.upsert_device(conn, mac="11:22:33:44:55:66", ip="192.168.1.11",
                                  hostname=None, vendor=None)
            devices = models.list_devices(conn)
            events = conn.execute(
                "SELECT event_type FROM events ORDER BY id"
            ).fetchall()

        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.1.11"
        assert [event[0] for event in events] == ["new_device", "ip_changed"]


def test_unknown_rescan_preserves_known_device_type():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            device_id = models.upsert_device(
                conn, mac="AA:00:00:00:00:01", ip="192.168.1.2",
                hostname="office-printer", vendor="Brother", device_type="printer",
                confidence=0.91,
            )
            models.upsert_device(
                conn, mac="AA:00:00:00:00:01", ip="192.168.1.2",
                hostname=None, vendor=None, device_type="unknown", confidence=0.0,
            )
            device = models.get_device(conn, device_id)
        assert device["device_type"] == "printer"
        assert device["hostname"] == "office-printer"
        assert device["fingerprint_confidence"] == 0.91


def test_inventory_summary_groups_types_and_vendors():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            models.upsert_device(
                conn, mac="AA:00:00:00:00:01", ip="192.168.1.2",
                hostname=None, vendor="Brother", device_type="printer",
            )
            models.upsert_device(
                conn, mac="AA:00:00:00:00:02", ip="192.168.1.3",
                hostname=None, vendor="Brother", device_type="printer",
            )
            summary = models.inventory_summary(conn)
        assert summary["total"] == 2
        assert summary["by_type"] == {"printer": 2}
        assert summary["top_vendors"][0] == {"vendor": "Brother", "count": 2}


def test_init_db_migrates_original_phase_one_database():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "legacy.db")
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """CREATE TABLE devices (
                    id INTEGER PRIMARY KEY,
                    mac TEXT UNIQUE,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    open_ports TEXT,
                    trust_score INTEGER,
                    is_authorized INTEGER,
                    first_seen TEXT,
                    last_seen TEXT
                )"""
            )
        models.init_db(db_path)
        with sqlite3.connect(db_path) as conn:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()
            }
        assert {
            "model",
            "fingerprint_confidence",
            "services",
            "discovery_sources",
            "fingerprint",
        } <= columns
