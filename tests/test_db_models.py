import tempfile
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
                device_type="computer", open_ports=[22, 80],
            )
            devices = models.list_devices(conn)

        assert len(devices) == 1
        assert devices[0]["id"] == device_id
        assert devices[0]["open_ports"] == [22, 80]


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
            event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.1.11"
        assert event_count == 1
