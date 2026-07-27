import tempfile
from pathlib import Path

from backend.db import models
from backend.monitor.anomaly_detection import observe_metric


def test_online_baseline_flags_large_positive_deviation():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "anomaly.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            device_id = models.upsert_device(
                conn,
                mac="AA:BB:CC:00:00:03",
                ip="192.168.1.12",
                hostname=None,
                vendor=None,
            )
            for value in (9, 10, 11, 10, 9, 10):
                assert observe_metric(conn, device_id, "queries", value) is None
            anomaly = observe_metric(conn, device_id, "queries", 100)
        assert anomaly is not None
        assert anomaly.z_score > 3
