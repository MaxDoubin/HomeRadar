import tempfile
from pathlib import Path

from backend.db import models
from backend.monitor.trust_scoring import household_score, recalculate_all, score_device


def test_authorized_recognized_device_scores_above_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "trust.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            device_id = models.upsert_device(
                conn,
                mac="AA:BB:CC:00:00:01",
                ip="192.168.1.10",
                hostname="office-printer",
                vendor="Brother",
                device_type="printer",
                confidence=0.9,
            )
            models.set_device_authorization(conn, device_id, 1)
            device = models.get_device(conn, device_id)
            result = score_device(conn, device)
        assert result.score == 85
        assert result.factors["household authorized"] == 15


def test_blocked_threat_activity_lowers_device_and_household_score():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "trust.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            device_id = models.upsert_device(
                conn,
                mac="AA:BB:CC:00:00:02",
                ip="192.168.1.11",
                hostname=None,
                vendor=None,
            )
            models.log_traffic(
                conn,
                device_id=device_id,
                domain="bad.example",
                was_blocked=True,
                threat_level="critical",
            )
            recalculate_all(conn)
            device = models.get_device(conn, device_id)
            household = household_score(conn)
        assert device["trust_score"] < 50
        assert household["score"] <= device["trust_score"]
