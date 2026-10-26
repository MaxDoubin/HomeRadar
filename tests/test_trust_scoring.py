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
        assert result.score == 95
        assert result.factors["household authorized"] == 15
        assert result.factors["clean recent activity"] == 10


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


def test_blocked_tracker_lookups_do_not_lower_security_trust():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "trust.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            tv = models.upsert_device(conn, mac="AA:BB:CC:00:00:03", ip="192.168.1.12", hostname=None, vendor=None)
            other = models.upsert_device(conn, mac="AA:BB:CC:00:00:04", ip="192.168.1.13", hostname=None, vendor=None)
            for _ in range(10):
                models.log_traffic(conn, device_id=tv, domain="ads.doubleclick.net", was_blocked=True)
                models.log_traffic(conn, device_id=other, domain="phish.example", was_blocked=True)
            tv_result = score_device(conn, models.get_device(conn, tv))
            other_result = score_device(conn, models.get_device(conn, other))
        assert "blocked requests" not in tv_result.factors
        assert other_result.factors["blocked requests"] == -25


def test_tracker_lookups_flagged_as_warnings_are_not_threat_matches():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "trust.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            tv = models.upsert_device(conn, mac="AA:BB:CC:00:00:05", ip="192.168.1.14", hostname=None, vendor=None)
            models.set_device_authorization(conn, tv, 1)
            for _ in range(10):
                models.log_traffic(
                    conn, device_id=tv, domain="ads.doubleclick.net", was_blocked=True, threat_level="warning"
                )
            result = score_device(conn, models.get_device(conn, tv))
        assert "threat-intel matches" not in result.factors
        assert result.factors["clean recent activity"] == 10


def test_clean_bonus_requires_authorized_device_with_no_threats():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "trust.db")
        models.init_db(db_path)
        with models.get_conn(db_path) as conn:
            pending = models.upsert_device(conn, mac="AA:BB:CC:00:00:06", ip="192.168.1.15", hostname=None, vendor=None)
            risky = models.upsert_device(conn, mac="AA:BB:CC:00:00:07", ip="192.168.1.16", hostname=None, vendor=None)
            models.set_device_authorization(conn, risky, 1)
            models.log_traffic(conn, device_id=risky, domain="malware.example", was_blocked=True, threat_level="critical")
            pending_result = score_device(conn, models.get_device(conn, pending))
            risky_result = score_device(conn, models.get_device(conn, risky))
        assert "clean recent activity" not in pending_result.factors
        assert "clean recent activity" not in risky_result.factors
