import os
import sqlite3
import tempfile
import time
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import config
from backend.db import models
from backend.maintenance import (
    backup_if_due,
    backup_path,
    cleanup_database,
    create_backup,
    health_report,
    list_backups,
    prune_backups,
)

_DiskUsage = namedtuple("_DiskUsage", ["total", "used", "free"])


def test_create_list_resolve_and_prune_backups():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "source.db"
        backups = root / "backups"
        with sqlite3.connect(source) as conn:
            conn.execute("CREATE TABLE example (value TEXT)")
            conn.execute("INSERT INTO example VALUES ('preserved')")
        created = create_backup(str(source), backups)
        assert created.exists()
        assert list_backups(backups)[0]["name"] == created.name
        assert backup_path(created.name, backups) == created
        assert backup_path("../source.db", backups) is None
        assert prune_backups(backups, keep=1) == 0
        with sqlite3.connect(created) as conn:
            assert conn.execute("SELECT value FROM example").fetchone()[0] == "preserved"


# ---------------------------------------------------------------------------
# backup_if_due()
# ---------------------------------------------------------------------------

def test_backup_if_due_creates_backup_when_none_exist(tmp_path):
    source = tmp_path / "source.db"
    backups = tmp_path / "backups"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE example (value TEXT)")

    result = backup_if_due(str(source), backups)

    assert result is not None
    assert result.exists()
    assert len(list_backups(backups)) == 1


def test_backup_if_due_skips_when_newest_backup_is_recent(tmp_path):
    source = tmp_path / "source.db"
    backups = tmp_path / "backups"
    backups.mkdir()
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE example (value TEXT)")
    existing = backups / "homeradar-20260101T000000Z.db"
    with sqlite3.connect(existing) as conn:
        conn.execute("CREATE TABLE example (value TEXT)")
    # `existing` was just created, so its mtime (what `list_backups` uses as
    # `created_at`) is "now" -- well within the 24h freshness window.

    result = backup_if_due(str(source), backups)

    assert result is None
    assert len(list_backups(backups)) == 1


def test_backup_if_due_creates_when_newest_backup_is_stale(tmp_path):
    source = tmp_path / "source.db"
    backups = tmp_path / "backups"
    backups.mkdir()
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE example (value TEXT)")
    stale = backups / "homeradar-20250101T000000Z.db"
    with sqlite3.connect(stale) as conn:
        conn.execute("CREATE TABLE example (value TEXT)")
    stale_time = time.time() - (25 * 3600)
    os.utime(stale, (stale_time, stale_time))

    result = backup_if_due(str(source), backups)

    assert result is not None
    assert result.exists()
    assert len(list_backups(backups)) == 2


# ---------------------------------------------------------------------------
# cleanup_database()
# ---------------------------------------------------------------------------

def test_cleanup_database_removes_expired_rows_and_keeps_recent(patched_db, db_path):
    now = datetime.now(timezone.utc)
    old_traffic = (now - timedelta(days=config.TRAFFIC_RETENTION_DAYS + 5)).isoformat()
    recent_traffic = (now - timedelta(days=1)).isoformat()
    old_alert = (now - timedelta(days=config.ALERT_RETENTION_DAYS + 5)).isoformat()
    recent_alert = (now - timedelta(days=1)).isoformat()
    expired_cache = (now - timedelta(hours=1)).isoformat()
    valid_cache = (now + timedelta(hours=1)).isoformat()

    with models.get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO traffic_logs (device_id, domain, was_blocked, created_at) VALUES (NULL, ?, 0, ?)",
            ("old.example", old_traffic),
        )
        conn.execute(
            "INSERT INTO traffic_logs (device_id, domain, was_blocked, created_at) VALUES (NULL, ?, 0, ?)",
            ("new.example", recent_traffic),
        )
        conn.execute(
            """INSERT INTO alerts (device_id, severity, title, description, is_resolved, created_at)
               VALUES (NULL, 'info', 'Old resolved', '', 1, ?)""",
            (old_alert,),
        )
        conn.execute(
            """INSERT INTO alerts (device_id, severity, title, description, is_resolved, created_at)
               VALUES (NULL, 'info', 'Recent resolved', '', 1, ?)""",
            (recent_alert,),
        )
        conn.execute(
            """INSERT INTO alerts (device_id, severity, title, description, is_resolved, created_at)
               VALUES (NULL, 'info', 'Old unresolved', '', 0, ?)""",
            (old_alert,),
        )
        conn.execute(
            """INSERT INTO threat_cache (
                   indicator, indicator_type, is_malicious, confidence, source, detail, expires_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("1.2.3.4", "ip", 0, 0, "test", None, expired_cache, now.isoformat()),
        )
        conn.execute(
            """INSERT INTO threat_cache (
                   indicator, indicator_type, is_malicious, confidence, source, detail, expires_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("5.6.7.8", "ip", 0, 0, "test", None, valid_cache, now.isoformat()),
        )

    with models.get_conn(db_path) as conn:
        counts = cleanup_database(conn)

    assert counts == {"traffic_removed": 1, "alerts_removed": 1, "cache_removed": 1}

    with models.get_conn(db_path) as conn:
        remaining_traffic = [row["domain"] for row in conn.execute("SELECT domain FROM traffic_logs")]
        remaining_alerts = {row["title"] for row in conn.execute("SELECT title FROM alerts")}
        remaining_cache = [row["indicator"] for row in conn.execute("SELECT indicator FROM threat_cache")]

    assert remaining_traffic == ["new.example"]
    assert remaining_alerts == {"Recent resolved", "Old unresolved"}
    assert remaining_cache == ["5.6.7.8"]


# ---------------------------------------------------------------------------
# health_report()
# ---------------------------------------------------------------------------

def test_health_report_uses_dns_upstream_setting_override(monkeypatch, patched_db, db_path):
    monkeypatch.setattr(
        "shutil.disk_usage",
        lambda path: _DiskUsage(total=100 * 1024**3, used=1 * 1024**3, free=99 * 1024**3),
    )
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "9.9.9.9"})

    with models.get_conn(db_path) as conn:
        report = health_report(conn)

    assert report["dns"]["upstream"] == "9.9.9.9"
    assert report["status"] == "healthy"
    assert not any("disk space" in warning for warning in report["warnings"])


def test_health_report_falls_back_to_config_dns_upstream_without_override(monkeypatch, patched_db, db_path):
    monkeypatch.setattr(
        "shutil.disk_usage",
        lambda path: _DiskUsage(total=100 * 1024**3, used=1 * 1024**3, free=99 * 1024**3),
    )

    with models.get_conn(db_path) as conn:
        report = health_report(conn)

    assert report["dns"]["upstream"] == config.DNS_UPSTREAM


def test_health_report_warns_on_low_disk_space(monkeypatch, patched_db, db_path):
    monkeypatch.setattr(
        "shutil.disk_usage",
        lambda path: _DiskUsage(total=100 * 1024**3, used=100 * 1024**3 - 100 * 1024**2, free=100 * 1024**2),
    )

    with models.get_conn(db_path) as conn:
        report = health_report(conn)

    assert report["status"] == "degraded"
    assert any("disk space" in warning for warning in report["warnings"])


def test_health_report_warns_when_dns_enabled_but_blocklist_missing(monkeypatch, patched_db, db_path, tmp_path):
    monkeypatch.setattr(
        "shutil.disk_usage",
        lambda path: _DiskUsage(total=100 * 1024**3, used=1 * 1024**3, free=99 * 1024**3),
    )
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    monkeypatch.setattr(config, "BLOCKLIST_PATH", tmp_path / "missing-blocklist.txt")

    with models.get_conn(db_path) as conn:
        report = health_report(conn)

    assert report["dns"]["enabled"] is True
    assert report["status"] == "degraded"
    assert any("blocklist" in warning for warning in report["warnings"])
