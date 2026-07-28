"""Regression tests for backup filename and secret safety."""
import sqlite3

from backend.maintenance import backup_path, create_backup, list_backups


def _source_database(path):
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
        conn.execute("INSERT INTO sample VALUES ('ok')")
        conn.execute(
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT NOT NULL)"
        )


def test_backup_path_rejects_windows_and_posix_traversal(tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    assert backup_path("../homeradar-20260101T000000Z.db", backups) is None
    assert backup_path("..\\homeradar-20260101T000000Z.db", backups) is None
    assert backup_path("homeradar-..\\outside.db", backups) is None
    assert backup_path("homeradar-not-a-timestamp.db", backups) is None


def test_rapid_backups_receive_unique_names(tmp_path):
    source = tmp_path / "source.db"
    backups = tmp_path / "backups"
    _source_database(source)

    first = create_backup(str(source), backups)
    second = create_backup(str(source), backups)

    assert first != second
    assert first.exists() and second.exists()
    assert len(list_backups(backups)) == 2


def test_backup_removes_pairing_credentials_but_preserves_normal_settings(tmp_path):
    source = tmp_path / "source.db"
    backups = tmp_path / "backups"
    _source_database(source)
    with sqlite3.connect(source) as conn:
        conn.executemany(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, 'now')",
            [
                ("pairing_token", "secret-token"),
                ("pairing_code", "123456"),
                ("pairing_code_expires_at", "future"),
                ("pairing_fail_count", "3"),
                ("pairing_locked_until", "future"),
                ("household_name", "Test Home"),
            ],
        )

    backup = create_backup(str(source), backups)
    with sqlite3.connect(backup) as conn:
        saved = dict(conn.execute("SELECT key, value FROM settings").fetchall())

    assert saved == {"household_name": "Test Home"}
