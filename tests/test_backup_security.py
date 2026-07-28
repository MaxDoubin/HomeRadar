"""Regression tests for backup filename safety and collision resistance."""
import sqlite3

from backend.maintenance import backup_path, create_backup, list_backups


def _source_database(path):
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE sample (value TEXT)")
        conn.execute("INSERT INTO sample VALUES ('ok')")


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
