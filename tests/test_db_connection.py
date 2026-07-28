"""Tests for the production SQLite connection boundary."""

from backend.db import get_conn, init_db


def test_production_connection_enables_safety_pragmas(tmp_path):
    database = str(tmp_path / "connection.db")
    init_db(database)

    with get_conn(database) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        assert conn.execute("PRAGMA synchronous").fetchone()[0] in {1, 2}


def test_connection_rolls_back_failed_transactions(tmp_path):
    database = str(tmp_path / "rollback.db")
    init_db(database)

    try:
        with get_conn(database) as conn:
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES ('temporary', 'x', 'now')"
            )
            raise RuntimeError("abort")
    except RuntimeError:
        pass

    with get_conn(database) as conn:
        assert conn.execute("SELECT value FROM settings WHERE key = 'temporary'").fetchone() is None
