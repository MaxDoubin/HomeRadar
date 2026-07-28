"""Shared SQLite connection boundary for the Home Radar process."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from backend import config
from backend.db import models


def _configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(db_path: str = config.DB_PATH) -> None:
    """Initialize/migrate the schema, then enable persistent WAL journaling."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    models.init_db(db_path)
    with sqlite3.connect(db_path, timeout=30) as conn:
        _configure_connection(conn)
        conn.execute("PRAGMA journal_mode = WAL")


@contextmanager
def get_conn(db_path: str = config.DB_PATH):
    """Open a resilient per-operation connection for concurrent worker threads."""
    conn = sqlite3.connect(db_path, timeout=30)
    _configure_connection(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


__all__ = ["get_conn", "init_db", "models"]
