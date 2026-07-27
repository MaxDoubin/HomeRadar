import sqlite3
import tempfile
from pathlib import Path

from backend.maintenance import backup_path, create_backup, list_backups, prune_backups


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
