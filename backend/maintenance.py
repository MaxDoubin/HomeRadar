"""Database retention, verified backups, and appliance health diagnostics."""
from __future__ import annotations

import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend import config

_BACKUP_NAME = re.compile(r"^homeradar-\d{8}T\d{6}(?:\d{6})?Z\.db$")
_SECRET_SETTING_KEYS = (
    "pairing_token",
    "pairing_code",
    "pairing_code_expires_at",
    "pairing_fail_count",
    "pairing_locked_until",
)


def create_backup(
    source_path: str = config.DB_PATH,
    backup_dir: Path = config.BACKUP_DIR,
) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = backup_dir / f"homeradar-{timestamp}.db"
    try:
        with sqlite3.connect(source_path, timeout=30) as source, sqlite3.connect(
            target, timeout=30
        ) as destination:
            source.backup(destination)
            placeholders = ",".join("?" for _ in _SECRET_SETTING_KEYS)
            destination.execute(
                f"DELETE FROM settings WHERE key IN ({placeholders})",
                _SECRET_SETTING_KEYS,
            )
            destination.commit()
            check = destination.execute("PRAGMA quick_check").fetchone()[0]
    except Exception:
        target.unlink(missing_ok=True)
        raise
    if check != "ok":
        target.unlink(missing_ok=True)
        raise RuntimeError(f"backup integrity check failed: {check}")
    return target


def list_backups(backup_dir: Path = config.BACKUP_DIR) -> list[dict]:
    if not backup_dir.exists():
        return []
    return [
        {
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "created_at": datetime.fromtimestamp(
                path.stat().st_mtime, timezone.utc
            ).isoformat(),
        }
        for path in sorted(backup_dir.glob("homeradar-*.db"), reverse=True)
        if path.is_file() and _BACKUP_NAME.fullmatch(path.name)
    ]


def backup_path(name: str, backup_dir: Path = config.BACKUP_DIR) -> Path | None:
    """Resolve a generated backup name without allowing path traversal."""
    if not _BACKUP_NAME.fullmatch(name):
        return None
    if Path(name).name != name or "/" in name or "\\" in name:
        return None
    candidate = backup_dir / name
    try:
        resolved = candidate.resolve(strict=True)
        root = backup_dir.resolve(strict=True)
    except (FileNotFoundError, OSError):
        return None
    if resolved.parent != root or not resolved.is_file():
        return None
    return resolved


def prune_backups(
    backup_dir: Path = config.BACKUP_DIR,
    keep: int = config.BACKUP_RETENTION_COUNT,
) -> int:
    backups = (
        sorted(
            (
                path
                for path in backup_dir.glob("homeradar-*.db")
                if path.is_file() and _BACKUP_NAME.fullmatch(path.name)
            ),
            reverse=True,
        )
        if backup_dir.exists()
        else []
    )
    removed = 0
    for path in backups[max(1, keep):]:
        path.unlink()
        removed += 1
    return removed


def cleanup_database(conn) -> dict:
    traffic = conn.execute(
        """DELETE FROM traffic_logs
           WHERE julianday(created_at) < julianday('now', ?)""",
        (f"-{max(1, config.TRAFFIC_RETENTION_DAYS)} days",),
    ).rowcount
    alerts = conn.execute(
        """DELETE FROM alerts
           WHERE is_resolved = 1 AND julianday(created_at) < julianday('now', ?)""",
        (f"-{max(1, config.ALERT_RETENTION_DAYS)} days",),
    ).rowcount
    cache = conn.execute(
        "DELETE FROM threat_cache WHERE julianday(expires_at) < julianday('now')"
    ).rowcount
    return {"traffic_removed": traffic, "alerts_removed": alerts, "cache_removed": cache}


def backup_if_due(
    source_path: str = config.DB_PATH,
    backup_dir: Path = config.BACKUP_DIR,
) -> Path | None:
    backups = list_backups(backup_dir)
    if backups:
        newest = datetime.fromisoformat(backups[0]["created_at"])
        if datetime.now(timezone.utc) - newest < timedelta(hours=24):
            return None
    result = create_backup(source_path, backup_dir)
    prune_backups(backup_dir)
    return result


def health_report(conn) -> dict:
    database_check = conn.execute("PRAGMA quick_check").fetchone()[0]
    data_path = Path(config.DB_PATH).parent
    data_path.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(data_path)
    last_seen = conn.execute("SELECT MAX(last_seen) FROM devices").fetchone()[0]
    last_blocklist = conn.execute(
        "SELECT MAX(updated_at) FROM blocklist_metadata WHERE status = 'ok'"
    ).fetchone()[0]
    warnings = []
    if database_check != "ok":
        warnings.append("database integrity check failed")
    if disk.free < 500 * 1024 * 1024:
        warnings.append("less than 500 MB disk space remains")
    if config.DNS_ENABLED and not config.BLOCKLIST_PATH.exists():
        warnings.append("DNS is enabled but no downloaded blocklist is present")
    return {
        "status": "healthy" if not warnings else "degraded",
        "database": database_check,
        "disk": {
            "free_bytes": disk.free,
            "total_bytes": disk.total,
            "free_percent": round((disk.free / disk.total) * 100, 1),
        },
        "dns": {
            "enabled": config.DNS_ENABLED,
            "listen": f"{config.DNS_HOST}:{config.DNS_PORT}",
            "upstream": conn.execute(
                "SELECT COALESCE((SELECT value FROM settings WHERE key = 'dns_upstream'), ?)",
                (config.DNS_UPSTREAM,),
            ).fetchone()[0],
        },
        "last_device_seen": last_seen,
        "last_blocklist_update": last_blocklist,
        "backup_count": len(list_backups()),
        "warnings": warnings,
    }
