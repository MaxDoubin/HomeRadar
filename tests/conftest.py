"""Shared pytest fixtures for the HomeRadar backend test suite.

Several backend functions bind configuration paths as default argument values at
import time. Tests therefore patch the names where they are used, not only the
central config module, and keep every database, backup, and blocklist operation
inside a temporary directory.
"""
from __future__ import annotations

import functools

import pytest

from backend.db import models as models_mod


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "homeradar-test.db")
    models_mod.init_db(path)
    return path


@pytest.fixture
def patched_db(monkeypatch, db_path):
    """Point every module's get_conn at a throwaway temp-file database."""
    conn_factory = functools.partial(models_mod.get_conn, db_path)
    for target in [
        "backend.api.routes.get_conn",
        "backend.api.websocket.get_conn",
        "backend.pairing.get_conn",
        "backend.security.get_conn",
        "backend.dns.proxy.get_conn",
        "backend.monitor.traffic_analyzer.get_conn",
        "backend.main.get_conn",
    ]:
        monkeypatch.setattr(target, conn_factory, raising=False)
    from backend import config

    monkeypatch.setattr(config, "DB_PATH", db_path)
    return db_path


@pytest.fixture
def patched_backups(monkeypatch, tmp_path, db_path):
    """Redirect backup helpers and their imported aliases to temporary paths."""
    from backend import maintenance

    backups_dir = tmp_path / "backups"
    for name in ("list_backups", "backup_path", "prune_backups"):
        original = getattr(maintenance, name)
        patched = functools.partial(original, backup_dir=backups_dir)
        monkeypatch.setattr(maintenance, name, patched)
        monkeypatch.setattr(f"backend.api.routes.{name}", patched, raising=False)
    patched_create = functools.partial(
        maintenance.create_backup, source_path=db_path, backup_dir=backups_dir
    )
    monkeypatch.setattr(maintenance, "create_backup", patched_create)
    monkeypatch.setattr("backend.api.routes.create_backup", patched_create, raising=False)
    return backups_dir


@pytest.fixture
def patched_blocklists(monkeypatch, tmp_path):
    """Replace the process-wide blocklist singleton with a temporary one."""
    from backend.dns.blocklists import BlocklistManager

    fresh = BlocklistManager(tmp_path / "blocklist.txt")
    monkeypatch.setattr("backend.api.routes.blocklists", fresh, raising=False)
    monkeypatch.setattr("backend.services.blocklists", fresh, raising=False)
    return fresh


@pytest.fixture
def app(patched_db):
    """A test app with the real API, WebSocket, and security middleware."""
    from fastapi import FastAPI

    from backend.api.routes import router as api_router
    from backend.api.websocket import router as websocket_router
    from backend.security import ApplianceSecurityMiddleware

    test_app = FastAPI()
    test_app.include_router(api_router)
    test_app.include_router(websocket_router)
    test_app.add_middleware(ApplianceSecurityMiddleware)
    return test_app


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_token(patched_db):
    """A valid pairing token, minted directly against the patched test DB."""
    from backend import pairing

    with models_mod.get_conn(patched_db) as conn:
        return pairing.get_or_create_token(conn)


@pytest.fixture
def auth_headers(auth_token):
    return {"X-HomeRadar-Token": auth_token}


class FakeSocket:
    """A minimal stand-in for socket.socket used by discovery tests."""

    def __init__(self, connect_ex_results=None, recv_queue=None, sendto_raises=None):
        self.connect_ex_results = connect_ex_results or {}
        self.recv_queue = list(recv_queue or [])
        self.sendto_raises = sendto_raises
        self.sent = []
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def connect_ex(self, address):
        return self.connect_ex_results.get(tuple(address), 111)

    def sendto(self, data, address):
        if self.sendto_raises:
            raise self.sendto_raises
        self.sent.append((data, address))
        return len(data)

    def recvfrom(self, bufsize):
        import socket as socket_mod

        if not self.recv_queue:
            raise socket_mod.timeout()
        return self.recv_queue.pop(0)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


@pytest.fixture
def fake_socket_factory():
    return FakeSocket


def fake_subprocess_run(returncode=0, stdout="", stderr=""):
    """Build a callable usable as a subprocess.run monkeypatch target."""
    import subprocess

    def _run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)

    return _run


@pytest.fixture
def make_subprocess_run():
    return fake_subprocess_run


@pytest.fixture
def smtp_mock():
    """A context-manager-compatible smtplib.SMTP mock."""
    from unittest.mock import MagicMock

    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.__exit__.return_value = False
    factory = MagicMock(return_value=instance)
    return factory, instance
