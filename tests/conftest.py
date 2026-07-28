"""Shared pytest fixtures for the HomeRadar backend test suite.

Big gotcha this file exists to solve: several backend functions bind
`config.DB_PATH` / `config.BACKUP_DIR` as *default argument values at
import time* (`get_conn(db_path=config.DB_PATH)`,
`create_backup(backup_dir=config.BACKUP_DIR)`, etc.), and the modules that
call them (`backend/api/routes.py`, `backend/api/websocket.py`,
`backend/main.py`) import those names *by name* into their own module
namespace. Monkeypatching `config.DB_PATH` alone, after those modules are
already imported, changes nothing -- you have to patch the name where it's
used (each importing module's own attribute), not just where it's defined.
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
    """Point every module's `get_conn` at a throwaway temp-file database."""
    conn_factory = functools.partial(models_mod.get_conn, db_path)
    for target in [
        "backend.api.routes.get_conn",
        "backend.api.websocket.get_conn",
        "backend.pairing.get_conn",
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
    """Redirect every backup helper (both where it's defined and every place
    it was imported by name) at a throwaway temp directory/DB, so tests
    never touch the real backend/data/backups/ or backend/data/homeradar.db."""
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
    """`backend.services.blocklists` is a process-wide singleton created at
    import time against the real `config.BLOCKLIST_PATH`, and
    `backend.api.routes` imported the *name* `blocklists` directly --
    patching `backend.services.blocklists` alone would not update
    `routes.py`'s already-bound reference."""
    from backend.dns.blocklists import BlocklistManager

    fresh = BlocklistManager(tmp_path / "blocklist.txt")
    monkeypatch.setattr("backend.api.routes.blocklists", fresh, raising=False)
    monkeypatch.setattr("backend.services.blocklists", fresh, raising=False)
    return fresh


@pytest.fixture
def app(patched_db):
    """A bare FastAPI app with only the API + WebSocket routers -- NOT
    `backend.main.app`, whose real lifespan would run a live ARP/mDNS/SSDP
    discovery pass and write a real backup file on startup."""
    from fastapi import FastAPI

    from backend.api.routes import router as api_router
    from backend.api.websocket import router as websocket_router

    test_app = FastAPI()
    test_app.include_router(api_router)
    test_app.include_router(websocket_router)
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
    """A minimal stand-in for `socket.socket` used by port/SSDP/ARP tests.

    `connect_ex_results` maps (host, port) -> return code for `connect_ex`;
    `recv_queue` is a list of (data, addr) tuples consumed in order by
    `recvfrom`, raising `socket.timeout` once exhausted.
    """

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
    """Build a callable usable as a `subprocess.run` monkeypatch target."""
    import subprocess

    def _run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)

    return _run


@pytest.fixture
def make_subprocess_run():
    return fake_subprocess_run


@pytest.fixture
def smtp_mock():
    """A MagicMock standing in for `smtplib.SMTP`, configured so its
    `with smtplib.SMTP(...) as server:` context-manager usage works."""
    from unittest.mock import MagicMock

    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.__exit__.return_value = False
    factory = MagicMock(return_value=instance)
    return factory, instance
