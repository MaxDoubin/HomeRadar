import asyncio
import logging
import threading

import pytest
from fastapi.testclient import TestClient

import backend.main as main
from backend import config, services


async def _noop_loop():
    return


def _stub_all_background_loops(monkeypatch):
    monkeypatch.setattr(main, "_discovery_loop", _noop_loop)
    monkeypatch.setattr(main, "_trust_loop", _noop_loop)
    monkeypatch.setattr(main, "_blocklist_loop", _noop_loop)
    monkeypatch.setattr(main, "_maintenance_loop", _noop_loop)


def _thread_names():
    return {t.name for t in threading.enumerate()}


# ---------------------------------------------------------------------------
# lifespan: DNS + traffic monitor both disabled
# ---------------------------------------------------------------------------


def test_lifespan_starts_and_stops_cleanly_with_dns_and_traffic_disabled(
    monkeypatch, patched_db
):
    _stub_all_background_loops(monkeypatch)
    monkeypatch.setattr(config, "DNS_ENABLED", False)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", False)
    services.dns_proxy = None

    with TestClient(main.app) as client:
        assert services.dns_proxy is None
        assert "homeradar-dns" not in _thread_names()
        assert "homeradar-traffic" not in _thread_names()
        response = client.get("/kiosk/status-display.html")
        assert response.status_code == 200

    assert services.dns_proxy is None
    assert "homeradar-dns" not in _thread_names()
    assert "homeradar-traffic" not in _thread_names()


# ---------------------------------------------------------------------------
# lifespan: DNS enabled with a fake DNSProxy
# ---------------------------------------------------------------------------


class FakeDNSProxy:
    instances = []

    def __init__(self, blocklists_manager):
        self.blocklists = blocklists_manager
        self.address = ("127.0.0.1", 53)
        self._stop_evt = threading.Event()
        self._ready_evt = threading.Event()
        self.stopped = False
        type(self).instances.append(self)

    def serve_forever(self):
        self._ready_evt.set()
        self._stop_evt.wait(timeout=5)

    def wait_until_ready(self, timeout=5.0):
        return self._ready_evt.wait(timeout=timeout)

    def stats(self):
        return {
            "running": self._ready_evt.is_set() and not self.stopped,
            "listeners": {"udp": True, "tcp": True, "errors": {}},
            "cache": {},
            "upstreams": {},
        }

    def stop(self):
        self.stopped = True
        self._stop_evt.set()


class FailingDNSProxy(FakeDNSProxy):
    def serve_forever(self):
        return

    def wait_until_ready(self, timeout=5.0):
        return False

    def stats(self):
        return {
            "running": False,
            "listeners": {
                "udp": False,
                "tcp": False,
                "errors": {"udp": "OSError: address already in use"},
            },
            "cache": {},
            "upstreams": {},
        }


def test_lifespan_starts_and_stops_dns_proxy_when_enabled(monkeypatch, patched_db):
    _stub_all_background_loops(monkeypatch)
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", False)
    monkeypatch.setattr(main, "DNSProxy", FakeDNSProxy)
    FakeDNSProxy.instances = []
    services.dns_proxy = None

    with TestClient(main.app) as client:
        assert isinstance(services.dns_proxy, FakeDNSProxy)
        assert len(FakeDNSProxy.instances) == 1
        assert "homeradar-dns" in _thread_names()

    assert services.dns_proxy is None
    assert FakeDNSProxy.instances[0].stopped is True


def test_lifespan_fails_when_configured_dns_listener_cannot_start(monkeypatch, patched_db):
    _stub_all_background_loops(monkeypatch)
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", False)
    monkeypatch.setattr(main, "DNSProxy", FailingDNSProxy)
    FailingDNSProxy.instances = []
    services.dns_proxy = None

    with pytest.raises(RuntimeError, match="DNS proxy failed to start"):
        with TestClient(main.app):
            pass

    assert services.dns_proxy is None
    assert FailingDNSProxy.instances[0].stopped is True


# ---------------------------------------------------------------------------
# lifespan: traffic monitor enabled with a fake PassiveTrafficMonitor
# ---------------------------------------------------------------------------


class FakeTrafficMonitor:
    instances = []

    def __init__(self, *args, **kwargs):
        self._stop_evt = threading.Event()
        self.stopped = False
        FakeTrafficMonitor.instances.append(self)

    def run(self):
        self._stop_evt.wait(timeout=5)

    def stop(self):
        self.stopped = True
        self._stop_evt.set()


def test_lifespan_starts_and_stops_traffic_monitor_when_enabled(monkeypatch, patched_db):
    _stub_all_background_loops(monkeypatch)
    monkeypatch.setattr(config, "DNS_ENABLED", False)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", True)
    monkeypatch.setattr(main, "PassiveTrafficMonitor", FakeTrafficMonitor)
    FakeTrafficMonitor.instances = []
    services.dns_proxy = None

    with TestClient(main.app):
        assert len(FakeTrafficMonitor.instances) == 1
        assert "homeradar-traffic" in _thread_names()

    assert FakeTrafficMonitor.instances[0].stopped is True
    assert "homeradar-traffic" not in _thread_names()


# ---------------------------------------------------------------------------
# Background loop error handling
# ---------------------------------------------------------------------------


async def _cancel_on_sleep(*args, **kwargs):
    raise asyncio.CancelledError()


def test_discovery_loop_logs_and_does_not_crash_on_error(monkeypatch, caplog):
    def _raise_run_discovery():
        raise RuntimeError("discovery boom")

    monkeypatch.setattr(main, "_run_discovery", _raise_run_discovery)
    monkeypatch.setattr(asyncio, "sleep", _cancel_on_sleep)

    with caplog.at_level(logging.ERROR, logger="homeradar.main"):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(main._discovery_loop())

    assert "Discovery scan failed" in caplog.text


def test_trust_loop_logs_and_does_not_crash_on_error(monkeypatch, patched_db, caplog):
    def _raise_audit_all(conn):
        raise RuntimeError("trust boom")

    monkeypatch.setattr(main, "audit_all", _raise_audit_all)
    monkeypatch.setattr(asyncio, "sleep", _cancel_on_sleep)

    with caplog.at_level(logging.ERROR, logger="homeradar.main"):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(main._trust_loop())

    assert "Trust score recalculation failed" in caplog.text


def test_blocklist_loop_logs_and_does_not_crash_on_error(monkeypatch, caplog):
    monkeypatch.setattr(config, "BLOCKLIST_AUTO_UPDATE", True)
    monkeypatch.setattr(config, "BLOCKLIST_URLS", ["http://example.invalid/list.txt"])

    def _raise_update():
        raise RuntimeError("blocklist boom")

    monkeypatch.setattr(main.blocklists, "update", _raise_update)
    monkeypatch.setattr(asyncio, "sleep", _cancel_on_sleep)

    with caplog.at_level(logging.ERROR, logger="homeradar.main"):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(main._blocklist_loop())

    assert "Blocklist update failed" in caplog.text


def test_maintenance_loop_logs_and_does_not_crash_on_error(monkeypatch, patched_db, caplog):
    def _raise_cleanup(conn):
        raise RuntimeError("maintenance boom")

    monkeypatch.setattr(main, "cleanup_database", _raise_cleanup)
    monkeypatch.setattr(asyncio, "sleep", _cancel_on_sleep)

    with caplog.at_level(logging.ERROR, logger="homeradar.main"):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(main._maintenance_loop())

    assert "Maintenance pass failed" in caplog.text
