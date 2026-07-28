from backend.db import models
from backend.discovery import scan_runner
from backend.discovery.scan_runner import run_discovery_scan


def _fake_fingerprint(ip, mac, observation):
    return {
        "ip": ip,
        "mac": mac.upper(),
        "vendor": "TestVendor",
        "hostname": f"host-{ip.split('.')[-1]}",
        "model": None,
        "open_ports": [80],
        "services": [],
        "discovery_sources": sorted(set(observation.get("sources", ["arp"]))),
        "device_type": "router",
        "confidence": 0.5,
        "fingerprint": {"evidence": [], "scores": {}},
    }


def _patch_sources(monkeypatch, *, arp=None, neighbor=None, mdns=None, ssdp=None, fingerprint=None):
    monkeypatch.setattr(scan_runner, "arp_scan", arp if arp is not None else (lambda subnet=None: []))
    monkeypatch.setattr(scan_runner, "neighbor_scan", neighbor if neighbor is not None else (lambda: []))
    monkeypatch.setattr(scan_runner, "mdns_discover", mdns if mdns is not None else (lambda: {}))
    monkeypatch.setattr(scan_runner, "ssdp_discover", ssdp if ssdp is not None else (lambda: {}))
    monkeypatch.setattr(
        scan_runner, "fingerprint_device", fingerprint if fingerprint is not None else _fake_fingerprint
    )


def test_run_discovery_scan_creates_device_and_new_device_alert(monkeypatch, patched_db, db_path):
    _patch_sources(
        monkeypatch,
        arp=lambda subnet=None: [{"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF"}],
    )

    with models.get_conn(db_path) as conn:
        results = run_discovery_scan(conn)

    assert len(results) == 1
    assert results[0]["mac"] == "AA:BB:CC:DD:EE:FF"

    with models.get_conn(db_path) as conn:
        devices = models.list_devices(conn)
        alerts = models.list_alerts(conn)

    assert len(devices) == 1
    assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert any(alert["title"] == "New device connected" for alert in alerts)


def test_run_discovery_scan_updates_existing_device_without_duplicate_alert(monkeypatch, patched_db, db_path):
    _patch_sources(
        monkeypatch,
        arp=lambda subnet=None: [{"ip": "192.168.1.21", "mac": "AA:BB:CC:DD:EE:01"}],
    )

    with models.get_conn(db_path) as conn:
        run_discovery_scan(conn)
    with models.get_conn(db_path) as conn:
        run_discovery_scan(conn)

    with models.get_conn(db_path) as conn:
        devices = models.list_devices(conn)
        alerts = models.list_alerts(conn)

    assert len(devices) == 1
    new_device_alerts = [alert for alert in alerts if alert["title"] == "New device connected"]
    assert len(new_device_alerts) == 1


def test_run_discovery_scan_continues_when_one_source_raises(monkeypatch, patched_db, db_path):
    def _boom(subnet=None):
        raise RuntimeError("arp scan exploded")

    _patch_sources(
        monkeypatch,
        arp=_boom,
        neighbor=lambda: [{"ip": "192.168.1.30", "mac": "11:22:33:44:55:66"}],
    )

    with models.get_conn(db_path) as conn:
        results = run_discovery_scan(conn)

    assert len(results) == 1
    assert results[0]["ip"] == "192.168.1.30"


def test_fingerprint_failure_for_one_host_does_not_abort_others(monkeypatch, patched_db, db_path):
    def flaky_fingerprint(ip, mac, observation):
        if ip.endswith(".40"):
            raise RuntimeError("fingerprint boom")
        return _fake_fingerprint(ip, mac, observation)

    _patch_sources(
        monkeypatch,
        arp=lambda subnet=None: [
            {"ip": "192.168.1.40", "mac": "AA:AA:AA:AA:AA:01"},
            {"ip": "192.168.1.41", "mac": "AA:AA:AA:AA:AA:02"},
        ],
        fingerprint=flaky_fingerprint,
    )

    with models.get_conn(db_path) as conn:
        results = run_discovery_scan(conn)

    assert len(results) == 1
    assert results[0]["ip"] == "192.168.1.41"


def test_discover_hosts_passes_none_subnet_only_when_lan_subnet_is_auto(monkeypatch):
    captured = {}

    def fake_arp_scan(subnet=None):
        captured["subnet"] = subnet
        return []

    _patch_sources(monkeypatch, arp=fake_arp_scan)

    monkeypatch.setattr(scan_runner.config, "LAN_SUBNET", "auto")
    scan_runner._discover_hosts()
    assert captured["subnet"] is None

    monkeypatch.setattr(scan_runner.config, "LAN_SUBNET", "192.168.50.0/24")
    scan_runner._discover_hosts()
    assert captured["subnet"] == "192.168.50.0/24"
