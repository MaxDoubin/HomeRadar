"""API input validation, friendly errors, setup lock, health, and mDNS advertisement."""
from __future__ import annotations

import asyncio

import pytest

import backend.main as main
from backend import config, services
from backend.db import models
from backend.dns.blocklists import UpdateResult


# --- DNS upstream defaults keep the failover list -------------------------


def test_settings_default_upstream_keeps_every_failover_server(client, monkeypatch):
    monkeypatch.setattr(config, "DNS_UPSTREAMS", ["127.0.0.2", "127.0.0.3"])
    assert client.get("/settings").json()["dns_upstream"] == "127.0.0.2,127.0.0.3"


def test_saving_settings_round_trip_preserves_both_upstreams(client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "DNS_UPSTREAMS", ["127.0.0.2", "127.0.0.3"])
    current = client.get("/settings").json()
    response = client.patch(
        "/settings",
        json={"household_name": current["household_name"], "dns_upstream": current["dns_upstream"]},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["dns_upstream"] == "127.0.0.2,127.0.0.3"


def test_first_run_setup_defaults_to_every_failover_server(client, monkeypatch):
    monkeypatch.setattr(config, "DNS_UPSTREAMS", ["127.0.0.2", "127.0.0.3"])
    response = client.post("/setup", json={"household_name": "Doubin Home"})
    assert response.status_code == 200
    assert response.json()["settings"]["dns_upstream"] == "127.0.0.2,127.0.0.3"


# --- settings validation ---------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"household_name": "   "},
        {"digest_email": "nope"},
        {"digest_email": "a b@example.com"},
        {"dns_upstream": "not an ip;;"},
        {"dns_upstream": " , "},
        {"custom_dns_records": "not json {"},
        {"custom_dns_records": "[1, 2]"},
    ],
)
def test_invalid_settings_are_rejected(client, auth_headers, payload):
    assert client.patch("/settings", json=payload, headers=auth_headers).status_code == 422


def test_valid_settings_are_normalized(client, auth_headers):
    response = client.patch(
        "/settings",
        json={
            "household_name": "  Doubin Home  ",
            "digest_email": " parent@example.com ",
            "dns_upstream": "1.1.1.1, 9.9.9.9",
            "custom_dns_records": '{"nas.home": "192.168.1.10"}',
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["household_name"] == "Doubin Home"
    assert body["digest_email"] == "parent@example.com"
    assert body["dns_upstream"] == "1.1.1.1,9.9.9.9"


def test_blank_digest_email_is_allowed(client, auth_headers):
    response = client.patch("/settings", json={"digest_email": ""}, headers=auth_headers)
    assert response.status_code == 200


# --- other input validation ------------------------------------------------


def test_traffic_observe_rejects_non_ip_addresses(client, auth_headers):
    response = client.post(
        "/traffic/observe",
        json={"source_ip": "nope", "destination_ip": "also nope"},
        headers=auth_headers,
    )
    assert response.status_code == 422


@pytest.mark.parametrize("bad_time", ["25:99", "24:00", "7pm"])
def test_policy_rejects_impossible_times(client, auth_headers, patched_db, bad_time):
    with models.get_conn(patched_db) as conn:
        device_id = models.upsert_device(conn, "AA:BB:CC:00:11:22", "192.168.1.40", None, None)
    response = client.put(
        f"/devices/{device_id}/policy",
        json={"internet_enabled": True, "block_start": bad_time, "block_end": "07:00"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_policy_accepts_overnight_window(client, auth_headers, patched_db):
    with models.get_conn(patched_db) as conn:
        device_id = models.upsert_device(conn, "AA:BB:CC:00:11:23", "192.168.1.41", None, None)
    response = client.put(
        f"/devices/{device_id}/policy",
        json={"internet_enabled": True, "block_start": "21:00", "block_end": "07:00"},
        headers=auth_headers,
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        "/threat-intel/cisa-kev?limit=0",
        "/threat-intel/cisa-kev?limit=501",
        "/traffic/summary?hours=0",
        "/traffic?limit=-1",
    ],
)
def test_query_bounds(client, url):
    assert client.get(url).status_code == 422


def test_catalog_search_treats_wildcards_literally(patched_db):
    from backend.monitor.cisa_kev import search_catalog

    with models.get_conn(patched_db) as conn:
        conn.execute(
            """INSERT INTO cisa_kev
               (cve_id, vendor_project, product, vulnerability_name, date_added, updated_at)
               VALUES ('CVE-2000-0001', 'Acme', 'Router', 'Example', '2024-01-01', '2024-01-01')"""
        )
        assert search_catalog(conn, query="%") == []
        assert search_catalog(conn, query="_") == []
        assert [row["cve_id"] for row in search_catalog(conn, query="acme")] == ["CVE-2000-0001"]


# --- friendly update errors -------------------------------------------------


def test_blocklist_update_returns_structured_summary(client, auth_headers, patched_blocklists, monkeypatch):
    results = [
        UpdateResult("https://good.example/list", 10, "ok"),
        UpdateResult(
            "https://bad.example/list", 0, "error",
            error="<urlopen error 502>", friendly_error="Couldn't reach bad.example.",
        ),
    ]
    monkeypatch.setattr(patched_blocklists, "update", lambda: results)
    response = client.post("/blocklists/update", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["message"]
    bad = body["sources"][1]
    assert bad["error_friendly"] == "Couldn't reach bad.example."
    assert bad["error_detail"] == "<urlopen error 502>"
    # Fields older dashboard builds read.
    assert bad["source"] == "https://bad.example/list"
    assert bad["status"] == "error"
    assert bad["error"] == "Couldn't reach bad.example."
    assert "domain_count" in body


def test_cisa_update_failure_is_friendly(client, auth_headers, monkeypatch):
    def boom(conn):
        raise OSError("<urlopen error Tunnel connection failed: 502 Bad Gateway>")

    monkeypatch.setattr("backend.api.routes.update_catalog", boom)
    response = client.post("/threat-intel/cisa-kev/update", headers=auth_headers)
    assert response.status_code == 502
    body = response.json()
    assert body["detail"].startswith("Couldn't reach cisa.gov")
    assert "urlopen" not in body["detail"]
    assert body["error_detail"] == "OSError"
    assert "Tunnel connection failed" not in response.text


# --- /setup lock -----------------------------------------------------------


def test_setup_can_only_be_rerun_with_a_token(client, auth_headers):
    assert client.post("/setup", json={"household_name": "First"}).status_code == 200
    assert client.post("/setup", json={"household_name": "Intruder"}).status_code == 401
    assert client.get("/settings").json()["household_name"] == "First"
    rerun = client.post("/setup", json={"household_name": "Renamed"}, headers=auth_headers)
    assert rerun.status_code == 200
    assert rerun.json()["settings"]["household_name"] == "Renamed"


# --- /health ---------------------------------------------------------------


class _Proxy:
    def __init__(self, failure):
        self.failure = failure


def test_health_reports_degraded_when_dns_listener_died(client, monkeypatch):
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    monkeypatch.setattr(services, "dns_proxy", _Proxy("DNS couldn't start on port 53: Permission denied"))
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["dns"]["listening"] is False
    assert any("Permission denied" in warning for warning in body["warnings"])


def test_health_reports_listening_dns(client, monkeypatch):
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    monkeypatch.setattr(services, "dns_proxy", _Proxy(None))
    body = client.get("/health").json()
    assert body["dns"]["listening"] is True
    assert not any("couldn't start" in warning for warning in body["warnings"])


def test_health_upstream_lists_every_failover_server(client, monkeypatch):
    monkeypatch.setattr(config, "DNS_UPSTREAMS", ["127.0.0.2", "127.0.0.3"])
    assert client.get("/health").json()["dns"]["upstream"] == "127.0.0.2,127.0.0.3"


# --- mDNS advertisement ----------------------------------------------------


class FakeZeroconf:
    instances: list["FakeZeroconf"] = []
    fail_register = False

    def __init__(self):
        self.registered = []
        self.unregistered = []
        self.closed = False
        FakeZeroconf.instances.append(self)

    def register_service(self, info, allow_name_change=False):
        if FakeZeroconf.fail_register:
            raise OSError("multicast unavailable")
        self.registered.append((info, allow_name_change))

    def unregister_service(self, info):
        self.unregistered.append(info)

    def close(self):
        self.closed = True


class FakeServiceInfo:
    def __init__(self, type_, name, addresses, port, properties, server):
        self.type = type_
        self.name = name
        self.addresses = addresses
        self.port = port
        self.properties = properties
        self.server = server


@pytest.fixture
def fake_zeroconf(monkeypatch):
    FakeZeroconf.instances = []
    FakeZeroconf.fail_register = False
    monkeypatch.setattr("zeroconf.Zeroconf", FakeZeroconf)
    monkeypatch.setattr("zeroconf.ServiceInfo", FakeServiceInfo)
    monkeypatch.setattr(main, "_lan_ipv4", lambda: "192.168.1.20")
    monkeypatch.setattr(main.socket, "gethostname", lambda: "old-laptop.lan")
    monkeypatch.setattr(config, "API_PORT", 8000)
    return FakeZeroconf


def test_mdns_advertises_homeradar_http_service(fake_zeroconf):
    zeroconf, info = main._start_mdns_advertisement()
    assert info.type == "_http._tcp.local."
    assert info.name == "HomeRadar on old-laptop._http._tcp.local."
    assert "homeradar" in info.name.lower()
    assert info.port == 8000
    assert info.addresses == [bytes([192, 168, 1, 20])]
    assert zeroconf.registered and zeroconf.registered[0][1] is True

    main._stop_mdns_advertisement((zeroconf, info))
    assert zeroconf.unregistered == [info]
    assert zeroconf.closed


def test_mdns_failure_never_breaks_startup(fake_zeroconf):
    fake_zeroconf.fail_register = True
    assert main._start_mdns_advertisement() is None
    assert fake_zeroconf.instances[-1].closed


def test_mdns_skipped_without_lan_address(fake_zeroconf, monkeypatch):
    monkeypatch.setattr(main, "_lan_ipv4", lambda: None)
    assert main._start_mdns_advertisement() is None
    assert fake_zeroconf.instances == []


def test_lifespan_advertises_and_withdraws_mdns(monkeypatch, patched_db):
    async def _noop():
        return

    for loop in ("_discovery_loop", "_trust_loop", "_blocklist_loop", "_maintenance_loop"):
        monkeypatch.setattr(main, loop, _noop)
    monkeypatch.setattr(config, "DNS_ENABLED", False)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", False)
    monkeypatch.setattr(config, "MDNS_ADVERTISE", True)
    calls = []
    monkeypatch.setattr(main, "_start_mdns_advertisement", lambda: calls.append("start") or ("zc", "info"))
    monkeypatch.setattr(main, "_stop_mdns_advertisement", lambda ad: calls.append(("stop", ad)))

    async def run():
        async with main.lifespan(main.app):
            assert calls == ["start"]

    asyncio.run(run())
    assert calls == ["start", ("stop", ("zc", "info"))]


def test_lifespan_skips_mdns_when_disabled(monkeypatch, patched_db):
    async def _noop():
        return

    for loop in ("_discovery_loop", "_trust_loop", "_blocklist_loop", "_maintenance_loop"):
        monkeypatch.setattr(main, loop, _noop)
    monkeypatch.setattr(config, "DNS_ENABLED", False)
    monkeypatch.setattr(config, "TRAFFIC_MONITOR_ENABLED", False)
    monkeypatch.setattr(main, "_start_mdns_advertisement", lambda: pytest.fail("should not advertise"))

    async def run():
        async with main.lifespan(main.app):
            pass

    asyncio.run(run())
