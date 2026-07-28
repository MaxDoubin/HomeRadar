"""HTTP-level tests for backend/api/routes.py: happy paths, error cases, and
the pairing-token auth matrix (which endpoints require a token, which stay
open)."""
from __future__ import annotations

import pytest

from backend import maintenance
from backend import services
from backend.api import routes as api_routes
from backend.db import models
from backend.dns.blocklists import UpdateResult
from backend.monitor.threat_intel import Reputation


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def device_id(client, db_path):
    with models.get_conn(db_path) as conn:
        return models.upsert_device(
            conn,
            mac="AA:BB:CC:DD:EE:01",
            ip="192.168.1.50",
            hostname="host1",
            vendor="Vendor1",
            model="Model X",
            device_type="computer",
            confidence=0.8,
            open_ports=[22, 80],
        )


@pytest.fixture
def alert_id(client, db_path, device_id):
    with models.get_conn(db_path) as conn:
        return models.create_alert(conn, device_id, "warning", "Test alert", "desc")


# ---------------------------------------------------------------------------
# status / health / dashboard
# ---------------------------------------------------------------------------


def test_status_no_auth(client):
    response = client.get("/status")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "device_count",
        "open_alert_count",
        "security_score",
        "dns_enabled",
        "blocklist_domains",
    }


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] in {"healthy", "degraded"}


def test_dashboard(client, device_id, alert_id):
    response = client.get("/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["status"]["device_count"] == 1
    assert body["status"]["open_alert_count"] == 1
    assert len(body["devices"]) == 1
    assert len(body["alerts"]) == 1
    assert "traffic" in body
    assert "inventory" in body


# ---------------------------------------------------------------------------
# devices
# ---------------------------------------------------------------------------


def test_get_devices_list(client, device_id):
    response = client.get("/devices")
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_get_device_detail_and_404(client, device_id):
    response = client.get(f"/devices/{device_id}")
    assert response.status_code == 200
    assert response.json()["id"] == device_id

    response = client.get("/devices/999999")
    assert response.status_code == 404


def test_update_device_authorization_happy_and_errors(client, device_id, auth_headers):
    response = client.patch(
        f"/devices/{device_id}/authorization", json={"state": 1}, headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["is_authorized"] == 1

    # Unknown device.
    response = client.patch(
        "/devices/999999/authorization", json={"state": 1}, headers=auth_headers
    )
    assert response.status_code == 404

    # Invalid state fails pydantic validation.
    response = client.patch(
        f"/devices/{device_id}/authorization", json={"state": 5}, headers=auth_headers
    )
    assert response.status_code == 422


def test_device_traffic_get_and_404(client, device_id):
    response = client.get(f"/devices/{device_id}/traffic")
    assert response.status_code == 200
    assert response.json() == []

    response = client.get("/devices/999999/traffic")
    assert response.status_code == 404


def test_device_trust_get_and_404(client, device_id):
    response = client.get(f"/devices/{device_id}/trust")
    assert response.status_code == 200
    body = response.json()
    assert "score" in body and "reasons" in body and "factors" in body

    response = client.get("/devices/999999/trust")
    assert response.status_code == 404


def test_device_policy_get_put_and_404(client, device_id, auth_headers):
    response = client.get(f"/devices/{device_id}/policy")
    assert response.status_code == 200
    assert response.json()["internet_enabled"] is True

    response = client.put(
        f"/devices/{device_id}/policy",
        json={"internet_enabled": False, "blocked_domains": ["ads.example.com"]},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json()["internet_enabled"] is False
    assert response.json()["blocked_domains"] == ["ads.example.com"]

    response = client.put(
        "/devices/999999/policy", json={"internet_enabled": True}, headers=auth_headers
    )
    assert response.status_code == 404

    # Malformed time triggers pydantic pattern validation.
    response = client.put(
        f"/devices/{device_id}/policy",
        json={"internet_enabled": True, "block_start": "not-a-time"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_device_findings_get_and_404(client, device_id):
    response = client.get(f"/devices/{device_id}/findings")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    response = client.get("/devices/999999/findings")
    assert response.status_code == 404


def test_inventory_summary(client, device_id):
    response = client.get("/inventory/summary")
    assert response.status_code == 200
    assert response.json()["total"] == 1


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------


def test_alerts_list(client, alert_id):
    response = client.get("/alerts")
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get("/alerts", params={"unresolved_only": True})
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_update_alert_happy_and_404(client, alert_id, auth_headers):
    response = client.patch(
        f"/alerts/{alert_id}", json={"resolved": True}, headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json() == {"id": alert_id, "is_resolved": True}

    response = client.patch(
        "/alerts/999999", json={"resolved": True}, headers=auth_headers
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# traffic
# ---------------------------------------------------------------------------


def test_traffic_list_and_summary(client, device_id, db_path):
    with models.get_conn(db_path) as conn:
        models.log_traffic(conn, device_id=device_id, domain="example.com", dest_ip="1.2.3.4")

    response = client.get("/traffic")
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get("/traffic", params={"device_id": device_id})
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get("/traffic/summary")
    assert response.status_code == 200
    assert response.json()["queries"] == 1


def test_observe_connection_private_ip_no_network(client, device_id, auth_headers):
    """Private-range destination IPs short-circuit threat_intel.check_ip before
    any network call is attempted, so this stays network-free."""
    response = client.post(
        "/traffic/observe",
        json={
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "bytes_sent": 10,
            "bytes_received": 20,
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["device_id"] == device_id
    assert body["threat_level"] == "none"
    assert body["reputation"]["malicious"] is False


def test_observe_connection_malicious_creates_alert(client, device_id, auth_headers, monkeypatch, db_path):
    def fake_check_ip(conn, ip):
        return Reputation(ip, "ip", True, 95, "abuseipdb", "known botnet C2")

    monkeypatch.setattr("backend.monitor.traffic_analyzer.check_ip", fake_check_ip)

    response = client.post(
        "/traffic/observe",
        json={"source_ip": "192.168.1.50", "destination_ip": "8.8.8.8"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["threat_level"] == "critical"
    assert body["reputation"]["malicious"] is True

    with models.get_conn(db_path) as conn:
        alerts = models.list_alerts(conn)
    assert any("8.8.8.8" in alert["title"] for alert in alerts)


def test_observe_connection_malformed_body(client, auth_headers):
    response = client.post("/traffic/observe", json={"source_ip": "1.2.3.4"}, headers=auth_headers)
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# trust / findings / audit
# ---------------------------------------------------------------------------


def test_trust_recalculate(client, device_id, auth_headers):
    response = client.post("/trust/recalculate", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert len(body["devices"]) == 1
    assert "household" in body


def test_findings(client, device_id):
    response = client.get("/findings")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_audit(client, device_id, auth_headers):
    response = client.post("/audit", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert "finding_count" in body
    assert body["finding_count"] == len(body["findings"])


# ---------------------------------------------------------------------------
# blocklists / dns
# ---------------------------------------------------------------------------


def test_blocklists_status(client, patched_blocklists):
    response = client.get("/blocklists")
    assert response.status_code == 200
    body = response.json()
    assert body["domain_count"] == patched_blocklists.count
    assert body["sources"] == []


def test_blocklists_update(client, patched_blocklists, auth_headers, monkeypatch):
    def fake_update(urls=None, timeout=30):
        return [UpdateResult("https://example.test/hosts", 3, "ok")]

    monkeypatch.setattr(patched_blocklists, "update", fake_update)

    response = client.post("/blocklists/update", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["sources"][0]["status"] == "ok"


def test_dns_stats_no_proxy(client, monkeypatch):
    monkeypatch.setattr(services, "dns_proxy", None)
    response = client.get("/dns/stats")
    assert response.status_code == 200
    assert response.json() == {"running": False, "cache": {}, "upstreams": {}}


class _FakeCache:
    def __init__(self):
        self.cleared = False

    def clear(self):
        self.cleared = True

    def stats(self):
        return {"size": 0, "cleared": self.cleared}


class _FakeDNSProxy:
    def __init__(self):
        self.cache = _FakeCache()

    def stats(self):
        return {"cache": self.cache.stats(), "upstreams": {}}


def test_dns_stats_with_proxy(client, monkeypatch):
    fake = _FakeDNSProxy()
    monkeypatch.setattr(services, "dns_proxy", fake)
    response = client.get("/dns/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["running"] is True
    assert "cache" in body and "upstreams" in body


def test_dns_cache_clear_no_proxy(client, auth_headers, monkeypatch):
    monkeypatch.setattr(services, "dns_proxy", None)
    response = client.post("/dns/cache/clear", headers=auth_headers)
    assert response.status_code == 503


def test_dns_cache_clear_with_proxy(client, auth_headers, monkeypatch):
    fake = _FakeDNSProxy()
    monkeypatch.setattr(services, "dns_proxy", fake)
    response = client.post("/dns/cache/clear", headers=auth_headers)
    assert response.status_code == 200
    assert fake.cache.cleared is True
    assert response.json()["cleared"] is True


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


def test_cisa_kev_get_empty(client):
    response = client.get("/threat-intel/cisa-kev")
    assert response.status_code == 200
    assert response.json() == []


def test_cisa_kev_update_success(client, auth_headers, monkeypatch):
    monkeypatch.setattr(api_routes, "update_catalog", lambda conn: 7)
    response = client.post("/threat-intel/cisa-kev/update", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["records"] == 7


def test_cisa_kev_update_failure(client, auth_headers, monkeypatch):
    def boom(conn):
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(api_routes, "update_catalog", boom)
    response = client.post("/threat-intel/cisa-kev/update", headers=auth_headers)
    assert response.status_code == 502


# ---------------------------------------------------------------------------
# settings / setup
# ---------------------------------------------------------------------------


def test_settings_get_patch_round_trip(client, auth_headers):
    response = client.get("/settings")
    assert response.status_code == 200
    assert "household_name" in response.json()

    response = client.patch(
        "/settings",
        json={"household_name": "Kristina's House", "notifications_enabled": False},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["household_name"] == "Kristina's House"
    assert body["notifications_enabled"] is False

    response = client.get("/settings")
    assert response.json()["household_name"] == "Kristina's House"


def test_setup_get_post_round_trip(client):
    response = client.get("/setup")
    assert response.status_code == 200
    assert response.json()["complete"] is False

    response = client.post(
        "/setup",
        json={
            "household_name": "Test Household",
            "digest_email": "family@example.com",
            "dns_upstream": "1.1.1.1",
            "notifications_enabled": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["complete"] is True
    assert response.json()["settings"]["setup_complete"] is True

    response = client.get("/setup")
    assert response.json()["complete"] is True

    # Missing required household_name.
    response = client.post("/setup", json={})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# backups
# ---------------------------------------------------------------------------


def test_backups_list_create_download_and_404(client, patched_backups, auth_headers):
    response = client.get("/backups")
    assert response.status_code == 200
    assert response.json()["backups"] == []

    response = client.post("/backups", headers=auth_headers)
    assert response.status_code == 200
    name = response.json()["backup"]["name"]

    response = client.get("/backups")
    assert len(response.json()["backups"]) == 1

    response = client.get(f"/backups/{name}", headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-sqlite3"

    response = client.get("/backups/does-not-exist.db", headers=auth_headers)
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# digest
# ---------------------------------------------------------------------------


def test_digest_preview(client):
    response = client.get("/digest/preview")
    assert response.status_code == 200
    body = response.json()
    assert "subject" in body and "body" in body


def test_digest_send_without_smtp_configured_returns_503(client, auth_headers):
    response = client.post("/digest/send", headers=auth_headers)
    assert response.status_code == 503


def test_digest_send_success(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        api_routes,
        "send_digest",
        lambda conn, recipient=None: {"sent": True, "recipient": recipient, "subject": "s"},
    )
    response = client.post("/digest/send", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["sent"] is True


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def test_scan_trigger(client, auth_headers, monkeypatch):
    monkeypatch.setattr(api_routes, "run_discovery_scan", lambda conn: [{"mac": "AA:BB"}])
    response = client.post("/scan", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["devices_found"] == 1


# ---------------------------------------------------------------------------
# pairing endpoints (over HTTP)
# ---------------------------------------------------------------------------


def test_pair_start_status_claim_round_trip(client):
    response = client.post("/pair/start")
    assert response.status_code == 200
    code = response.json()["code"]
    assert len(code) == 6

    response = client.get("/pair/status")
    assert response.status_code == 200
    assert response.json()["pending"] is True

    # Wrong code fails.
    wrong = "000000" if code != "000000" else "111111"
    response = client.post("/pair/claim", json={"code": wrong})
    assert response.status_code == 400

    # Right code succeeds.
    response = client.post("/pair/claim", json={"code": code})
    assert response.status_code == 200
    token = response.json()["token"]
    assert token

    # Single-use: claiming the same code again fails.
    response = client.post("/pair/claim", json={"code": code})
    assert response.status_code == 400


def test_pair_local_token_matches_claimed_token(client):
    response = client.post("/pair/start")
    code = response.json()["code"]
    claimed_token = client.post("/pair/claim", json={"code": code}).json()["token"]

    response = client.get("/pair/local-token")
    assert response.status_code == 200
    assert response.json()["token"] == claimed_token


def test_pair_regenerate_requires_token_and_invalidates_old(client, auth_headers, auth_token):
    response = client.post("/pair/regenerate")
    assert response.status_code == 401

    response = client.post("/pair/regenerate", headers=auth_headers)
    assert response.status_code == 200
    new_token = response.json()["token"]
    assert new_token != auth_token

    # Old token no longer works on a protected endpoint.
    response = client.post("/trust/recalculate", headers=auth_headers)
    assert response.status_code == 401

    # New token does work.
    response = client.post("/trust/recalculate", headers={"X-HomeRadar-Token": new_token})
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Auth matrix: endpoints that require a token vs. endpoints that stay open.
# ---------------------------------------------------------------------------

AUTH_REQUIRED_ENDPOINTS = [
    "device_authorization",
    "device_policy",
    "alert_update",
    "traffic_observe",
    "trust_recalculate",
    "audit",
    "blocklists_update",
    "dns_cache_clear",
    "settings_patch",
    "backups_create",
    "backups_download",
    "cisa_kev_update",
    "digest_send",
    "scan",
    "pair_regenerate",
]


@pytest.fixture
def auth_matrix_context(client, db_path, patched_backups, patched_blocklists, monkeypatch):
    """Seed everything the auth-required endpoints need and stub out anything
    that would otherwise touch the network, SMTP, or a real ARP/mDNS scan."""
    with models.get_conn(db_path) as conn:
        seeded_device_id = models.upsert_device(
            conn,
            mac="AA:BB:CC:DD:EE:02",
            ip="192.168.1.60",
            hostname="auth-host",
            vendor="Vendor",
            device_type="computer",
            confidence=0.5,
        )
        seeded_alert_id = models.create_alert(conn, seeded_device_id, "warning", "Auth matrix alert")

    backup = maintenance.create_backup()

    monkeypatch.setattr(api_routes, "update_catalog", lambda conn: 0)
    monkeypatch.setattr(api_routes, "run_discovery_scan", lambda conn: [])
    monkeypatch.setattr(
        api_routes,
        "send_digest",
        lambda conn, recipient=None: {"sent": True, "recipient": recipient, "subject": "x"},
    )
    monkeypatch.setattr(patched_blocklists, "update", lambda *a, **k: [])
    monkeypatch.setattr(services, "dns_proxy", _FakeDNSProxy())

    return {
        "device_id": seeded_device_id,
        "alert_id": seeded_alert_id,
        "backup_name": backup.name,
    }


def _auth_matrix_request(client, headers, context, name):
    device_id = context["device_id"]
    alert_id = context["alert_id"]
    backup_name = context["backup_name"]
    if name == "device_authorization":
        return client.patch(
            f"/devices/{device_id}/authorization", json={"state": 1}, headers=headers
        )
    if name == "device_policy":
        return client.put(
            f"/devices/{device_id}/policy", json={"internet_enabled": False}, headers=headers
        )
    if name == "alert_update":
        return client.patch(f"/alerts/{alert_id}", json={"resolved": True}, headers=headers)
    if name == "traffic_observe":
        return client.post(
            "/traffic/observe",
            json={"source_ip": "192.168.1.60", "destination_ip": "192.168.1.1"},
            headers=headers,
        )
    if name == "trust_recalculate":
        return client.post("/trust/recalculate", headers=headers)
    if name == "audit":
        return client.post("/audit", headers=headers)
    if name == "blocklists_update":
        return client.post("/blocklists/update", headers=headers)
    if name == "dns_cache_clear":
        return client.post("/dns/cache/clear", headers=headers)
    if name == "settings_patch":
        return client.patch("/settings", json={"household_name": "Auth Test"}, headers=headers)
    if name == "backups_create":
        return client.post("/backups", headers=headers)
    if name == "backups_download":
        return client.get(f"/backups/{backup_name}", headers=headers)
    if name == "cisa_kev_update":
        return client.post("/threat-intel/cisa-kev/update", headers=headers)
    if name == "digest_send":
        return client.post("/digest/send", headers=headers)
    if name == "scan":
        return client.post("/scan", headers=headers)
    if name == "pair_regenerate":
        return client.post("/pair/regenerate", headers=headers)
    raise ValueError(f"unhandled endpoint name: {name}")


@pytest.mark.parametrize("name", AUTH_REQUIRED_ENDPOINTS)
def test_protected_endpoints_reject_missing_token(client, auth_matrix_context, name):
    response = _auth_matrix_request(client, {}, auth_matrix_context, name)
    assert response.status_code == 401


@pytest.mark.parametrize("name", AUTH_REQUIRED_ENDPOINTS)
def test_protected_endpoints_accept_valid_token(client, auth_matrix_context, auth_headers, name):
    response = _auth_matrix_request(client, auth_headers, auth_matrix_context, name)
    assert response.status_code != 401


OPEN_ENDPOINTS = [
    ("GET", "/status"),
    ("GET", "/devices"),
    ("GET", "/alerts"),
    ("GET", "/setup"),
    ("POST", "/pair/start"),
    ("GET", "/pair/status"),
]


@pytest.mark.parametrize("method,path", OPEN_ENDPOINTS)
def test_open_endpoints_require_no_auth(client, method, path):
    """Regression guard: these must keep working with zero auth headers."""
    response = client.request(method, path)
    assert response.status_code == 200
