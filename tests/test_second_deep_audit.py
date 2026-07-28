"""Regression coverage for defects found during the second full-code audit."""
from __future__ import annotations

import pytest

from backend.db import models
from backend.dns.blocklists import BlocklistManager
from backend.dns.proxy import DNSProxy


@pytest.fixture
def device_id(db_path):
    with models.get_conn(db_path) as conn:
        return models.upsert_device(
            conn,
            mac="AA:BB:CC:DD:EE:99",
            ip="192.168.1.99",
            hostname="second-audit-device",
            vendor="Test Vendor",
        )


def test_main_application_does_not_publish_openapi_schema():
    from backend.main import app

    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_api_rejects_unbounded_query_parameters(client, device_id):
    assert client.get(f"/devices/{device_id}/traffic", params={"limit": 0}).status_code == 422
    assert client.get("/traffic", params={"limit": 1001}).status_code == 422
    assert client.get("/traffic/summary", params={"hours": 0}).status_code == 422
    assert client.get("/traffic/summary", params={"hours": 8761}).status_code == 422
    assert client.get("/threat-intel/cisa-kev", params={"limit": 0}).status_code == 422
    assert client.get("/threat-intel/cisa-kev", params={"query": "x" * 201}).status_code == 422


def test_connection_observation_rejects_invalid_ip_addresses(client, auth_headers):
    response = client.post(
        "/traffic/observe",
        json={"source_ip": "not-an-ip", "destination_ip": "192.168.1.1"},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_device_policy_rejects_impossible_times_and_invalid_domains(
    client, device_id, auth_headers
):
    response = client.put(
        f"/devices/{device_id}/policy",
        json={"block_start": "99:99", "block_end": "07:00"},
        headers=auth_headers,
    )
    assert response.status_code == 422

    response = client.put(
        f"/devices/{device_id}/policy",
        json={"blocked_domains": ["localhost"]},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_device_policy_normalizes_and_deduplicates_domains(client, device_id, auth_headers):
    response = client.put(
        f"/devices/{device_id}/policy",
        json={
            "block_start": "22:30",
            "block_end": "07:00:00",
            "blocked_domains": ["Ads.Example.COM.", "ads.example.com"],
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["block_start"] == "22:30:00"
    assert body["block_end"] == "07:00:00"
    assert body["blocked_domains"] == ["ads.example.com"]


def test_settings_reject_invalid_dns_configuration(client, auth_headers):
    response = client.patch(
        "/settings", json={"dns_upstream": "not-an-ip"}, headers=auth_headers
    )
    assert response.status_code == 422

    response = client.patch(
        "/settings", json={"custom_dns_records": "not json"}, headers=auth_headers
    )
    assert response.status_code == 422

    response = client.patch(
        "/settings",
        json={"custom_dns_records": '{"localhost":"192.168.1.10"}'},
        headers=auth_headers,
    )
    assert response.status_code == 422

    response = client.patch(
        "/settings",
        json={"custom_dns_records": '{"router.example":"999.1.1.1"}'},
        headers=auth_headers,
    )
    assert response.status_code == 422


def test_settings_normalize_valid_dns_configuration(client, auth_headers):
    response = client.patch(
        "/settings",
        json={
            "dns_upstream": "1.1.1.1, 1.1.1.1, 2606:4700:4700::1111",
            "custom_dns_records": '{"Router.Example.":"192.168.1.1"}',
        },
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["dns_upstream"] == "1.1.1.1,2606:4700:4700::1111"
    assert body["custom_dns_records"] == '{"router.example":"192.168.1.1"}'


def test_pair_claim_requires_exactly_six_digits(client):
    assert client.post("/pair/claim", json={"code": "12345"}).status_code == 422
    assert client.post("/pair/claim", json={"code": "1234567"}).status_code == 422
    assert client.post("/pair/claim", json={"code": "12A456"}).status_code == 422


class _BindFailureSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def setsockopt(self, *args):
        return None

    def bind(self, address):
        raise OSError("address already in use")

    def close(self):
        return None


def test_dns_proxy_reports_listener_bind_failure(monkeypatch, tmp_path):
    proxy = DNSProxy(
        BlocklistManager(tmp_path / "blocklist.txt"),
        host="127.0.0.1",
        port=53535,
        dynamic_upstream=False,
    )
    monkeypatch.setattr("backend.dns.proxy.socket.socket", lambda *args, **kwargs: _BindFailureSocket())

    proxy.serve_forever()

    assert proxy.wait_until_ready(0.01) is False
    stats = proxy.stats()
    assert stats["running"] is False
    assert stats["listeners"]["udp"] is False
    assert "address already in use" in stats["listeners"]["errors"]["udp"]
    proxy.stop()
