"""Regression tests for bugs found in the pre-submission QA pass."""
from __future__ import annotations

import ssl
import urllib.error

import pytest
from dnslib import A, DNSRecord, EDNS0, QTYPE, RCODE, RR
from fastapi.testclient import TestClient

from backend import config
from backend.db import models
from backend.dns import blocklists as blocklists_module
from backend.dns.blocklists import BlocklistManager, UpdateResult, summarize_update
from backend.dns.cache import DNSCache, cache_key
from backend.dns.proxy import (
    DNSProxy,
    normalize_custom_records,
    truncate_for_udp,
    udp_size_limit,
)
from backend.security import demo_denies

REMOTE = ("203.0.113.7", 50000)


# --- WebSocket snapshot -------------------------------------------------------

def test_snapshot_status_keeps_dns_and_blocklist_fields(patched_db, patched_blocklists, monkeypatch):
    from backend.api.websocket import dashboard_snapshot

    patched_blocklists.replace({"malware.example", "tracker.example"})
    monkeypatch.setattr(config, "DNS_ENABLED", True)
    status = dashboard_snapshot()["status"]
    assert status["blocklist_domains"] == 2
    assert status["dns_enabled"] is True


# --- Upstreams ----------------------------------------------------------------

def test_upstreams_accept_comma_separated_setting(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "1.1.1.1, 9.9.9.9,not-an-ip"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "b.txt"), upstream=("8.8.8.8", 53))
    assert sorted(address for address, _ in proxy._upstreams()) == ["1.1.1.1", "9.9.9.9"]


# --- UDP truncation -----------------------------------------------------------

def _big_response(request: DNSRecord, answers: int = 60) -> bytes:
    reply = request.reply()
    for index in range(answers):
        reply.add_answer(RR("many.example", QTYPE.A, ttl=60, rdata=A(f"10.0.{index // 250}.{index % 250}")))
    return reply.pack()


def test_oversized_reply_to_classic_client_is_truncated():
    request = DNSRecord.question("many.example", "A")
    response = _big_response(request)
    assert len(response) > 512
    truncated = DNSRecord.parse(truncate_for_udp(request.pack(), response))
    assert truncated.header.tc == 1
    assert truncated.rr == []
    assert truncated.header.rcode == RCODE.NOERROR
    assert truncated.header.id == request.header.id


def test_edns_client_buffer_size_is_respected():
    request = DNSRecord.question("many.example", "A")
    request.add_ar(EDNS0(udp_len=4096))
    assert udp_size_limit(request.pack()) == 4096
    response = _big_response(request)
    assert truncate_for_udp(request.pack(), response) == response


def test_small_reply_is_untouched():
    request = DNSRecord.question("one.example", "A")
    reply = request.reply()
    reply.add_answer(RR("one.example", QTYPE.A, ttl=60, rdata=A("10.0.0.1")))
    assert truncate_for_udp(request.pack(), reply.pack()) == reply.pack()


# --- Custom DNS records -------------------------------------------------------

def test_custom_record_keys_are_normalized():
    records = normalize_custom_records('{"NAS.Home.": "192.168.1.10", "bad": "nope", "x": 3}')
    assert records == {"nas.home": "192.168.1.10"}
    assert normalize_custom_records("not json {") == {}
    assert normalize_custom_records('["a"]') == {}


def test_custom_record_answers_case_and_trailing_dot(tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "b.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("nas.home", "A").pack()
    reply = DNSRecord.parse(proxy._check_custom_dns(payload, '{"NAS.Home.": "192.168.1.10"}'))
    assert str(reply.rr[0].rdata) == "192.168.1.10"


@pytest.mark.parametrize("qtype", ["AAAA", "MX", "TXT"])
def test_custom_record_wrong_type_is_nodata_not_forwarded(tmp_path, qtype):
    proxy = DNSProxy(BlocklistManager(tmp_path / "b.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("nas.home", qtype).pack()
    reply = DNSRecord.parse(proxy._check_custom_dns(payload, '{"nas.home": "192.168.1.10"}'))
    assert reply.header.rcode == RCODE.NOERROR
    assert reply.rr == []


def test_unknown_name_falls_through_to_upstream(tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "b.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("other.home", "A").pack()
    assert proxy._check_custom_dns(payload, '{"nas.home": "192.168.1.10"}') is None


# --- Policy blocks ------------------------------------------------------------

def test_paused_device_gets_nxdomain_not_refused(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        device_id = models.upsert_device(conn, mac="AA:BB:CC:00:00:99", ip="10.0.0.99", hostname=None, vendor=None)
        models.set_device_policy(conn, device_id, internet_enabled=False)
    proxy = DNSProxy(BlocklistManager(tmp_path / "b.txt"), dynamic_upstream=False)
    response = proxy._process(DNSRecord.question("any.example", "A").pack(), "10.0.0.99")
    assert DNSRecord.parse(response).header.rcode == RCODE.NXDOMAIN


# --- Blocklist updates --------------------------------------------------------

class _FakeResponse:
    def __init__(self, text: str):
        self._text = text.encode()

    def read(self, _limit: int) -> bytes:
        return self._text

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(sources: dict):
    def fake(request, timeout, context):
        outcome = sources[request.full_url]
        if isinstance(outcome, Exception):
            raise outcome
        return _FakeResponse(outcome)

    return fake


def test_partial_failure_keeps_previous_domains(tmp_path, monkeypatch):
    manager = BlocklistManager(tmp_path / "blocklist.txt")
    manager.replace({"old-a.example", "old-b.example"})
    good, bad = "https://good.example/list", "https://bad.example/list"
    monkeypatch.setattr(
        blocklists_module.urllib.request,
        "urlopen",
        _fake_urlopen({good: "new.example\n", bad: urllib.error.URLError("Tunnel connection failed")}),
    )
    results = manager.update([good, bad])
    assert manager.is_blocked("new.example")
    assert manager.is_blocked("old-a.example")
    failed = next(result for result in results if result.status == "error")
    assert failed.friendly_error == "Couldn't reach bad.example. Check the internet connection."
    assert "Tunnel connection failed" in failed.error


def test_all_sources_failing_keeps_list_untouched(tmp_path, monkeypatch):
    manager = BlocklistManager(tmp_path / "blocklist.txt")
    manager.replace({"old.example"})
    source = "https://down.example/list"
    monkeypatch.setattr(
        blocklists_module.urllib.request, "urlopen", _fake_urlopen({source: OSError("timed out")})
    )
    results = manager.update([source])
    assert manager.count == 1
    summary = summarize_update(results, manager.count)
    assert summary["ok"] is False
    assert "previous list" in summary["message"]
    assert summary["sources"][0]["error_friendly"].startswith("Couldn't reach down.example")
    assert summary["sources"][0]["error_detail"] == "timed out"


def test_http_and_bad_url_errors_are_friendly():
    http_error = urllib.error.HTTPError("https://x.example/l", 404, "Not Found", None, None)
    assert "HTTP 404" in blocklists_module.friendly_update_error("https://x.example/l", http_error)
    assert "HTTPS" in blocklists_module.friendly_update_error("ftp://x", ValueError("bad"))


def test_successful_update_summary():
    results = [UpdateResult("https://a.example/l", 10, "ok")]
    summary = summarize_update(results, 10)
    assert summary["ok"] is True
    assert summary["sources"][0]["ok"] is True
    assert "Blocking 10 known bad domains" in summary["message"]


# --- DNS cache ----------------------------------------------------------------

def test_cache_preserves_edns_flags(monkeypatch):
    cache = DNSCache()
    request = DNSRecord.question("signed.example", "A")
    reply = request.reply()
    reply.add_answer(RR("signed.example", QTYPE.A, ttl=300, rdata=A("10.0.0.1")))
    reply.add_ar(EDNS0(flags="do", udp_len=1232))
    key = cache_key(request.pack())
    assert cache.put(key, reply.pack())
    cached = DNSRecord.parse(cache.get(key, 1234))
    opt = next(record for record in cached.ar if record.rtype == QTYPE.OPT)
    assert opt.ttl == 0x8000  # DNSSEC OK bit intact
    assert cached.rr[0].ttl <= 300


def test_cache_clear_resets_counters():
    cache = DNSCache()
    cache.get(("x", 1, 1), 1)
    assert cache.stats()["misses"] == 1
    cache.clear()
    assert cache.stats()["hits"] == 0 and cache.stats()["misses"] == 0


# --- Email digest TLS ---------------------------------------------------------

def test_digest_starttls_uses_certifi_context(patched_db, db_path, monkeypatch):
    from backend.alerts import email_digest

    used = {}

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context):
            used["context"] = context

        def login(self, *args):
            pass

        def send_message(self, message):
            used["sent"] = True

    sentinel = ssl.create_default_context()
    monkeypatch.setattr(email_digest, "https_context", lambda: sentinel)
    monkeypatch.setattr(email_digest.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example")
    monkeypatch.setattr(config, "SMTP_FROM", "radar@example.com")
    monkeypatch.setattr(config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(config, "SMTP_USERNAME", "")
    with models.get_conn(db_path) as conn:
        email_digest.send_digest(conn, "family@example.com")
    assert used["context"] is sentinel and used["sent"]


# --- OUI fallback table -------------------------------------------------------

def test_fallback_oui_entries_match_ieee_registry():
    from backend.discovery.oui_lookup import _FALLBACK_OUI

    assert _FALLBACK_OUI["A0:02:DC"] == "Amazon"
    assert _FALLBACK_OUI["B0:C5:54"] == "D-Link"
    assert _FALLBACK_OUI["EC:B5:FA"] == "Philips (Hue)"
    assert "70:88:6B" not in _FALLBACK_OUI


# --- Security: /habits and public demo mode -----------------------------------

def test_habits_routes_require_pairing_for_remote_clients(app, monkeypatch):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", False)
    with TestClient(app, client=REMOTE) as remote:
        assert remote.get("/habits/summary").status_code == 401


def test_remote_visitor_blocked_without_demo_mode(app, monkeypatch):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", False)
    with TestClient(app, client=REMOTE) as remote:
        assert remote.get("/dashboard").status_code == 401
        assert remote.get("/pair/local-token").status_code == 403


def test_public_demo_lets_remote_visitors_use_the_dashboard(app, monkeypatch):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    with TestClient(app, client=REMOTE) as remote:
        assert remote.get("/dashboard").status_code == 200
        token = remote.get("/pair/local-token").json()["token"]
        response = remote.post(
            "/demo/simulate-attack", json={"kind": "deauth"}, headers={"X-HomeRadar-Token": token}
        )
        assert response.status_code == 200
        with remote.websocket_connect(f"/ws?token={token}") as socket:
            assert socket.receive_json()["type"] == "snapshot"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/pair/regenerate"),
        ("POST", "/pair/start"),
        ("PATCH", "/settings"),
        ("GET", "/backups"),
        ("POST", "/backups"),
        ("GET", "/backups/homeradar.db"),
        ("POST", "/digest/send"),
        ("POST", "/blocklists/update"),
        ("POST", "/threat-intel/cisa-kev/update"),
    ],
)
def test_public_demo_keeps_sensitive_actions_off_for_remote_visitors(app, monkeypatch, auth_headers, method, path):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    assert demo_denies(method, path)
    with TestClient(app, client=REMOTE) as remote:
        response = remote.request(method, path, headers=auth_headers, json={})
        assert response.status_code == 403
        assert "public demo" in response.json()["detail"]


def test_public_demo_does_not_restrict_the_appliance_itself(client, monkeypatch, auth_headers):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    assert client.get("/backups", headers=auth_headers).status_code != 403
    assert not demo_denies("GET", "/dashboard")


# --- DNS listener failure is visible ------------------------------------------

def test_listener_bind_failure_is_recorded(tmp_path):
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        port = occupied.getsockname()[1]
        proxy = DNSProxy(
            BlocklistManager(tmp_path / "b.txt"), host="127.0.0.1", port=port, dynamic_upstream=False
        )
        proxy.serve_forever()  # returns immediately instead of dying silently
    assert proxy.failure is not None
    assert str(port) in proxy.failure
