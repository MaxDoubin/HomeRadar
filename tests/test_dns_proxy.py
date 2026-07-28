import socket
import threading
import time

import pytest
from dnslib import A, DNSRecord, QTYPE, RCODE, RR

from backend import config
from backend.db import models
from backend.dns.blocklists import BlocklistManager
from backend.dns.cache import cache_key
from backend.dns.proxy import (
    DNSProxy,
    blocked_response,
    client_is_allowed,
    error_response,
    inspect_query,
)


def _valid_answer(query_payload: bytes, ttl: int = 60) -> bytes:
    request = DNSRecord.parse(query_payload)
    reply = request.reply()
    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("203.0.113.10"), ttl=ttl))
    return reply.pack()


def _truncated_response(query_payload: bytes) -> bytes:
    request = DNSRecord.parse(query_payload)
    reply = request.reply()
    reply.header.tc = 1
    return reply.pack()


class _FakeUDPSocket:
    def __init__(self, sendto_raises=None, recvfrom_raises=None, recv_response=None):
        self.sendto_raises = sendto_raises
        self.recvfrom_raises = recvfrom_raises
        self.recv_response = recv_response
        self.sent = []

    def settimeout(self, value):
        pass

    def sendto(self, data, address):
        if self.sendto_raises:
            raise self.sendto_raises
        self.sent.append((data, address))

    def recvfrom(self, bufsize):
        if self.recvfrom_raises:
            raise self.recvfrom_raises
        return self.recv_response, ("upstream", 0)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _socket_queue_factory(sockets):
    iterator = iter(sockets)

    def _factory(*args, **kwargs):
        return next(iterator)

    return _factory


def _insert_device(db_path, mac, ip, is_authorized=0):
    with models.get_conn(db_path) as conn:
        device_id = models.upsert_device(conn, mac=mac, ip=ip, hostname=None, vendor=None)
        if is_authorized:
            models.set_device_authorization(conn, device_id, is_authorized)
    return device_id


def test_inspect_query_attributes_and_blocks(tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malware.example\n")
    manager = BlocklistManager(blocklist_path)
    decision = inspect_query(DNSRecord.question("cdn.malware.example", "A").pack(), manager)
    assert decision.domain == "cdn.malware.example"
    assert decision.query_type == "A"
    assert decision.blocked is True


def test_blocked_and_error_responses_preserve_transaction_id():
    request = DNSRecord.question("malware.example", "AAAA")
    blocked = DNSRecord.parse(blocked_response(request.pack()))
    refused = DNSRecord.parse(error_response(request.pack(), RCODE.REFUSED))
    assert blocked.header.id == refused.header.id == request.header.id
    assert blocked.header.rcode == RCODE.NXDOMAIN
    assert refused.header.rcode == RCODE.REFUSED


def test_client_allowlist_rejects_public_sources_by_default(monkeypatch):
    monkeypatch.setattr(config, "DNS_ALLOW_PUBLIC_CLIENTS", False)
    assert client_is_allowed("127.0.0.1")
    assert client_is_allowed("192.168.1.50")
    assert client_is_allowed("10.0.0.5")
    assert client_is_allowed("100.64.1.2")
    assert client_is_allowed("fe80::1")
    assert not client_is_allowed("8.8.8.8")
    assert not client_is_allowed("not-an-ip")


def test_public_source_override_is_explicit(monkeypatch):
    monkeypatch.setattr(config, "DNS_ALLOW_PUBLIC_CLIENTS", True)
    assert client_is_allowed("8.8.8.8")


def test_tcp_receive_exact_handles_fragmented_stream():
    left, right = socket.socketpair()
    try:
        right.sendall(b"ab")
        right.sendall(b"cdef")
        assert DNSProxy._receive_exact(left, 6) == b"abcdef"
    finally:
        left.close()
        right.close()


def test_upstreams_prefers_valid_saved_setting(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "bad,9.9.9.9,8.8.4.4"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    assert [item[0] for item in proxy._upstreams()] == ["9.9.9.9", "8.8.4.4"]


def test_static_upstream_mode_never_touches_database(monkeypatch, tmp_path):
    def _boom():
        raise AssertionError("database should not be used")

    monkeypatch.setattr("backend.dns.proxy.get_conn", _boom)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    assert proxy._upstreams() == [proxy.upstream]


def test_upstreams_sort_by_failures_then_latency(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "1.2.3.1,1.2.3.2,1.2.3.3"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    proxy._upstream_stats["1.2.3.1"] = {"queries": 1, "failures": 2, "latency_ms": 5.0}
    proxy._upstream_stats["1.2.3.2"] = {"queries": 1, "failures": 0, "latency_ms": 50.0}
    proxy._upstream_stats["1.2.3.3"] = {"queries": 1, "failures": 0, "latency_ms": 10.0}
    assert [item[0] for item in proxy._upstreams()] == ["1.2.3.3", "1.2.3.2", "1.2.3.1"]


def test_forward_fails_over_and_tracks_health(monkeypatch, patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "10.0.0.1,10.0.0.2"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    payload = DNSRecord.question("example.com", "A").pack()
    answer = _valid_answer(payload)
    sockets = [
        _FakeUDPSocket(recvfrom_raises=OSError("refused")),
        _FakeUDPSocket(recv_response=answer),
    ]
    monkeypatch.setattr("backend.dns.proxy.socket.socket", _socket_queue_factory(sockets))
    assert proxy._forward(payload) == answer
    stats = proxy.stats()["upstreams"]
    assert stats["10.0.0.1"]["failures"] == 1
    assert stats["10.0.0.2"]["failures"] == 0


def test_forward_uses_tcp_for_truncated_udp(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("example.com", "A").pack()
    answer = _valid_answer(payload)
    monkeypatch.setattr(
        "backend.dns.proxy.socket.socket",
        _socket_queue_factory([_FakeUDPSocket(recv_response=_truncated_response(payload))]),
    )
    calls = []
    monkeypatch.setattr(proxy, "_forward_tcp", lambda p, upstream: calls.append(upstream) or answer)
    assert proxy._forward(payload) == answer
    assert calls == [proxy.upstream]


def test_resolve_cache_hit_never_calls_forward(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("cached.example", "A").pack()
    proxy.cache.put(cache_key(payload), _valid_answer(payload))
    monkeypatch.setattr(proxy, "_forward", lambda p: (_ for _ in ()).throw(AssertionError()))
    assert DNSRecord.parse(proxy._resolve(payload)).header.rcode == RCODE.NOERROR


def test_resolve_coalesces_identical_concurrent_queries(tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    call_count = 0
    lock = threading.Lock()

    def fake_forward(payload):
        nonlocal call_count
        with lock:
            call_count += 1
        time.sleep(0.15)
        return _valid_answer(payload)

    proxy._forward = fake_forward
    results = [None, None]

    def run(index):
        results[index] = proxy._resolve(DNSRecord.question("shared.example", "A").pack())

    first = threading.Thread(target=run, args=(0,))
    second = threading.Thread(target=run, args=(1,))
    first.start()
    time.sleep(0.03)
    second.start()
    first.join(timeout=5)
    second.join(timeout=5)
    assert call_count == 1
    assert all(result is not None for result in results)


def test_process_refuses_household_blocked_device(patched_db, db_path, tmp_path):
    _insert_device(db_path, "AA:BB:CC:DD:EE:01", "10.0.0.5", is_authorized=2)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    response = proxy._process(DNSRecord.question("clean.example", "A").pack(), "10.0.0.5")
    assert DNSRecord.parse(response).header.rcode == RCODE.REFUSED


def test_process_blocks_domain_and_creates_alert(patched_db, db_path, tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malware.example\n")
    proxy = DNSProxy(BlocklistManager(blocklist_path), dynamic_upstream=False)
    response = proxy._process(DNSRecord.question("malware.example", "A").pack(), "10.0.0.9")
    assert DNSRecord.parse(response).header.rcode == RCODE.NXDOMAIN
    with models.get_conn(db_path) as conn:
        assert any("malware.example" in alert["title"] for alert in models.list_alerts(conn))


def test_process_allows_clean_domain_and_logs(monkeypatch, patched_db, db_path, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("clean.example", "A").pack()
    answer = _valid_answer(payload)
    monkeypatch.setattr(proxy, "_resolve", lambda p: answer)
    assert proxy._process(payload, "10.0.0.7") == answer
    with models.get_conn(db_path) as conn:
        assert models.list_traffic(conn)[0]["was_blocked"] == 0


def test_logging_failure_never_reverses_block_decision(monkeypatch, patched_db, tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malware.example\n")
    proxy = DNSProxy(BlocklistManager(blocklist_path), dynamic_upstream=False)
    payload = DNSRecord.question("malware.example", "A").pack()
    monkeypatch.setattr(models, "log_traffic", lambda *args, **kwargs: (_ for _ in ()).throw(sqlite_error()))
    monkeypatch.setattr(proxy, "_forward", lambda p: (_ for _ in ()).throw(AssertionError("must not forward")))
    response = proxy._process(payload, "10.0.0.9")
    assert DNSRecord.parse(response).header.rcode == RCODE.NXDOMAIN


def sqlite_error():
    import sqlite3

    return sqlite3.OperationalError("database is busy")


def test_inspection_failure_returns_formerr_not_upstream_answer(monkeypatch, patched_db, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("oops.example", "A").pack()
    monkeypatch.setattr("backend.dns.proxy.inspect_query", lambda *args: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(proxy, "_forward", lambda p: (_ for _ in ()).throw(AssertionError("must not forward")))
    response = proxy._process(payload, "10.0.0.8")
    assert DNSRecord.parse(response).header.rcode == RCODE.FORMERR


def test_policy_database_failure_returns_servfail(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("example.com", "A").pack()
    monkeypatch.setattr("backend.dns.proxy.get_conn", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    response = proxy._process(payload, "10.0.0.8")
    assert DNSRecord.parse(response).header.rcode == RCODE.SERVFAIL


def test_upstream_failure_returns_servfail(monkeypatch, patched_db, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("example.com", "A").pack()
    monkeypatch.setattr(proxy, "_resolve", lambda p: (_ for _ in ()).throw(OSError("offline")))
    response = proxy._process(payload, "10.0.0.8")
    assert DNSRecord.parse(response).header.rcode == RCODE.SERVFAIL


def test_malformed_packet_is_dropped_without_forwarding(monkeypatch, patched_db, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    monkeypatch.setattr(proxy, "_forward", lambda p: (_ for _ in ()).throw(AssertionError("must not forward")))
    assert proxy._process(b"not-dns", "10.0.0.8") is None


def test_public_client_receives_refused(monkeypatch, patched_db, tmp_path):
    monkeypatch.setattr(config, "DNS_ALLOW_PUBLIC_CLIENTS", False)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("example.com", "A").pack()
    response = proxy._process(payload, "8.8.8.8")
    assert DNSRecord.parse(response).header.rcode == RCODE.REFUSED


def test_udp_handle_sends_selected_response(monkeypatch, tmp_path, fake_socket_factory):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    monkeypatch.setattr(proxy, "_process", lambda payload, ip: b"response")
    proxy._socket = fake_socket_factory()
    proxy._handle(b"query", ("10.0.0.1", 5353))
    assert proxy._socket.sent == [(b"response", ("10.0.0.1", 5353))]


def test_tcp_round_trip_uses_length_prefixed_framing(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    request_payload = DNSRecord.question("example.com", "A").pack()
    response_payload = _valid_answer(request_payload)
    monkeypatch.setattr(proxy, "_process", lambda payload, ip: response_payload)
    left, right = socket.socketpair()
    try:
        right.sendall(len(request_payload).to_bytes(2, "big") + request_payload)
        proxy._handle_tcp(left, "127.0.0.1")
        size = int.from_bytes(right.recv(2), "big")
        assert right.recv(size) == response_payload
    finally:
        right.close()
