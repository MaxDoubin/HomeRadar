import socket
import threading
import time

import pytest
from dnslib import RR, A, DNSRecord, QTYPE, RCODE

from backend.db import models
from backend.dns.blocklists import BlocklistManager
from backend.dns.cache import cache_key
from backend.dns.proxy import DNSProxy, blocked_response, error_response, inspect_query


def _valid_answer(query_payload: bytes, ttl: int = 60) -> bytes:
    """Build a well-formed NOERROR response with one A record for a query."""
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
    """Stand-in for `socket.socket(AF_INET, SOCK_DGRAM)` used inside `_forward`."""

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
    request = DNSRecord.question("cdn.malware.example", "A").pack()
    decision = inspect_query(request, manager)
    assert decision.domain == "cdn.malware.example"
    assert decision.query_type == "A"
    assert decision.blocked is True


def test_blocked_response_preserves_id_and_returns_nxdomain():
    request = DNSRecord.question("malware.example", "AAAA")
    response = DNSRecord.parse(blocked_response(request.pack()))
    assert response.header.id == request.header.id
    assert response.header.rcode == RCODE.NXDOMAIN
    assert response.q.qtype == QTYPE.AAAA


def test_error_response_can_refuse_household_blocked_device():
    request = DNSRecord.question("example.com", "A")
    response = DNSRecord.parse(error_response(request.pack(), RCODE.REFUSED))
    assert response.header.rcode == RCODE.REFUSED


def test_tcp_receive_exact_handles_fragmented_stream():
    left, right = socket.socketpair()
    try:
        right.sendall(b"ab")
        right.sendall(b"cdef")
        assert DNSProxy._receive_exact(left, 6) == b"abcdef"
    finally:
        left.close()
        right.close()


# ---------------------------------------------------------------------------
# _upstreams()
# ---------------------------------------------------------------------------

def test_upstreams_prefers_db_setting_over_static_config(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "9.9.9.9,8.8.4.4"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    upstreams = proxy._upstreams()
    assert [item[0] for item in upstreams] == ["9.9.9.9", "8.8.4.4"]


def test_upstreams_ignores_invalid_ip_strings(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "not-an-ip,8.8.8.8,also bad"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    upstreams = proxy._upstreams()
    assert [item[0] for item in upstreams] == ["8.8.8.8"]


def test_upstreams_falls_back_to_static_config_without_setting_row(patched_db, tmp_path):
    from backend import config

    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    upstreams = proxy._upstreams()
    assert [item[0] for item in upstreams] == list(config.DNS_UPSTREAMS)


def test_upstreams_static_mode_never_touches_db(monkeypatch, tmp_path):
    """dynamic_upstream=False must not query the DB at all."""

    def _boom():
        raise AssertionError("get_conn should not be called when dynamic_upstream=False")

    monkeypatch.setattr("backend.dns.proxy.get_conn", _boom)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    upstreams = proxy._upstreams()
    assert upstreams == [proxy.upstream]


def test_upstreams_sorted_by_failures_then_latency(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "1.2.3.1,1.2.3.2,1.2.3.3"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    proxy._upstream_stats["1.2.3.1"] = {"queries": 1, "failures": 2, "latency_ms": 5.0}
    proxy._upstream_stats["1.2.3.2"] = {"queries": 1, "failures": 0, "latency_ms": 50.0}
    proxy._upstream_stats["1.2.3.3"] = {"queries": 1, "failures": 0, "latency_ms": 10.0}
    ordered = [item[0] for item in proxy._upstreams()]
    assert ordered == ["1.2.3.3", "1.2.3.2", "1.2.3.1"]


# ---------------------------------------------------------------------------
# _record_upstream()
# ---------------------------------------------------------------------------

def test_record_upstream_tracks_failures(tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    proxy._record_upstream("1.1.1.1", None)
    stats = proxy.stats()["upstreams"]["1.1.1.1"]
    assert stats["queries"] == 1
    assert stats["failures"] == 1
    assert stats["latency_ms"] == 0.0


def test_record_upstream_success_resets_failure_and_computes_ema(tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    proxy._record_upstream("1.1.1.1", None)
    proxy._record_upstream("1.1.1.1", 0.05)
    stats = proxy.stats()["upstreams"]["1.1.1.1"]
    assert stats["queries"] == 2
    assert stats["failures"] == 0
    assert stats["latency_ms"] == 50.0

    proxy._record_upstream("1.1.1.1", 0.10)
    stats = proxy.stats()["upstreams"]["1.1.1.1"]
    assert stats["latency_ms"] == round(50.0 * 0.8 + 100.0 * 0.2, 2)


# ---------------------------------------------------------------------------
# _forward() failover / TCP fallback
# ---------------------------------------------------------------------------

def test_forward_fails_over_to_second_upstream(monkeypatch, patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "10.0.0.1,10.0.0.2"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    query_payload = DNSRecord.question("example.com", "A").pack()
    good_response = _valid_answer(query_payload)
    sockets = [
        _FakeUDPSocket(recvfrom_raises=OSError("refused")),
        _FakeUDPSocket(recv_response=good_response),
    ]
    monkeypatch.setattr("backend.dns.proxy.socket.socket", _socket_queue_factory(sockets))

    result = proxy._forward(query_payload)

    assert result == good_response
    stats = proxy.stats()["upstreams"]
    assert stats["10.0.0.1"]["failures"] == 1
    assert stats["10.0.0.2"]["failures"] == 0
    assert stats["10.0.0.2"]["queries"] == 1


def test_forward_raises_when_all_upstreams_fail(monkeypatch, patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        models.set_settings(conn, {"dns_upstream": "10.0.0.1,10.0.0.2"})
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=True)
    query_payload = DNSRecord.question("example.com", "A").pack()
    sockets = [
        _FakeUDPSocket(recvfrom_raises=OSError("refused")),
        _FakeUDPSocket(recvfrom_raises=OSError("timed out")),
    ]
    monkeypatch.setattr("backend.dns.proxy.socket.socket", _socket_queue_factory(sockets))

    with pytest.raises(OSError):
        proxy._forward(query_payload)


def test_forward_uses_tcp_when_udp_response_truncated(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    query_payload = DNSRecord.question("example.com", "A").pack()
    truncated = _truncated_response(query_payload)
    good_response = _valid_answer(query_payload)
    sockets = [_FakeUDPSocket(recv_response=truncated)]
    monkeypatch.setattr("backend.dns.proxy.socket.socket", _socket_queue_factory(sockets))

    tcp_calls = []

    def fake_forward_tcp(self, payload, upstream):
        tcp_calls.append(upstream)
        return good_response

    monkeypatch.setattr(DNSProxy, "_forward_tcp", fake_forward_tcp)

    result = proxy._forward(query_payload)

    assert result == good_response
    assert tcp_calls == [proxy.upstream]


# ---------------------------------------------------------------------------
# _resolve(): cache short-circuit and in-flight coalescing
# ---------------------------------------------------------------------------

def test_resolve_cache_hit_never_calls_forward(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    query_payload = DNSRecord.question("cached.example", "A").pack()
    key = cache_key(query_payload)
    proxy.cache.put(key, _valid_answer(query_payload))

    def _boom(payload):
        raise AssertionError("forward must not be called on a cache hit")

    monkeypatch.setattr(proxy, "_forward", _boom)

    result = proxy._resolve(query_payload)
    assert DNSRecord.parse(result).header.rcode == RCODE.NOERROR


def test_resolve_coalesces_concurrent_identical_queries(tmp_path):
    """`_resolve` keys in-flight lookups by (qname, qtype, qclass) with a
    per-key `threading.Event`, so two threads issuing the same query while
    the first is still in flight should only trigger one real `_forward`
    call and both should get back a consistent answer."""
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)

    call_count = 0
    count_lock = threading.Lock()

    def fake_forward(payload):
        nonlocal call_count
        with count_lock:
            call_count += 1
        time.sleep(0.15)
        return _valid_answer(payload)

    proxy._forward = fake_forward

    results = [None, None]

    def _run(index, payload):
        results[index] = proxy._resolve(payload)

    payload_a = DNSRecord.question("shared.example", "A").pack()
    payload_b = DNSRecord.question("shared.example", "A").pack()

    thread_a = threading.Thread(target=_run, args=(0, payload_a))
    thread_b = threading.Thread(target=_run, args=(1, payload_b))
    thread_a.start()
    time.sleep(0.03)
    thread_b.start()
    thread_a.join(timeout=5)
    thread_b.join(timeout=5)

    assert call_count == 1
    assert results[0] is not None and results[1] is not None
    first = DNSRecord.parse(results[0])
    second = DNSRecord.parse(results[1])
    assert str(first.rr[0].rdata) == str(second.rr[0].rdata) == "203.0.113.10"


# ---------------------------------------------------------------------------
# _process(): blocking gates, logging, and error fallback
# ---------------------------------------------------------------------------

def test_process_refuses_household_blocked_device_regardless_of_domain(patched_db, db_path, tmp_path):
    _insert_device(db_path, "AA:BB:CC:DD:EE:01", "10.0.0.5", is_authorized=2)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("perfectly-normal-site.example", "A").pack()

    response = proxy._process(payload, "10.0.0.5")

    parsed = DNSRecord.parse(response)
    assert parsed.header.rcode == RCODE.REFUSED
    with models.get_conn(db_path) as conn:
        logs = models.list_traffic(conn)
    assert logs[0]["threat_reason"] == "device blocked by household"
    assert logs[0]["was_blocked"] == 1


def test_process_blocks_blocklisted_domain_and_creates_alert(patched_db, db_path, tmp_path):
    blocklist_path = tmp_path / "blocklist.txt"
    blocklist_path.write_text("malware.example\n")
    proxy = DNSProxy(BlocklistManager(blocklist_path), dynamic_upstream=False)
    payload = DNSRecord.question("malware.example", "A").pack()

    response = proxy._process(payload, "10.0.0.9")

    parsed = DNSRecord.parse(response)
    assert parsed.header.rcode == RCODE.NXDOMAIN
    with models.get_conn(db_path) as conn:
        alerts = models.list_alerts(conn)
        logs = models.list_traffic(conn)
    assert any("malware.example" in alert["title"] for alert in alerts)
    assert logs[0]["was_blocked"] == 1
    assert logs[0]["threat_level"] == "warning"


def test_process_refuses_device_policy_blocked_domain_with_reason(patched_db, db_path, tmp_path):
    with models.get_conn(db_path) as conn:
        device_id = models.upsert_device(conn, mac="AA:BB:CC:DD:EE:02", ip="10.0.0.6", hostname=None, vendor=None)
        models.set_device_policy(conn, device_id, blocked_domains=["policy-blocked.example"])
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("policy-blocked.example", "A").pack()

    response = proxy._process(payload, "10.0.0.6")

    parsed = DNSRecord.parse(response)
    assert parsed.header.rcode == RCODE.REFUSED
    with models.get_conn(db_path) as conn:
        logs = models.list_traffic(conn)
    assert logs[0]["threat_reason"] == "custom device domain rule"


def test_process_allows_clean_domain_and_logs_traffic(monkeypatch, patched_db, db_path, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("clean.example", "A").pack()
    canned = _valid_answer(payload)
    monkeypatch.setattr(proxy, "_resolve", lambda p: canned)

    response = proxy._process(payload, "10.0.0.7")

    assert response == canned
    with models.get_conn(db_path) as conn:
        logs = models.list_traffic(conn)
    assert logs[0]["was_blocked"] == 0
    assert logs[0]["threat_level"] == "none"


def test_process_falls_back_to_forward_when_main_logic_raises(monkeypatch, patched_db, db_path, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("oops.example", "A").pack()
    canned = _valid_answer(payload)

    def _raise_inspect(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("backend.dns.proxy.inspect_query", _raise_inspect)
    monkeypatch.setattr(proxy, "_forward", lambda p: canned)

    response = proxy._process(payload, "10.0.0.8")

    assert response == canned


def test_process_returns_none_when_fallback_forward_also_fails(monkeypatch, patched_db, db_path, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("oops2.example", "A").pack()

    def _raise_inspect(*args, **kwargs):
        raise RuntimeError("boom")

    def _raise_forward(payload):
        raise OSError("no upstream")

    monkeypatch.setattr("backend.dns.proxy.inspect_query", _raise_inspect)
    monkeypatch.setattr(proxy, "_forward", _raise_forward)

    response = proxy._process(payload, "10.0.0.8")

    assert response is None


# ---------------------------------------------------------------------------
# UDP/TCP entry points
# ---------------------------------------------------------------------------

def test_handle_sends_response_via_socket(monkeypatch, tmp_path, fake_socket_factory):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    canned = b"response-bytes"
    monkeypatch.setattr(proxy, "_process", lambda payload, ip: canned)
    fake = fake_socket_factory()
    proxy._socket = fake

    proxy._handle(b"query", ("10.0.0.1", 5353))

    assert fake.sent == [(canned, ("10.0.0.1", 5353))]


def test_handle_swallows_socket_send_errors(monkeypatch, tmp_path, fake_socket_factory):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    monkeypatch.setattr(proxy, "_process", lambda payload, ip: b"resp")
    fake = fake_socket_factory(sendto_raises=OSError("boom"))
    proxy._socket = fake

    proxy._handle(b"query", ("10.0.0.1", 5353))  # must not raise


def test_handle_tcp_round_trip_with_length_prefixed_framing(monkeypatch, tmp_path):
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    request_payload = DNSRecord.question("example.com", "A").pack()
    canned_response = _valid_answer(request_payload)
    monkeypatch.setattr(proxy, "_process", lambda payload, ip: canned_response)

    left, right = socket.socketpair()
    try:
        right.sendall(len(request_payload).to_bytes(2, "big") + request_payload)
        proxy._handle_tcp(left, "127.0.0.1")

        received_len = int.from_bytes(right.recv(2), "big")
        received = right.recv(received_len)
        assert received == canned_response
    finally:
        right.close()
