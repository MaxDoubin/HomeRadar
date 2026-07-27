import socket

from dnslib import DNSRecord, QTYPE, RCODE

from backend.dns.blocklists import BlocklistManager
from backend.dns.proxy import DNSProxy, blocked_response, error_response, inspect_query


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
