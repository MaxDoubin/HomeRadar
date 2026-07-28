from unittest.mock import patch

from dnslib import A, DNSRecord, QTYPE, RR

from backend.dns.cache import DNSCache, cache_key


def response_payload(name: str, ttl: int = 120, request_id: int = 42) -> bytes:
    request = DNSRecord.question(name)
    request.header.id = request_id
    response = request.reply()
    response.add_answer(RR(name, QTYPE.A, rdata=A("192.0.2.10"), ttl=ttl))
    return response.pack()


def test_cache_rewrites_request_id_and_decrements_ttl():
    cache = DNSCache(capacity=2, max_ttl=300)
    request = DNSRecord.question("example.test")
    key = cache_key(request.pack())
    with patch("backend.dns.cache.time.monotonic", side_effect=[100.0, 110.0]):
        assert cache.put(key, response_payload("example.test", ttl=120))
        cached = DNSRecord.parse(cache.get(key, request_id=999))
    assert cached.header.id == 999
    assert cached.rr[0].ttl == 110
    assert cache.stats()["hits"] == 1


def test_cache_expires_and_evicts_least_recently_used():
    cache = DNSCache(capacity=1, max_ttl=60)
    first = cache_key(DNSRecord.question("one.test").pack())
    second = cache_key(DNSRecord.question("two.test").pack())
    cache.put(first, response_payload("one.test"))
    cache.put(second, response_payload("two.test"))
    assert cache.get(first, 1) is None
    assert cache.get(second, 2) is not None


def test_cache_does_not_store_empty_answers():
    cache = DNSCache()
    request = DNSRecord.question("empty.test")
    assert not cache.put(cache_key(request.pack()), request.reply().pack())
