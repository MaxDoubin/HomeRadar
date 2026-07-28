"""Small thread-safe TTL-aware DNS response cache."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

from dnslib import DNSRecord, RCODE


def cache_key(payload: bytes) -> tuple[str, int, int]:
    request = DNSRecord.parse(payload)
    question = request.questions[0]
    return str(question.qname).lower(), question.qtype, question.qclass


class DNSCache:
    def __init__(self, capacity: int = 4096, max_ttl: int = 3600):
        self.capacity = max(1, capacity)
        self.max_ttl = max(1, max_ttl)
        self._entries: OrderedDict[tuple, tuple[float, int, bytes]] = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: tuple, request_id: int) -> bytes | None:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry[0] <= now:
                self._entries.pop(key, None)
                self.misses += 1
                return None
            expires, original_ttl, packed = entry
            self._entries.move_to_end(key)
            self.hits += 1
        response = DNSRecord.parse(packed)
        response.header.id = request_id
        remaining = max(0, min(original_ttl, int(expires - now)))
        for record in (*response.rr, *response.auth, *response.ar):
            record.ttl = min(record.ttl, remaining)
        return response.pack()

    def put(self, key: tuple, payload: bytes) -> bool:
        response = DNSRecord.parse(payload)
        if response.header.rcode != RCODE.NOERROR or not response.rr:
            return False
        ttl = min(self.max_ttl, min(record.ttl for record in response.rr))
        if ttl <= 0:
            return False
        response.header.id = 0
        with self._lock:
            self._entries[key] = (time.monotonic() + ttl, ttl, response.pack())
            self._entries.move_to_end(key)
            while len(self._entries) > self.capacity:
                self._entries.popitem(last=False)
        return True

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / max(1, self.hits + self.misses), 3),
            }
