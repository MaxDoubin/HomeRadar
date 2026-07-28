"""Concurrent UDP/TCP DNS proxy with blocking, attribution, and safe failure behavior."""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from dnslib import A, AAAA, DNSHeader, DNSRecord, QTYPE, RCODE, RR

from backend import config
from backend.db import get_conn, models
from backend.dns.blocklists import BlocklistManager
from backend.dns.cache import DNSCache, cache_key
from backend.dns.policy import evaluate_policy

logger = logging.getLogger("homeradar.dns")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class QueryDecision:
    domain: str
    query_type: str
    blocked: bool
    reason: str | None


def inspect_query(payload: bytes, blocklists: BlocklistManager) -> QueryDecision:
    request = DNSRecord.parse(payload)
    if not request.questions:
        raise ValueError("DNS request contains no question")
    question = request.questions[0]
    domain = str(question.qname).rstrip(".").lower()
    query_type = QTYPE.get(question.qtype, str(question.qtype))
    blocked = blocklists.is_blocked(domain)
    return QueryDecision(domain, query_type, blocked, "community blocklist" if blocked else None)


def error_response(payload: bytes, rcode: int = RCODE.NXDOMAIN) -> bytes:
    request = DNSRecord.parse(payload)
    reply = request.reply()
    reply.header = DNSHeader(
        id=request.header.id,
        qr=1,
        aa=0,
        ra=1,
        rd=request.header.rd,
        rcode=rcode,
    )
    return reply.pack()


def blocked_response(payload: bytes) -> bytes:
    return error_response(payload, RCODE.NXDOMAIN)


def client_is_allowed(client_ip: str) -> bool:
    """Refuse public-source clients unless explicitly enabled.

    Home Radar is a household resolver, not a public recursive DNS service.
    RFC1918/ULA, loopback, link-local, and carrier-grade NAT ranges are accepted.
    """
    if config.DNS_ALLOW_PUBLIC_CLIENTS:
        return True
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or (address.version == 4 and address in _CGNAT)
    )


class DNSProxy:
    def __init__(
        self,
        blocklists: BlocklistManager,
        *,
        host: str = config.DNS_HOST,
        port: int = config.DNS_PORT,
        upstream: tuple[str, int] = (config.DNS_UPSTREAM, config.DNS_UPSTREAM_PORT),
        dynamic_upstream: bool = True,
    ):
        self.blocklists = blocklists
        self.address = (host, port)
        self.upstream = upstream
        self.dynamic_upstream = dynamic_upstream
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._tcp_socket: socket.socket | None = None
        self._tcp_thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns-query")
        self.cache = DNSCache(config.DNS_CACHE_SIZE, config.DNS_CACHE_MAX_TTL)
        self._upstream_stats: dict[str, dict] = {}
        self._stats_lock = threading.Lock()
        self._inflight: dict[tuple, threading.Event] = {}
        self._inflight_lock = threading.Lock()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(self.address)
            server.settimeout(0.5)
            self._socket = server
            self._tcp_thread = threading.Thread(
                target=self._serve_tcp,
                daemon=True,
                name="homeradar-dns-tcp",
            )
            self._tcp_thread.start()
            logger.info("DNS proxy listening on %s:%d over UDP and TCP", *self.address)
            while not self._stop.is_set():
                try:
                    payload, client = server.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    if not self._stop.is_set():
                        logger.exception("DNS listener failed")
                    break
                self._pool.submit(self._handle, payload, client)

    def stop(self) -> None:
        self._stop.set()
        if self._socket:
            self._socket.close()
        if self._tcp_socket:
            self._tcp_socket.close()
        if self._tcp_thread:
            self._tcp_thread.join(timeout=2)
        self._pool.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _receive_exact(connection: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                raise OSError("DNS TCP connection closed early")
            chunks.extend(chunk)
        return bytes(chunks)

    def _upstreams(self) -> list[tuple[str, int]]:
        candidates = [self.upstream[0]] if not self.dynamic_upstream else config.DNS_UPSTREAMS
        if self.dynamic_upstream:
            with get_conn() as conn:
                configured = models.get_setting(conn, "dns_upstream")
            if configured:
                candidates = [value.strip() for value in configured.split(",") if value.strip()]
        valid = []
        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)
                valid.append((candidate, self.upstream[1]))
            except ValueError:
                continue
        if not valid:
            valid = [self.upstream]
        with self._stats_lock:
            return sorted(
                valid,
                key=lambda item: (
                    self._upstream_stats.get(item[0], {}).get("failures", 0),
                    self._upstream_stats.get(item[0], {}).get("latency_ms", float("inf")),
                ),
            )

    def _record_upstream(self, address: str, elapsed: float | None) -> None:
        with self._stats_lock:
            stats = self._upstream_stats.setdefault(
                address, {"queries": 0, "failures": 0, "latency_ms": 0.0}
            )
            stats["queries"] += 1
            if elapsed is None:
                stats["failures"] += 1
            else:
                previous = stats["latency_ms"]
                stats["latency_ms"] = round(
                    elapsed * 1000 if not previous else previous * 0.8 + elapsed * 1000 * 0.2,
                    2,
                )
                stats["failures"] = max(0, stats["failures"] - 1)

    def _forward_tcp(self, payload: bytes, upstream: tuple[str, int]) -> bytes:
        with socket.create_connection(upstream, timeout=config.DNS_TIMEOUT_SECONDS) as connection:
            connection.sendall(len(payload).to_bytes(2, "big") + payload)
            response_size = int.from_bytes(self._receive_exact(connection, 2), "big")
            return self._receive_exact(connection, response_size)

    def _forward(self, payload: bytes) -> bytes:
        last_error = None
        for upstream in self._upstreams():
            started = time.monotonic()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                    upstream_socket.settimeout(config.DNS_TIMEOUT_SECONDS)
                    upstream_socket.sendto(payload, upstream)
                    response = upstream_socket.recvfrom(65535)[0]
                if DNSRecord.parse(response).header.tc:
                    response = self._forward_tcp(payload, upstream)
                self._record_upstream(upstream[0], time.monotonic() - started)
                return response
            except OSError as exc:
                last_error = exc
                self._record_upstream(upstream[0], None)
        raise last_error or OSError("no valid DNS upstream is configured")

    def _resolve(self, payload: bytes) -> bytes:
        request = DNSRecord.parse(payload)
        key = cache_key(payload)
        cached = self.cache.get(key, request.header.id)
        if cached:
            return cached
        with self._inflight_lock:
            event = self._inflight.get(key)
            if event is None:
                event = threading.Event()
                self._inflight[key] = event
                owner = True
            else:
                owner = False
        if not owner:
            event.wait(config.DNS_TIMEOUT_SECONDS * max(1, len(self._upstreams())))
            cached = self.cache.get(key, request.header.id)
            if cached:
                return cached
        try:
            response = self._forward(payload)
            self.cache.put(key, response)
            return response
        finally:
            if owner:
                with self._inflight_lock:
                    self._inflight.pop(key, None)
                    event.set()

    def stats(self) -> dict:
        with self._stats_lock:
            upstreams = {key: dict(value) for key, value in self._upstream_stats.items()}
        return {"cache": self.cache.stats(), "upstreams": upstreams}

    def _check_custom_dns(self, payload: bytes, custom_records: str | None) -> bytes | None:
        if not custom_records:
            return None
        try:
            records = json.loads(custom_records)
        except (TypeError, ValueError):
            return None
        if not isinstance(records, dict):
            return None

        request = DNSRecord.parse(payload)
        if not request.questions:
            return None

        question = request.questions[0]
        domain = str(question.qname).rstrip(".").lower()
        ip_str = records.get(domain)
        if not isinstance(ip_str, str) or not ip_str:
            return None

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        qtype = question.qtype
        reply = request.reply()
        added = False
        if ip.version == 4 and qtype in (QTYPE.A, QTYPE.ANY):
            reply.add_answer(
                RR(rname=question.qname, rtype=QTYPE.A, rclass=1, ttl=300, rdata=A(ip_str))
            )
            added = True
        elif ip.version == 6 and qtype in (QTYPE.AAAA, QTYPE.ANY):
            reply.add_answer(
                RR(rname=question.qname, rtype=QTYPE.AAAA, rclass=1, ttl=300, rdata=AAAA(ip_str))
            )
            added = True
        return reply.pack() if added else None

    def _safe_error(self, payload: bytes, rcode: int) -> bytes | None:
        try:
            return error_response(payload, rcode)
        except Exception:
            return None

    def _process(self, payload: bytes, client_ip: str) -> bytes | None:
        if not client_is_allowed(client_ip):
            logger.warning("Refusing DNS request from non-local client %s", client_ip)
            return self._safe_error(payload, RCODE.REFUSED)

        try:
            decision = inspect_query(payload, self.blocklists)
        except Exception:
            logger.debug("Invalid DNS request from %s", client_ip, exc_info=True)
            return self._safe_error(payload, RCODE.FORMERR)

        try:
            with get_conn() as conn:
                device = models.find_device_by_ip(conn, client_ip)
                policy = models.get_device_policy(conn, device["id"]) if device else None
                custom_dns_records = models.get_setting(conn, "custom_dns_records")
        except Exception:
            logger.exception("Could not load DNS policy for %s", client_ip)
            return self._safe_error(payload, RCODE.SERVFAIL)

        policy_decision = evaluate_policy(policy, decision.domain)
        household_blocked = bool(device and device["is_authorized"] == 2)
        policy_blocked = household_blocked or policy_decision.blocked

        if policy_blocked:
            response = self._safe_error(payload, RCODE.REFUSED)
        elif decision.blocked:
            response = self._safe_error(payload, RCODE.NXDOMAIN)
        else:
            custom_response = self._check_custom_dns(payload, custom_dns_records)
            if custom_response:
                response = custom_response
            else:
                try:
                    response = self._resolve(payload)
                except Exception:
                    logger.warning("DNS upstream resolution failed for %s", decision.domain, exc_info=True)
                    response = self._safe_error(payload, RCODE.SERVFAIL)

        if response is None:
            return None

        try:
            with get_conn() as conn:
                models.log_traffic(
                    conn,
                    device_id=device["id"] if device else None,
                    domain=decision.domain,
                    was_blocked=decision.blocked or policy_blocked,
                    threat_level="warning" if decision.blocked else "none",
                    threat_reason=(
                        "device blocked by household"
                        if household_blocked
                        else policy_decision.reason or decision.reason
                    ),
                    query_type=decision.query_type,
                    bytes_sent=len(payload),
                    bytes_received=len(response),
                )
                if decision.blocked:
                    models.create_alert_once(
                        conn,
                        device_id=device["id"] if device else None,
                        severity="warning",
                        title=f"Blocked DNS request: {decision.domain}",
                        description=f"{client_ip} requested {decision.domain}",
                    )
        except Exception:
            # Observability must never reverse a policy decision. Return the
            # response already selected even if SQLite is temporarily busy.
            logger.warning("Could not record DNS request for %s", client_ip, exc_info=True)

        return response

    def _handle(self, payload: bytes, client: tuple[str, int]) -> None:
        response = self._process(payload, client[0])
        if response and self._socket:
            try:
                self._socket.sendto(response, client)
            except OSError:
                logger.debug("Could not return DNS response to %s", client[0], exc_info=True)

    def _serve_tcp(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(self.address)
            server.listen(64)
            server.settimeout(0.5)
            self._tcp_socket = server
            while not self._stop.is_set():
                try:
                    connection, client = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._pool.submit(self._handle_tcp, connection, client[0])

    def _handle_tcp(self, connection: socket.socket, client_ip: str) -> None:
        with connection:
            connection.settimeout(config.DNS_TIMEOUT_SECONDS)
            try:
                size = int.from_bytes(self._receive_exact(connection, 2), "big")
                if size <= 0 or size > 65535:
                    return
                payload = self._receive_exact(connection, size)
                response = self._process(payload, client_ip)
                if response:
                    connection.sendall(len(response).to_bytes(2, "big") + response)
            except OSError:
                logger.debug("TCP DNS request failed for %s", client_ip, exc_info=True)
