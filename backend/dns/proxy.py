"""Concurrent UDP DNS proxy with blocking, device attribution, and query logging."""
from __future__ import annotations

import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from dnslib import DNSHeader, DNSRecord, QTYPE, RCODE

from backend import config
from backend.db import get_conn, models
from backend.dns.blocklists import BlocklistManager

logger = logging.getLogger("homeradar.dns")


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


class DNSProxy:
    def __init__(
        self,
        blocklists: BlocklistManager,
        *,
        host: str = config.DNS_HOST,
        port: int = config.DNS_PORT,
        upstream: tuple[str, int] = (config.DNS_UPSTREAM, config.DNS_UPSTREAM_PORT),
    ):
        self.blocklists = blocklists
        self.address = (host, port)
        self.upstream = upstream
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns-query")

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(self.address)
            server.settimeout(0.5)
            self._socket = server
            logger.info("DNS proxy listening on %s:%d", *self.address)
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
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _forward(self, payload: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
            upstream_socket.settimeout(config.DNS_TIMEOUT_SECONDS)
            upstream_socket.sendto(payload, self.upstream)
            return upstream_socket.recvfrom(65535)[0]

    def _handle(self, payload: bytes, client: tuple[str, int]) -> None:
        response: bytes | None = None
        try:
            decision = inspect_query(payload, self.blocklists)
            with get_conn() as conn:
                device = models.find_device_by_ip(conn, client[0])
            policy_blocked = bool(device and device["is_authorized"] == 2)
            if policy_blocked:
                response = error_response(payload, RCODE.REFUSED)
            elif decision.blocked:
                response = blocked_response(payload)
            else:
                response = self._forward(payload)
            with get_conn() as conn:
                models.log_traffic(
                    conn,
                    device_id=device["id"] if device else None,
                    domain=decision.domain,
                    was_blocked=decision.blocked or policy_blocked,
                    threat_level="warning" if decision.blocked else "none",
                    threat_reason="device blocked by household" if policy_blocked else decision.reason,
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
                        description=f"{client[0]} requested {decision.domain}",
                    )
        except Exception:
            logger.debug("DNS query handling failed for %s", client[0], exc_info=True)
            try:
                response = self._forward(payload)
            except OSError:
                response = None
        if response and self._socket:
            try:
                self._socket.sendto(response, client)
            except OSError:
                logger.debug("Could not return DNS response to %s", client[0], exc_info=True)
