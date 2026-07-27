"""Concurrent UDP DNS proxy with blocking, device attribution, and query logging."""
from __future__ import annotations

import logging
import ipaddress
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

    def _upstream(self) -> tuple[str, int]:
        if not self.dynamic_upstream:
            return self.upstream
        with get_conn() as conn:
            configured = models.get_setting(conn, "dns_upstream", self.upstream[0])
        try:
            ipaddress.ip_address(configured)
            return configured, self.upstream[1]
        except ValueError:
            return self.upstream

    def _forward_tcp(self, payload: bytes) -> bytes:
        with socket.create_connection(self._upstream(), timeout=config.DNS_TIMEOUT_SECONDS) as connection:
            connection.sendall(len(payload).to_bytes(2, "big") + payload)
            response_size = int.from_bytes(self._receive_exact(connection, 2), "big")
            return self._receive_exact(connection, response_size)

    def _forward(self, payload: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
            upstream_socket.settimeout(config.DNS_TIMEOUT_SECONDS)
            upstream_socket.sendto(payload, self._upstream())
            response = upstream_socket.recvfrom(65535)[0]
        if DNSRecord.parse(response).header.tc:
            return self._forward_tcp(payload)
        return response

    def _process(self, payload: bytes, client_ip: str) -> bytes | None:
        response: bytes | None = None
        try:
            decision = inspect_query(payload, self.blocklists)
            with get_conn() as conn:
                device = models.find_device_by_ip(conn, client_ip)
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
                        description=f"{client_ip} requested {decision.domain}",
                    )
        except Exception:
            logger.debug("DNS query handling failed for %s", client_ip, exc_info=True)
            try:
                response = self._forward(payload)
            except OSError:
                response = None
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
                payload = self._receive_exact(connection, size)
                response = self._process(payload, client_ip)
                if response:
                    connection.sendall(len(response).to_bytes(2, "big") + response)
            except OSError:
                logger.debug("TCP DNS request failed for %s", client_ip, exc_info=True)
