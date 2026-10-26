"""Blocklist normalization, matching, persistence, and safe remote updates."""
from __future__ import annotations

import ipaddress
import logging
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from backend import config
from backend.tls import https_context as _https_context

logger = logging.getLogger("homeradar.blocklists")

_IGNORED_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost"}
_HOSTS_FILE_ADDRESSES = {
    str(ipaddress.IPv4Address(0)),
    str(ipaddress.IPv4Address(0x7F000001)),
    str(ipaddress.IPv6Address(0)),
}


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    if not domain or domain.startswith(("#", "!", "[")):
        return None
    if "://" in domain:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    if domain in _IGNORED_HOSTS or " " in domain or "." not in domain:
        return None
    labels = domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    if any(set(label) - allowed for label in labels):
        return None
    return domain


def parse_blocklist(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        candidates = fields[1:] if fields and fields[0] in _HOSTS_FILE_ADDRESSES else fields
        for candidate in candidates:
            if candidate.startswith("||"):
                candidate = candidate[2:].split("^", 1)[0]
            if candidate.startswith("*."):
                candidate = candidate[2:]
            domain = normalize_domain(candidate)
            if domain:
                domains.add(domain)
    return domains


@dataclass(frozen=True)
class UpdateResult:
    source: str
    domain_count: int
    status: str
    error: str | None = None
    friendly_error: str | None = None


def friendly_update_error(source: str, exc: BaseException) -> str:
    """Describe a failed blocklist download in words a household can act on."""
    host = urllib.parse.urlsplit(source).hostname or source
    if isinstance(exc, urllib.error.HTTPError):
        return f"{host} answered with an error (HTTP {exc.code}). We'll try again later."
    if isinstance(exc, ValueError):
        return "This blocklist address isn't a valid HTTPS link."
    return f"Couldn't reach {host}. Check the internet connection."


def summarize_update(results: list[UpdateResult], domain_count: int) -> dict:
    failed = [result for result in results if result.status != "ok"]
    if not failed:
        message = f"Blocklists updated. Blocking {domain_count:,} known bad domains."
    elif len(failed) == len(results):
        message = (
            "Couldn't update the blocklists just now, so the previous list "
            f"({domain_count:,} domains) is still protecting you. We'll retry automatically."
        )
    else:
        message = (
            f"Updated {len(results) - len(failed)} of {len(results)} blocklists. "
            "Domains from the sources we couldn't reach were kept from the previous list."
        )
    return {
        "ok": not failed,
        "message": message,
        "domain_count": domain_count,
        "sources": [
            {
                "url": result.source,
                "ok": result.status == "ok",
                "domain_count": result.domain_count,
                "error_friendly": result.friendly_error,
                "error_detail": result.error,
            }
            for result in results
        ],
    }


def _validated_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("blocklist sources must use an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("blocklist source URLs must not contain credentials")
    return urllib.parse.urlunsplit(parsed)


class BlocklistManager:
    """Thread-safe exact and parent-domain matcher."""

    def __init__(self, path: Path = config.BLOCKLIST_PATH):
        self.path = Path(path)
        self._domains: set[str] = set()
        self._lock = threading.RLock()
        self.load()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._domains)

    def load(self) -> int:
        if not self.path.exists():
            return 0
        domains = parse_blocklist(self.path.read_text(errors="replace"))
        with self._lock:
            self._domains = domains
        return len(domains)

    def is_blocked(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        if not normalized:
            return False
        labels = normalized.split(".")
        with self._lock:
            return any(".".join(labels[index:]) in self._domains for index in range(len(labels) - 1))

    def replace(self, domains: set[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(sorted(domains)) + "\n"
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".blocklist-", dir=self.path.parent, text=True
        )
        try:
            with os.fdopen(file_descriptor, "w") as handle:
                handle.write(content)
            Path(temporary_name).replace(self.path)
        finally:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()
        with self._lock:
            self._domains = set(domains)

    def update(self, urls: list[str] | None = None, timeout: float = 30) -> list[UpdateResult]:
        merged: set[str] = set()
        results: list[UpdateResult] = []
        context = _https_context()
        for source in urls or config.BLOCKLIST_URLS:
            try:
                url = _validated_https_url(source)
                request = urllib.request.Request(
                    url, headers={"User-Agent": "HomeRadar/0.3 blocklist updater"}
                )
                with urllib.request.urlopen(  # nosec B310
                    request, timeout=timeout, context=context
                ) as response:
                    text = response.read(50_000_000).decode("utf-8", "replace")
                domains = parse_blocklist(text)
                merged.update(domains)
                results.append(UpdateResult(source, len(domains), "ok"))
            except Exception as exc:
                logger.warning("Blocklist update failed for %s: %s", source, exc)
                results.append(
                    UpdateResult(
                        source, 0, "error", str(exc)[:500], friendly_update_error(source, exc)
                    )
                )
        if merged:
            if any(result.status != "ok" for result in results):
                # A source that failed this time must not silently lose the
                # domains it contributed before, so keep the previous list too.
                with self._lock:
                    merged |= self._domains
            self.replace(merged)
        return results


def record_update_results(conn, results: list[UpdateResult]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        """INSERT INTO blocklist_metadata (source, domain_count, status, error, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(source) DO UPDATE SET
               domain_count = excluded.domain_count,
               status = excluded.status,
               error = excluded.error,
               updated_at = excluded.updated_at""",
        [(result.source, result.domain_count, result.status, result.error, now) for result in results],
    )
