"""Process-wide service objects shared by API and background workers."""
from __future__ import annotations

from typing import TYPE_CHECKING

from backend.dns.blocklists import BlocklistManager

if TYPE_CHECKING:
    from backend.dns.proxy import DNSProxy

blocklists = BlocklistManager()
dns_proxy: DNSProxy | None = None
