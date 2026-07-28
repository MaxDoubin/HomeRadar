"""Process-wide service objects shared by API and background workers."""
from backend.dns.blocklists import BlocklistManager

blocklists = BlocklistManager()
dns_proxy = None
