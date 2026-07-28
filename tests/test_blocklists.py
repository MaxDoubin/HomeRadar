from pathlib import Path

from backend.db import models
from backend.dns.blocklists import (
    BlocklistManager,
    UpdateResult,
    normalize_domain,
    parse_blocklist,
    record_update_results,
)


def test_parse_hosts_adblock_and_domain_formats():
    domains = parse_blocklist(
        """
        # hosts syntax
        0.0.0.0 ads.example.com tracker.example.net
        127.0.0.1 localhost
        ||malware.example.org^
        *.telemetry.vendor.test
        clean.example.com
        """
    )
    assert domains == {
        "ads.example.com",
        "tracker.example.net",
        "malware.example.org",
        "telemetry.vendor.test",
        "clean.example.com",
    }


def test_parent_domain_matching(tmp_path: Path):
    path = tmp_path / "blocklist.txt"
    path.write_text("tracker.example.com\n")
    manager = BlocklistManager(path)
    assert manager.is_blocked("tracker.example.com")
    assert manager.is_blocked("pixel.tracker.example.com.")
    assert not manager.is_blocked("example.com")


def test_normalize_rejects_ips_urls_and_local_names():
    assert normalize_domain("https://example.com") is None
    assert normalize_domain("127.0.0.1") is None
    assert normalize_domain("localhost") is None
    assert normalize_domain("Example.COM.") == "example.com"
