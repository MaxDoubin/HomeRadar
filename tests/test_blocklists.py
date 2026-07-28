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


class _FakeURLResponse:
    """A context-manager stand-in for `http.client.HTTPResponse`."""

    def __init__(self, text: str):
        self._data = text.encode("utf-8")

    def read(self, amount=-1):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_replace_writes_atomically_and_leaves_no_temp_file(tmp_path: Path):
    path = tmp_path / "blocklist.txt"
    manager = BlocklistManager(path)

    manager.replace({"first.example"})
    assert path.read_text() == "first.example\n"

    manager.replace({"second.example", "third.example"})
    assert path.read_text() == "second.example\nthird.example\n"

    leftover = [entry for entry in tmp_path.iterdir() if entry != path]
    assert leftover == []
    assert manager.count == 2


def test_update_merges_domains_from_multiple_sources(monkeypatch, tmp_path: Path):
    manager = BlocklistManager(tmp_path / "blocklist.txt")
    responses = {
        "http://a.example/hosts.txt": "0.0.0.0 a-ads.example\n",
        "http://b.example/hosts.txt": "0.0.0.0 b-ads.example\n",
    }

    def fake_urlopen(request, timeout=None):
        return _FakeURLResponse(responses[request.full_url])

    monkeypatch.setattr("backend.dns.blocklists.urllib.request.urlopen", fake_urlopen)

    results = manager.update(urls=list(responses.keys()))

    assert {result.status for result in results} == {"ok"}
    assert {result.source for result in results} == set(responses.keys())
    assert manager.is_blocked("a-ads.example")
    assert manager.is_blocked("b-ads.example")


def test_update_reports_error_for_one_failing_source_but_applies_the_other(monkeypatch, tmp_path: Path):
    manager = BlocklistManager(tmp_path / "blocklist.txt")
    urls = ["http://good.example/hosts.txt", "http://bad.example/hosts.txt"]

    def fake_urlopen(request, timeout=None):
        if "bad" in request.full_url:
            raise OSError("connection refused")
        return _FakeURLResponse("0.0.0.0 good-ads.example\n")

    monkeypatch.setattr("backend.dns.blocklists.urllib.request.urlopen", fake_urlopen)

    results = manager.update(urls=urls)
    by_source = {result.source: result for result in results}

    assert by_source["http://good.example/hosts.txt"].status == "ok"
    assert by_source["http://bad.example/hosts.txt"].status == "error"
    assert by_source["http://bad.example/hosts.txt"].error
    assert manager.is_blocked("good-ads.example")
    assert not manager.is_blocked("bad-should-not-appear.example")


def test_record_update_results_inserts_then_upserts_on_conflict(db_path):
    with models.get_conn(db_path) as conn:
        record_update_results(conn, [UpdateResult("http://a.example/hosts.txt", 10, "ok")])

    with models.get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM blocklist_metadata WHERE source = ?", ("http://a.example/hosts.txt",)
        ).fetchone()
    assert row["domain_count"] == 10
    assert row["status"] == "ok"
    assert row["error"] is None
    first_updated_at = row["updated_at"]

    with models.get_conn(db_path) as conn:
        record_update_results(
            conn,
            [UpdateResult("http://a.example/hosts.txt", 20, "error", "temporary failure")],
        )

    with models.get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM blocklist_metadata").fetchall()
        row = conn.execute(
            "SELECT * FROM blocklist_metadata WHERE source = ?", ("http://a.example/hosts.txt",)
        ).fetchone()

    assert len(rows) == 1  # upsert, not a duplicate row
    assert row["domain_count"] == 20
    assert row["status"] == "error"
    assert row["error"] == "temporary failure"
    assert row["updated_at"] >= first_updated_at
