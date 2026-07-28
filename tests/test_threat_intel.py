import json
import urllib.error

import pytest

from backend import config
from backend.db import models
from backend.monitor import threat_intel
from backend.monitor.threat_intel import Reputation, _is_public_ip, cache_feed_indicators, check_ip


def _forbidden_urlopen(*args, **kwargs):
    raise AssertionError("urlopen should not have been called")


class FakeResponse:
    """Minimal stand-in for the object returned by urllib.request.urlopen()."""

    def __init__(self, payload):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen_factory(payload):
    def _urlopen(request, timeout=10):
        return FakeResponse(payload)

    return _urlopen


def _cache_rows(conn, indicator=None):
    if indicator is None:
        return conn.execute("SELECT * FROM threat_cache").fetchall()
    return conn.execute(
        "SELECT * FROM threat_cache WHERE indicator = ?", (indicator,)
    ).fetchall()


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.0.0.5", False),
        ("192.168.1.1", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("224.0.0.1", False),  # multicast
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("93.184.216.34", True),
        ("not-an-ip", False),
    ],
)
def test_is_public_ip(ip, expected):
    assert _is_public_ip(ip) is expected


def test_check_ip_private_returns_neutral_with_no_db_write_and_no_network(
    monkeypatch, db_path
):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "somekey")
    monkeypatch.setattr("urllib.request.urlopen", _forbidden_urlopen)
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "192.168.1.50")
        assert result.malicious is False
        assert result.confidence == 0
        assert result.source == "local"
        assert _cache_rows(conn, "192.168.1.50") == []


def test_check_ip_no_api_key_returns_neutral_without_network_call(monkeypatch, db_path):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr("urllib.request.urlopen", _forbidden_urlopen)
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "8.8.8.8")
        assert result.malicious is False
        assert result.confidence == 0
        assert result.source == "abuseipdb"
        assert "API key not configured" in result.detail
        assert _cache_rows(conn, "8.8.8.8") == []


def test_check_ip_malicious_when_confidence_at_or_above_threshold(monkeypatch, db_path):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(config, "ABUSEIPDB_MIN_CONFIDENCE", 70)
    payload = {
        "data": {
            "abuseConfidenceScore": 95,
            "totalReports": 42,
            "countryCode": "RU",
            "usageType": "Data Center",
        }
    }
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen_factory(payload))
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "8.8.8.8")
        assert result.malicious is True
        assert result.confidence == 95
        assert "42 reports" in result.detail
        rows = _cache_rows(conn, "8.8.8.8")
        assert len(rows) == 1
        assert rows[0]["is_malicious"] == 1
        assert rows[0]["confidence"] == 95


def test_check_ip_benign_when_confidence_below_threshold(monkeypatch, db_path):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(config, "ABUSEIPDB_MIN_CONFIDENCE", 70)
    payload = {
        "data": {
            "abuseConfidenceScore": 10,
            "totalReports": 1,
            "countryCode": "US",
            "usageType": "Commercial",
        }
    }
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen_factory(payload))
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "8.8.4.4")
        assert result.malicious is False
        assert result.confidence == 10
        rows = _cache_rows(conn, "8.8.4.4")
        assert len(rows) == 1
        assert rows[0]["is_malicious"] == 0


def test_check_ip_result_is_cached_and_reused_without_second_network_call(
    monkeypatch, db_path
):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(config, "ABUSEIPDB_MIN_CONFIDENCE", 70)
    payload = {
        "data": {
            "abuseConfidenceScore": 88,
            "totalReports": 5,
            "countryCode": "CN",
            "usageType": "ISP",
        }
    }
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen_factory(payload))
    with models.get_conn(db_path) as conn:
        first = check_ip(conn, "1.2.3.4")
        assert first.malicious is True
        assert first.confidence == 88

    # Second call: urlopen must NOT be invoked -- the cached row should be used.
    monkeypatch.setattr("urllib.request.urlopen", _forbidden_urlopen)
    with models.get_conn(db_path) as conn:
        second = check_ip(conn, "1.2.3.4")
        assert second.malicious is True
        assert second.confidence == 88
        assert second.source == "abuseipdb"
        # Still exactly one row -- no duplicate inserted.
        assert len(_cache_rows(conn, "1.2.3.4")) == 1


def test_check_ip_network_failure_returns_neutral_without_raising(monkeypatch, db_path):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "test-key")

    def _raise_timeout(request, timeout=10):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", _raise_timeout)
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "5.6.7.8")
        assert result.malicious is False
        assert result.confidence == 0
        assert "lookup failed" in result.detail
        assert _cache_rows(conn, "5.6.7.8") == []

    def _raise_url_error(request, timeout=10):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr("urllib.request.urlopen", _raise_url_error)
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, "5.6.7.9")
        assert result.malicious is False
        assert "lookup failed" in result.detail


def test_expired_cache_row_is_treated_as_miss(monkeypatch, db_path):
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(config, "ABUSEIPDB_MIN_CONFIDENCE", 70)
    ip = "9.9.9.9"
    with models.get_conn(db_path) as conn:
        conn.execute(
            """INSERT INTO threat_cache (
                   indicator, indicator_type, is_malicious, confidence, source,
                   detail, expires_at, updated_at
               ) VALUES (?, 'ip', 1, 99, 'abuseipdb', 'stale', '2000-01-01T00:00:00+00:00',
                         '2000-01-01T00:00:00+00:00')""",
            (ip,),
        )

    payload = {
        "data": {
            "abuseConfidenceScore": 15,
            "totalReports": 0,
            "countryCode": None,
            "usageType": None,
        }
    }
    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen_factory(payload))
    with models.get_conn(db_path) as conn:
        result = check_ip(conn, ip)
        # The stale cached row said malicious/99 -- an unexpired lookup must not use it.
        assert result.malicious is False
        assert result.confidence == 15
        rows = _cache_rows(conn, ip)
        assert len(rows) == 1
        assert rows[0]["confidence"] == 15
        assert rows[0]["is_malicious"] == 0


def test_cache_feed_indicators_stores_all_rows_and_returns_count(db_path):
    indicators = {"bad1.example.com", "bad2.example.com", "bad3.example.com"}
    with models.get_conn(db_path) as conn:
        count = cache_feed_indicators(
            conn,
            indicators,
            indicator_type="domain",
            source="community-feed",
        )
        assert count == 3
        rows = conn.execute(
            "SELECT indicator FROM threat_cache WHERE source = 'community-feed'"
        ).fetchall()
        assert {row["indicator"] for row in rows} == indicators
        for row in conn.execute(
            "SELECT * FROM threat_cache WHERE source = 'community-feed'"
        ).fetchall():
            assert row["is_malicious"] == 1
            assert row["confidence"] == 100
            assert row["detail"] == "community threat feed"
