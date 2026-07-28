import logging
import sys

import pytest

from backend.db import models
from backend.monitor.threat_intel import Reputation
from backend.monitor.traffic_analyzer import PassiveTrafficMonitor, record_connection


def _malicious_reputation(confidence):
    def _check_ip(conn, ip):
        return Reputation(ip, "ip", True, confidence, "abuseipdb", f"{confidence}% confidence")

    return _check_ip


def _benign_reputation(conn, ip):
    return Reputation(ip, "ip", False, 0, "abuseipdb", "")


# ---------------------------------------------------------------------------
# record_connection
# ---------------------------------------------------------------------------


def test_record_connection_critical_malicious_creates_alert_and_logs_traffic(
    monkeypatch, patched_db
):
    monkeypatch.setattr(
        "backend.monitor.traffic_analyzer.check_ip", _malicious_reputation(95)
    )
    with models.get_conn(patched_db) as conn:
        result = record_connection(
            conn,
            source_ip="192.168.1.50",
            destination_ip="6.6.6.6",
            bytes_sent=100,
            bytes_received=200,
        )
        assert result["threat_level"] == "critical"
        assert result["device_id"] is None

        traffic_rows = conn.execute(
            "SELECT * FROM traffic_logs WHERE dest_ip = ?", ("6.6.6.6",)
        ).fetchall()
        assert len(traffic_rows) == 1
        assert traffic_rows[0]["threat_level"] == "critical"
        assert traffic_rows[0]["threat_reason"] == "95% confidence"
        assert traffic_rows[0]["bytes_sent"] == 100
        assert traffic_rows[0]["bytes_received"] == 200

        alert_rows = conn.execute(
            "SELECT * FROM alerts WHERE description LIKE ?", ("%6.6.6.6%",)
        ).fetchall()
        assert len(alert_rows) == 1
        assert alert_rows[0]["severity"] == "critical"
        assert "6.6.6.6" in alert_rows[0]["title"]


def test_record_connection_warning_malicious_below_critical_threshold(
    monkeypatch, patched_db
):
    monkeypatch.setattr(
        "backend.monitor.traffic_analyzer.check_ip", _malicious_reputation(75)
    )
    with models.get_conn(patched_db) as conn:
        result = record_connection(
            conn, source_ip="192.168.1.51", destination_ip="7.7.7.7"
        )
        assert result["threat_level"] == "warning"
        alert_rows = conn.execute(
            "SELECT * FROM alerts WHERE description LIKE ?", ("%7.7.7.7%",)
        ).fetchall()
        assert len(alert_rows) == 1
        assert alert_rows[0]["severity"] == "warning"


def test_record_connection_benign_logs_traffic_without_alert(monkeypatch, patched_db):
    monkeypatch.setattr("backend.monitor.traffic_analyzer.check_ip", _benign_reputation)
    with models.get_conn(patched_db) as conn:
        result = record_connection(
            conn, source_ip="192.168.1.52", destination_ip="8.8.8.8"
        )
        assert result["threat_level"] == "none"
        traffic_rows = conn.execute(
            "SELECT * FROM traffic_logs WHERE dest_ip = ?", ("8.8.8.8",)
        ).fetchall()
        assert len(traffic_rows) == 1
        assert traffic_rows[0]["threat_level"] == "none"
        assert traffic_rows[0]["threat_reason"] is None
        alert_rows = conn.execute("SELECT * FROM alerts").fetchall()
        assert alert_rows == []


def test_record_connection_unknown_source_device_logs_with_null_device_id(
    monkeypatch, patched_db
):
    monkeypatch.setattr("backend.monitor.traffic_analyzer.check_ip", _benign_reputation)
    with models.get_conn(patched_db) as conn:
        result = record_connection(
            conn, source_ip="192.168.99.99", destination_ip="9.9.9.9"
        )
        assert result["device_id"] is None
        row = conn.execute(
            "SELECT device_id FROM traffic_logs WHERE dest_ip = ?", ("9.9.9.9",)
        ).fetchone()
        assert row["device_id"] is None


def test_record_connection_known_source_device_populates_device_id(
    monkeypatch, patched_db
):
    monkeypatch.setattr("backend.monitor.traffic_analyzer.check_ip", _benign_reputation)
    with models.get_conn(patched_db) as conn:
        device_id = models.upsert_device(
            conn, "AA:BB:CC:DD:EE:FF", "192.168.1.60", "laptop", "Acme"
        )
        result = record_connection(
            conn, source_ip="192.168.1.60", destination_ip="10.10.10.10"
        )
        assert result["device_id"] == device_id
        row = conn.execute(
            "SELECT device_id FROM traffic_logs WHERE dest_ip = ?", ("10.10.10.10",)
        ).fetchone()
        assert row["device_id"] == device_id


# ---------------------------------------------------------------------------
# PassiveTrafficMonitor._packet direction filtering
# ---------------------------------------------------------------------------


def test_packet_private_to_public_is_recorded():
    from scapy.layers.inet import IP

    monitor = PassiveTrafficMonitor()
    packet = IP(src="192.168.1.5", dst="8.8.8.8") / b"payload"
    monitor._packet(packet)
    assert ("192.168.1.5", "8.8.8.8") in monitor._flows
    assert monitor._flows[("192.168.1.5", "8.8.8.8")][0] == len(packet)


def test_packet_public_to_private_is_ignored():
    from scapy.layers.inet import IP

    monitor = PassiveTrafficMonitor()
    packet = IP(src="8.8.8.8", dst="192.168.1.5") / b"payload"
    monitor._packet(packet)
    assert dict(monitor._flows) == {}


def test_packet_private_to_private_is_ignored():
    from scapy.layers.inet import IP

    monitor = PassiveTrafficMonitor()
    packet = IP(src="192.168.1.5", dst="192.168.1.6") / b"payload"
    monitor._packet(packet)
    assert dict(monitor._flows) == {}


def test_packet_non_ip_packet_is_ignored():
    from scapy.layers.l2 import Ether

    monitor = PassiveTrafficMonitor()
    packet = Ether()
    monitor._packet(packet)
    assert dict(monitor._flows) == {}


def test_packet_accumulates_multiple_packets_for_same_flow():
    from scapy.layers.inet import IP

    monitor = PassiveTrafficMonitor()
    packet = IP(src="192.168.1.5", dst="8.8.8.8") / b"payload"
    monitor._packet(packet)
    monitor._packet(packet)
    assert monitor._flows[("192.168.1.5", "8.8.8.8")][0] == 2 * len(packet)


# ---------------------------------------------------------------------------
# PassiveTrafficMonitor._flush
# ---------------------------------------------------------------------------


def test_flush_with_no_flows_does_not_touch_db(monkeypatch, patched_db):
    called = {"value": False}

    def _spy_get_conn(*args, **kwargs):
        called["value"] = True
        raise AssertionError("get_conn should not be called when there are no flows")

    monkeypatch.setattr("backend.monitor.traffic_analyzer.get_conn", _spy_get_conn)
    monitor = PassiveTrafficMonitor()
    monitor._flush()
    assert called["value"] is False


def test_flush_drains_flows_and_writes_traffic_rows(monkeypatch, patched_db):
    monkeypatch.setattr("backend.monitor.traffic_analyzer.check_ip", _benign_reputation)
    monitor = PassiveTrafficMonitor()
    monitor._flows[("192.168.1.5", "8.8.8.8")][0] = 1234
    monitor._flows[("192.168.1.6", "9.9.9.9")][1] = 5678

    monitor._flush()

    # Internal flow-tracking structure must be drained/reset.
    assert dict(monitor._flows) == {}

    with models.get_conn(patched_db) as conn:
        rows = {
            row["dest_ip"]: row
            for row in conn.execute("SELECT * FROM traffic_logs").fetchall()
        }
    assert rows["8.8.8.8"]["bytes_sent"] == 1234
    assert rows["9.9.9.9"]["bytes_received"] == 5678


def test_flush_records_alert_for_malicious_flow(monkeypatch, patched_db):
    monkeypatch.setattr(
        "backend.monitor.traffic_analyzer.check_ip", _malicious_reputation(99)
    )
    monitor = PassiveTrafficMonitor()
    monitor._flows[("192.168.1.5", "6.6.6.6")][0] = 42

    monitor._flush()

    assert dict(monitor._flows) == {}
    with models.get_conn(patched_db) as conn:
        alert_rows = conn.execute(
            "SELECT * FROM alerts WHERE description LIKE ?", ("%6.6.6.6%",)
        ).fetchall()
    assert len(alert_rows) == 1
    assert alert_rows[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# PassiveTrafficMonitor.run()
# ---------------------------------------------------------------------------


class FakeSniffer:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        FakeSniffer.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def test_run_starts_and_stops_sniffer_and_returns_when_already_stopped(
    monkeypatch, patched_db
):
    FakeSniffer.instances = []
    monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeSniffer)
    monitor = PassiveTrafficMonitor(interface="eth0")
    monitor.stop()  # pre-set the stop event so the internal wait loop exits immediately

    monitor.run()

    assert len(FakeSniffer.instances) == 1
    sniffer = FakeSniffer.instances[0]
    assert sniffer.started is True
    assert sniffer.stopped is True
    assert sniffer.kwargs["iface"] == "eth0"


def test_run_swallows_import_error_from_missing_scapy_sendrecv(patched_db, caplog):
    original = sys.modules.get("scapy.sendrecv")
    sys.modules["scapy.sendrecv"] = None
    try:
        monitor = PassiveTrafficMonitor()
        monitor.stop()
        with caplog.at_level(logging.ERROR, logger="homeradar.traffic"):
            monitor.run()  # must not raise
    finally:
        if original is not None:
            sys.modules["scapy.sendrecv"] = original
        else:
            sys.modules.pop("scapy.sendrecv", None)
    assert "Passive traffic monitor failed" in caplog.text
