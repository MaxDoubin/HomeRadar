from __future__ import annotations

import socket
import sys
import types

from backend.discovery import arp_scanner


def test_detect_local_subnet_from_ip_command(monkeypatch, make_subprocess_run):
    stdout = "2: eth0    inet 192.168.1.42/24 brd 192.168.1.255 scope global eth0\n"
    monkeypatch.setattr(
        arp_scanner.subprocess, "run", make_subprocess_run(returncode=0, stdout=stdout)
    )
    assert arp_scanner.detect_local_subnet() == "192.168.1.0/24"


def test_detect_local_subnet_falls_back_to_socket_when_ip_missing(monkeypatch):
    def raise_fnf(*args, **kwargs):
        raise FileNotFoundError("no ip command")

    monkeypatch.setattr(arp_scanner.subprocess, "run", raise_fnf)

    class FakeSocket:
        def __init__(self, *a, **kw):
            pass

        def connect(self, address):
            pass

        def getsockname(self):
            return ("10.20.30.40", 55555)

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(socket, "socket", FakeSocket)
    assert arp_scanner.detect_local_subnet() == "10.20.30.0/24"


def test_detect_local_subnet_returns_none_when_everything_fails(monkeypatch):
    def raise_fnf(*args, **kwargs):
        raise FileNotFoundError("no ip command")

    monkeypatch.setattr(arp_scanner.subprocess, "run", raise_fnf)

    class FailingSocket:
        def __init__(self, *a, **kw):
            pass

        def connect(self, address):
            raise OSError("network unreachable")

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(socket, "socket", FailingSocket)
    assert arp_scanner.detect_local_subnet() is None


def test_scan_uses_active_fallback_when_scapy_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "scapy.all", None)
    monkeypatch.setattr(
        arp_scanner,
        "_active_neighbor_scan",
        lambda network, timeout: [
            {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "source": "active_neighbor"}
        ],
    )
    assert arp_scanner.scan(subnet="192.168.1.0/29") == [
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "source": "active_neighbor"}
    ]


def test_scan_returns_empty_when_subnet_cannot_be_detected(monkeypatch):
    monkeypatch.setattr(arp_scanner, "detect_local_subnet", lambda: None)
    assert arp_scanner.scan(subnet=None) == []


def test_scan_refuses_oversized_subnet():
    assert arp_scanner.scan(subnet="10.0.0.0/8") == []


def test_scan_refuses_ipv6_subnet():
    assert arp_scanner.scan(subnet="::1/128") == []


def test_scan_refuses_bogus_subnet():
    assert arp_scanner.scan(subnet="not-a-cidr") == []


def test_scan_returns_sorted_devices_and_prefers_raw_arp(monkeypatch):
    import scapy.all as scapy_all

    answered = [
        (None, types.SimpleNamespace(hwsrc="aa:bb:cc:dd:ee:02", psrc="192.168.1.6")),
        (None, types.SimpleNamespace(hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.5")),
    ]

    monkeypatch.setattr(scapy_all, "srp", lambda packet, timeout=None, verbose=None: (answered, []))
    monkeypatch.setattr(
        arp_scanner,
        "_active_neighbor_scan",
        lambda network, timeout: [
            {"ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:01", "source": "active_neighbor"}
        ],
    )

    devices = arp_scanner.scan(subnet="192.168.1.0/29")
    assert devices == [
        {"ip": "192.168.1.5", "mac": "AA:BB:CC:DD:EE:01", "source": "arp"},
        {"ip": "192.168.1.6", "mac": "AA:BB:CC:DD:EE:02", "source": "arp"},
    ]


def test_scan_falls_back_on_permission_error(monkeypatch):
    import scapy.all as scapy_all

    def fake_srp(packet, timeout=None, verbose=None):
        raise PermissionError("need root")

    monkeypatch.setattr(scapy_all, "srp", fake_srp)
    monkeypatch.setattr(
        arp_scanner,
        "_active_neighbor_scan",
        lambda network, timeout: [
            {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:03", "source": "active_neighbor"}
        ],
    )
    assert arp_scanner.scan(subnet="192.168.1.0/29") == [
        {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:03", "source": "active_neighbor"}
    ]


def test_scan_falls_back_on_os_error(monkeypatch):
    import scapy.all as scapy_all

    def fake_srp(packet, timeout=None, verbose=None):
        raise OSError("socket error")

    monkeypatch.setattr(scapy_all, "srp", fake_srp)
    monkeypatch.setattr(arp_scanner, "_active_neighbor_scan", lambda network, timeout: [])
    assert arp_scanner.scan(subnet="192.168.1.0/29") == []
