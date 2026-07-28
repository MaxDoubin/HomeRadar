from __future__ import annotations

from backend import config
from backend.discovery import port_scanner


# ---------------------------------------------------------------------------
# _is_port_open
# ---------------------------------------------------------------------------

class _FakeSock:
    def __init__(self, connect_ex_result=None, connect_ex_raises=None):
        self._result = connect_ex_result
        self._raises = connect_ex_raises

    def settimeout(self, value):
        pass

    def connect_ex(self, address):
        if self._raises is not None:
            raise self._raises
        return self._result

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_is_port_open_true_when_connect_succeeds(monkeypatch):
    monkeypatch.setattr(
        port_scanner.socket, "socket", lambda *a, **kw: _FakeSock(connect_ex_result=0)
    )
    assert port_scanner._is_port_open("192.168.1.1", 22, 0.1) is True


def test_is_port_open_false_when_connect_raises(monkeypatch):
    monkeypatch.setattr(
        port_scanner.socket,
        "socket",
        lambda *a, **kw: _FakeSock(connect_ex_raises=OSError("boom")),
    )
    assert port_scanner._is_port_open("192.168.1.1", 22, 0.1) is False


def test_is_port_open_false_when_connect_returns_nonzero(monkeypatch):
    monkeypatch.setattr(
        port_scanner.socket, "socket", lambda *a, **kw: _FakeSock(connect_ex_result=111)
    )
    assert port_scanner._is_port_open("192.168.1.1", 22, 0.1) is False


# ---------------------------------------------------------------------------
# scan_ports
# ---------------------------------------------------------------------------

def test_scan_ports_preserves_input_order(monkeypatch):
    open_ports = {22, 8080}

    def fake_is_port_open(ip, port, timeout):
        return port in open_ports

    monkeypatch.setattr(port_scanner, "_is_port_open", fake_is_port_open)
    result = port_scanner.scan_ports("192.168.1.1", ports=[443, 22, 8080])
    assert result == [22, 8080]


def test_scan_ports_empty_list_short_circuits(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("_is_port_open should not be called for an empty port list")

    monkeypatch.setattr(port_scanner, "_is_port_open", boom)
    assert port_scanner.scan_ports("192.168.1.1", ports=[]) == []


def test_scan_ports_defaults_to_common_ports(monkeypatch):
    called_ports = []

    def fake_is_port_open(ip, port, timeout):
        called_ports.append(port)
        return False

    monkeypatch.setattr(port_scanner, "_is_port_open", fake_is_port_open)
    result = port_scanner.scan_ports("192.168.1.1", ports=None)
    assert result == []
    assert set(called_ports) == set(config.COMMON_PORTS)
