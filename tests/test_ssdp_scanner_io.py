from __future__ import annotations

from backend.discovery import ssdp_scanner


def _response(status_line, headers):
    lines = [status_line] + [f"{key}: {value}" for key, value in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _sock_with_setsockopt(fake_socket_factory, **kwargs):
    class SockWithOpt(fake_socket_factory):
        def setsockopt(self, *a, **kw):
            pass

    return SockWithOpt(**kwargs)


def test_discover_sends_msearch_and_parses_response(monkeypatch, fake_socket_factory):
    payload = _response(
        "HTTP/1.1 200 OK",
        {
            "ST": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "SERVER": "Linux/5.10 UPnP/1.0 Router/2.0",
            "LOCATION": "http://192.168.1.1:5000/device.xml",
        },
    )
    fake_sock = _sock_with_setsockopt(
        fake_socket_factory, recv_queue=[(payload, ("192.168.1.1", 1900))]
    )
    monkeypatch.setattr(ssdp_scanner.socket, "socket", lambda *a, **kw: fake_sock)

    result = ssdp_scanner.discover(timeout=0.05)

    assert len(fake_sock.sent) == 1
    sent_payload, sent_address = fake_sock.sent[0]
    assert sent_payload == ssdp_scanner.M_SEARCH
    assert sent_address == ssdp_scanner.SSDP_ADDRESS

    assert "192.168.1.1" in result
    entry = result["192.168.1.1"]
    assert entry["ssdp_types"] == ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]
    assert entry["server"] == "Linux/5.10 UPnP/1.0 Router/2.0"
    assert entry["location"] == "http://192.168.1.1:5000/device.xml"


def test_discover_returns_empty_when_sendto_raises(monkeypatch, fake_socket_factory):
    fake_sock = _sock_with_setsockopt(fake_socket_factory, sendto_raises=OSError("network down"))
    monkeypatch.setattr(ssdp_scanner.socket, "socket", lambda *a, **kw: fake_sock)

    assert ssdp_scanner.discover(timeout=0.05) == {}


def test_discover_accumulates_types_but_keeps_first_header_value(monkeypatch, fake_socket_factory):
    first = _response(
        "HTTP/1.1 200 OK",
        {"ST": "urn:schemas-upnp-org:device:MediaServer:1", "SERVER": "ServerA/1.0"},
    )
    second = _response(
        "HTTP/1.1 200 OK",
        {"ST": "urn:schemas-upnp-org:device:MediaRenderer:1", "SERVER": "ServerB/1.0"},
    )
    fake_sock = _sock_with_setsockopt(
        fake_socket_factory,
        recv_queue=[
            (first, ("192.168.1.50", 1900)),
            (second, ("192.168.1.50", 1900)),
        ],
    )
    monkeypatch.setattr(ssdp_scanner.socket, "socket", lambda *a, **kw: fake_sock)

    result = ssdp_scanner.discover(timeout=0.05)
    entry = result["192.168.1.50"]
    # `st` values across separate responses accumulate into a set...
    assert entry["ssdp_types"] == [
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "urn:schemas-upnp-org:device:MediaServer:1",
    ]
    # ...but scalar headers like `server` keep whichever value arrived first.
    assert entry["server"] == "ServerA/1.0"
