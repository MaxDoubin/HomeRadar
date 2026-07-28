from __future__ import annotations

import sys
import types

from backend.discovery import mdns_scanner


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_decode_properties_handles_bytes_keys_and_values():
    raw = {b"MD": b"Chromecast", b"id": b"abc123"}
    assert mdns_scanner._decode_properties(raw) == {"md": "Chromecast", "id": "abc123"}


def test_decode_properties_handles_none():
    assert mdns_scanner._decode_properties(None) == {}


def test_decode_properties_handles_str_keys_and_values():
    raw = {"Model": "Printer", "ty": 5}
    assert mdns_scanner._decode_properties(raw) == {"model": "Printer", "ty": "5"}


def test_model_from_properties_prefers_first_matching_key():
    # Lookup order is model, modelname, md, am, ty, product -- "md" wins over "am".
    props = {"am": "should not win", "md": "AppleTV"}
    assert mdns_scanner._model_from_properties(props) == "AppleTV"


def test_model_from_properties_truncates_long_values():
    props = {"model": "x" * 200}
    assert mdns_scanner._model_from_properties(props) == "x" * 160


def test_model_from_properties_returns_none_without_match():
    assert mdns_scanner._model_from_properties({"unrelated": "value"}) is None


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------

def test_discover_returns_empty_when_zeroconf_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "zeroconf", None)
    assert mdns_scanner.discover() == {}


class _FakeInfo:
    def __init__(self, addresses, properties):
        self._addresses = addresses
        self.properties = properties

    def parsed_scoped_addresses(self):
        return self._addresses


def _make_fake_zeroconf_module(
    service_map, service_info_map, zeroconf_init_raises=None, browser_init_raises=None
):
    class FakeZeroconf:
        def __init__(self):
            if zeroconf_init_raises:
                raise zeroconf_init_raises
            self.closed = False

        def get_service_info(self, service_type, name, timeout=750):
            return service_info_map.get((service_type, name))

        def close(self):
            self.closed = True

    class FakeServiceBrowser:
        def __init__(self, zeroconf, service_type, listener):
            if browser_init_raises:
                raise browser_init_raises
            for name in service_map.get(service_type, []):
                listener.add_service(zeroconf, service_type, name)

        def cancel(self):
            pass

    return types.SimpleNamespace(Zeroconf=FakeZeroconf, ServiceBrowser=FakeServiceBrowser)


def test_discover_populates_ipv4_service(monkeypatch):
    service_type = "_airplay._tcp.local."
    name = "Living Room._airplay._tcp.local."
    fake_module = _make_fake_zeroconf_module(
        service_map={service_type: [name]},
        service_info_map={
            (service_type, name): _FakeInfo(["192.168.1.9"], {b"am": b"AppleTV"}),
        },
    )
    monkeypatch.setitem(sys.modules, "zeroconf", fake_module)
    monkeypatch.setattr(mdns_scanner.time, "sleep", lambda *_a, **_kw: None)

    result = mdns_scanner.discover(timeout=0.05)
    assert "192.168.1.9" in result
    entry = result["192.168.1.9"]
    assert entry["mdns_services"] == [service_type]
    assert entry["service_names"] == ["Living Room"]
    assert entry["model"] == "AppleTV"


def test_discover_skips_ipv6_only_service(monkeypatch):
    service_type = "_raop._tcp.local."
    name = "Bedroom._raop._tcp.local."
    fake_module = _make_fake_zeroconf_module(
        service_map={service_type: [name]},
        service_info_map={
            (service_type, name): _FakeInfo(["fe80::1"], {}),
        },
    )
    monkeypatch.setitem(sys.modules, "zeroconf", fake_module)
    monkeypatch.setattr(mdns_scanner.time, "sleep", lambda *_a, **_kw: None)

    result = mdns_scanner.discover(timeout=0.05)
    assert result == {}


def test_discover_returns_empty_when_service_browser_raises_oserror(monkeypatch):
    fake_module = _make_fake_zeroconf_module(
        service_map={},
        service_info_map={},
        browser_init_raises=OSError("bind failed"),
    )
    monkeypatch.setitem(sys.modules, "zeroconf", fake_module)
    monkeypatch.setattr(mdns_scanner.time, "sleep", lambda *_a, **_kw: None)

    assert mdns_scanner.discover(timeout=0.05) == {}


def test_discover_returns_empty_when_zeroconf_init_raises_oserror(monkeypatch):
    fake_module = _make_fake_zeroconf_module(
        service_map={},
        service_info_map={},
        zeroconf_init_raises=OSError("bind failed"),
    )
    monkeypatch.setitem(sys.modules, "zeroconf", fake_module)
    monkeypatch.setattr(mdns_scanner.time, "sleep", lambda *_a, **_kw: None)

    assert mdns_scanner.discover(timeout=0.05) == {}
