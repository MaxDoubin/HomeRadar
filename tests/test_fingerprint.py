from backend.discovery.device_fingerprint import classify, classify_details
from backend.discovery.oui_lookup import lookup_vendor, normalize_mac


def test_classify_camera_by_rtsp_port():
    assert classify(vendor=None, hostname=None, open_ports=[554]) == "iot_camera"


def test_classify_printer_by_port():
    assert classify(vendor=None, hostname=None, open_ports=[9100]) == "printer"


def test_classify_streaming_device_by_hostname():
    result = classify_details(None, "LivingRoom-Roku", [])
    assert result["device_type"] == "streaming_device"
    assert result["confidence"] >= 0.8


def test_classify_computer_by_vendor_hint():
    assert classify(vendor="Raspberry Pi Foundation", hostname=None, open_ports=[]) == "computer"


def test_classify_home_assistant_from_mdns():
    result = classify_details(
        vendor=None,
        hostname=None,
        open_ports=[8123],
        mdns_services=["_home-assistant._tcp.local."],
    )
    assert result["device_type"] == "smart_home_hub"
    assert any("Home Assistant" in item or "mDNS" in item for item in result["evidence"])


def test_classify_router_from_ssdp():
    result = classify_details(
        vendor=None,
        hostname=None,
        open_ports=[53, 80],
        ssdp_types=["urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
        ssdp_server="Linux UPnP/1.0",
    )
    assert result["device_type"] == "router"
    assert result["confidence"] >= 0.8


def test_classify_phone_from_ios_sync_port():
    result = classify_details("Apple", None, [62078])
    assert result["device_type"] == "phone"


def test_ambiguous_vendor_does_not_force_bad_category():
    assert classify(vendor="Apple", hostname=None, open_ports=[]) == "unknown"


def test_classify_unknown_with_no_signals():
    result = classify_details(None, None, [])
    assert result == {
        "device_type": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "scores": {},
    }


def test_lookup_vendor_falls_back_to_offline_table():
    assert lookup_vendor("B8:27:EB:00:00:00") == "Raspberry Pi Foundation"


def test_lookup_vendor_identifies_randomized_mac():
    assert lookup_vendor("02:11:22:33:44:55") == "Private / randomized MAC"


def test_normalize_mac_accepts_common_formats():
    assert normalize_mac("b8-27-eb-00-00-00") == "B8:27:EB:00:00:00"
    assert normalize_mac("not-a-mac") is None
