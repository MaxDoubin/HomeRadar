from backend.discovery.device_fingerprint import classify
from backend.discovery.oui_lookup import lookup_vendor


def test_classify_camera_by_port():
    assert classify(vendor=None, hostname=None, open_ports=[554]) == "iot_camera"


def test_classify_printer_by_port():
    assert classify(vendor=None, hostname=None, open_ports=[9100]) == "printer"


def test_classify_smart_tv_by_hostname():
    assert classify(vendor=None, hostname="LivingRoom-Roku", open_ports=[]) == "smart_tv"


def test_classify_computer_by_vendor_hint():
    assert classify(vendor="Raspberry Pi Foundation", hostname=None, open_ports=[]) == "computer"


def test_classify_unknown_with_no_signals():
    assert classify(vendor=None, hostname=None, open_ports=[]) == "unknown"


def test_lookup_vendor_falls_back_to_offline_table():
    # This OUI is in the built-in fallback table, so it should resolve even
    # without network access or the mac-vendor-lookup package installed.
    assert lookup_vendor("B8:27:EB:00:00:00") == "Raspberry Pi Foundation"
