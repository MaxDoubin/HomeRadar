from backend.discovery.neighbor_scanner import parse_neighbor_output
from backend.discovery.scan_runner import merge_discovery_results
from backend.discovery.ssdp_scanner import parse_response


def test_parse_ssdp_response():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"SERVER: Linux/5.10 UPnP/1.0 Router/2.0\r\n"
        b"LOCATION: http://192.168.1.1:5000/device.xml\r\n\r\n"
    )
    headers = parse_response(payload)
    assert headers["st"].endswith("InternetGatewayDevice:1")
    assert headers["server"].startswith("Linux")
    assert headers["location"].startswith("http://192.168.1.1")


def test_parse_linux_neighbor_cache():
    output = (
        "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.3 dev eth0 FAILED\n"
    )
    assert parse_neighbor_output(output) == [
        {
            "ip": "192.168.1.2",
            "mac": "AA:BB:CC:DD:EE:FF",
            "source": "neighbor_cache",
        }
    ]


def test_parse_bsd_arp_cache():
    output = "? (192.168.1.10) at b8:27:eb:00:00:01 on en0 ifscope [ethernet]\n"
    assert parse_neighbor_output(output)[0]["mac"] == "B8:27:EB:00:00:01"


def test_merge_discovery_sources_enriches_matching_host():
    hosts = merge_discovery_results(
        arp_hosts=[{"ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF"}],
        neighbor_hosts=[],
        mdns_results={
            "192.168.1.20": {
                "mdns_services": ["_googlecast._tcp.local."],
                "service_names": ["Living Room._googlecast._tcp.local."],
                "properties": {"md": "Chromecast"},
                "model": "Chromecast",
            }
        },
        ssdp_results={
            "192.168.1.20": {
                "ssdp_types": ["urn:dial-multiscreen-org:device:dial:1"],
                "server": "Chromecast UPnP/1.0",
            }
        },
    )
    assert len(hosts) == 1
    observation = hosts[0]["observation"]
    assert observation["sources"] == ["arp", "mdns", "ssdp"]
    assert observation["model"] == "Chromecast"
    assert "_googlecast._tcp.local." in observation["mdns_services"]


def test_merge_skips_mdns_only_host_without_stable_mac():
    hosts = merge_discovery_results(
        arp_hosts=[],
        neighbor_hosts=[],
        mdns_results={"192.168.1.50": {"mdns_services": ["_http._tcp.local."]}},
        ssdp_results={},
    )
    assert hosts == []
