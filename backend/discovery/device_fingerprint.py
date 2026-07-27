"""Multi-signal device fingerprinting for consumer and smart-home networks.

No single signal is trustworthy enough to identify a device. Home Radar combines
vendor, reverse DNS, open ports, mDNS services, SSDP device types, advertised model
names, and discovery source into a scored classification with human-readable evidence.
"""
from __future__ import annotations

import re
import socket
from collections import defaultdict
from typing import Iterable

from backend.discovery.oui_lookup import lookup_vendor
from backend.discovery.port_scanner import scan_ports

_VENDOR_RULES = (
    (("raspberry pi", "intel corporate", "dell", "lenovo", "framework computer"), "computer", 5),
    (("vmware", "virtualbox", "parallels", "xen"), "virtual_machine", 9),
    (("synology", "qnap", "asustor", "western digital"), "nas", 9),
    (("hewlett packard", "hp inc", "brother", "epson", "xerox", "lexmark"), "printer", 7),
    (("hikvision", "dahua", "axis", "reolink", "amcrest", "wyze", "arlo"), "iot_camera", 8),
    (("ring",), "doorbell", 8),
    (("ubiquiti", "aruba", "ruckus"), "access_point", 7),
    (("netgear", "tp-link", "arris", "eero", "cisco", "juniper", "mikrotik"), "router", 5),
    (("roku",), "streaming_device", 10),
    (("vizio", "tcl", "hisense", "lg electronics"), "smart_tv", 7),
    (("sonos", "bose"), "smart_speaker", 8),
    (("ecobee",), "thermostat", 10),
    (("philips lighting", "signify"), "smart_home_hub", 7),
    (("espressif", "tuya", "shelly"), "iot_device", 6),
    (("nintendo",), "game_console", 9),
)

_NAME_RULES = (
    (("iphone", "android phone", "pixel phone", "galaxy phone"), "phone", 12),
    (("ipad", "tablet", "galaxy tab", "kindle"), "tablet", 12),
    (("macbook", "imac", "desktop", "laptop", "thinkpad", "chromebook"), "computer", 10),
    (("windows-pc", "windows pc", "workstation"), "computer", 8),
    (("synology", "diskstation", "qnap", "nas"), "nas", 12),
    (("printer", "officejet", "laserjet", "deskjet", "epson", "brother"), "printer", 12),
    (("camera", "ipcam", "webcam", "wyze cam", "reolink", "hikvision"), "iot_camera", 12),
    (("doorbell", "ring-"), "doorbell", 12),
    (("apple tv", "appletv", "chromecast", "fire tv", "firetv", "roku"), "streaming_device", 12),
    (("smart tv", "smarttv", "bravia", "webos", "vizio", "hisense"), "smart_tv", 11),
    (("xbox", "playstation", "ps4", "ps5", "nintendo switch"), "game_console", 12),
    (("homepod", "sonos", "echo dot", "echo show", "google home", "nest audio"), "smart_speaker", 12),
    (("homeassistant", "home assistant", "hue bridge", "smartthings", "home hub"), "smart_home_hub", 12),
    (("thermostat", "ecobee", "nest thermostat"), "thermostat", 12),
    (("smart plug", "smartplug", "kasa", "shelly plug"), "smart_plug", 11),
    (("watch", "fitbit", "wearable"), "wearable", 9),
    (("router", "gateway", "firewall", "dream machine"), "router", 11),
    (("access point", "unifi ap", "wireless ap"), "access_point", 11),
    (("switch",), "network_switch", 7),
    (("plex", "jellyfin", "emby"), "media_server", 11),
    (("server", "proxmox", "truenas", "home lab", "homelab"), "server", 8),
)

_SERVICE_RULES = (
    (("_ipp.", "_ipps.", "_printer.", "_pdl-datastream.", "_scanner."), "printer", 11),
    (("_googlecast.",), "streaming_device", 8),
    (("_airplay.",), "streaming_device", 6),
    (("_raop.", "_sonos.", "_amzn-wplay."), "smart_speaker", 8),
    (("_rtsp.", "_axis-video."), "iot_camera", 11),
    (("_home-assistant.", "_hue."), "smart_home_hub", 12),
    (("_hap.", "_homekit.", "_matter.", "_matterc."), "iot_device", 7),
    (("_plexmediasvr.",), "media_server", 12),
    (("_workstation.",), "computer", 8),
    (("_smb.",), "computer", 4),
)

_SSDP_RULES = (
    (("internetgatewaydevice", "wandevice", "wanconnectiondevice"), "router", 12),
    (("mediarenderer", "roku", "dial"), "streaming_device", 9),
    (("mediaserver",), "media_server", 9),
    (("printer",), "printer", 10),
    (("camera", "digital security camera"), "iot_camera", 10),
    (("xbox", "playstation"), "game_console", 11),
)

_PORT_RULES: dict[int, tuple[str, int, str]] = {
    515: ("printer", 8, "LPD printing"),
    554: ("iot_camera", 10, "RTSP video"),
    631: ("printer", 9, "IPP printing"),
    1400: ("smart_speaker", 5, "speaker control"),
    1883: ("iot_device", 5, "MQTT"),
    3389: ("computer", 8, "Remote Desktop"),
    3689: ("media_server", 5, "media sharing"),
    5357: ("printer", 4, "web services discovery"),
    8008: ("streaming_device", 6, "Cast control"),
    8009: ("streaming_device", 7, "Cast transport"),
    8060: ("streaming_device", 11, "Roku control"),
    8123: ("smart_home_hub", 12, "Home Assistant"),
    8883: ("iot_device", 5, "secure MQTT"),
    9000: ("smart_speaker", 4, "media control"),
    9100: ("printer", 10, "raw printing"),
    32400: ("media_server", 12, "Plex"),
    62078: ("phone", 11, "iOS sync"),
}

_MODEL_KEYS = ("model", "modelname", "md", "am", "ty", "product")


def lookup_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _normalized_text(values: Iterable[str | None]) -> str:
    return " ".join(value.lower() for value in values if value)


def _add(
    scores: dict[str, int],
    evidence: dict[str, list[str]],
    category: str,
    points: int,
    reason: str,
) -> None:
    scores[category] += points
    if reason not in evidence[category]:
        evidence[category].append(reason)


def _apply_rules(
    text: str,
    rules: Iterable[tuple[tuple[str, ...], str, int]],
    source: str,
    scores: dict[str, int],
    evidence: dict[str, list[str]],
) -> None:
    for tokens, category, points in rules:
        matched = next((token for token in tokens if token in text), None)
        if matched:
            _add(scores, evidence, category, points, f"{source}: {matched}")


def classify_details(
    vendor: str | None,
    hostname: str | None,
    open_ports: list[int],
    *,
    mdns_services: list[str] | None = None,
    service_names: list[str] | None = None,
    ssdp_types: list[str] | None = None,
    ssdp_server: str | None = None,
    model: str | None = None,
) -> dict:
    """Return a scored device classification and the evidence behind it."""
    scores: dict[str, int] = defaultdict(int)
    evidence: dict[str, list[str]] = defaultdict(list)

    vendor_text = (vendor or "").lower()
    name_text = _normalized_text((hostname, model, *(service_names or [])))
    services_text = _normalized_text(mdns_services or [])
    ssdp_text = _normalized_text((ssdp_server, *(ssdp_types or [])))

    _apply_rules(vendor_text, _VENDOR_RULES, "vendor", scores, evidence)
    _apply_rules(name_text, _NAME_RULES, "name/model", scores, evidence)
    _apply_rules(services_text, _SERVICE_RULES, "mDNS", scores, evidence)
    _apply_rules(ssdp_text, _SSDP_RULES, "SSDP", scores, evidence)

    for port in set(open_ports):
        rule = _PORT_RULES.get(port)
        if rule:
            category, points, service = rule
            _add(scores, evidence, category, points, f"port {port}: {service}")

    port_set = set(open_ports)
    if {139, 445} <= port_set:
        _add(scores, evidence, "computer", 5, "ports 139/445: SMB host")
    if 22 in port_set:
        _add(scores, evidence, "server", 3, "port 22: SSH")
    if {53, 80} <= port_set or {53, 443} <= port_set:
        _add(scores, evidence, "router", 3, "DNS plus web management")
    if {5000, 5001} & port_set and ("synology" in vendor_text or "nas" in name_text):
        _add(scores, evidence, "nas", 8, "NAS management service")

    # Resolve common ambiguous ecosystems only when a second signal is available.
    combined = f"{name_text} {services_text} {ssdp_text}"
    if "apple" in vendor_text:
        if any(token in combined for token in ("iphone", "_companion-link", "_apple-mobdev")):
            _add(scores, evidence, "phone", 7, "Apple mobile-device signals")
        elif "ipad" in combined:
            _add(scores, evidence, "tablet", 8, "Apple tablet signals")
        elif any(token in combined for token in ("apple tv", "appletv", "_airplay")):
            _add(scores, evidence, "streaming_device", 5, "Apple media signals")
        elif any(token in combined for token in ("macbook", "imac", "_workstation")):
            _add(scores, evidence, "computer", 5, "Apple computer signals")

    if not scores:
        return {"device_type": "unknown", "confidence": 0.0, "evidence": [], "scores": {}}

    category, top_score = max(scores.items(), key=lambda item: (item[1], item[0]))
    sorted_scores = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    runner_up = sorted_scores[1][1] if len(sorted_scores) > 1 else 0
    margin = top_score - runner_up
    confidence = min(0.99, 0.35 + (top_score * 0.035) + (margin * 0.015))
    return {
        "device_type": category,
        "confidence": round(confidence, 2),
        "evidence": evidence[category],
        "scores": dict(sorted_scores),
    }


def classify(vendor: str | None, hostname: str | None, open_ports: list[int]) -> str:
    """Backward-compatible category-only classifier."""
    return classify_details(vendor, hostname, open_ports)["device_type"]


def _clean_service_name(name: str) -> str:
    return re.sub(r"\._[^.]+\._(?:tcp|udp)\.local\.?$", "", name, flags=re.IGNORECASE)


def _advertised_model(observation: dict) -> str | None:
    if observation.get("model"):
        return str(observation["model"])[:160]
    properties = observation.get("properties") or {}
    for key in _MODEL_KEYS:
        if properties.get(key):
            return str(properties[key])[:160]
    server = observation.get("server")
    return str(server)[:160] if server else None


def fingerprint_device(ip: str, mac: str, observation: dict | None = None) -> dict:
    """Run active and advertised fingerprinting signals for one discovered host."""
    observation = observation or {}
    vendor = lookup_vendor(mac)
    hostname = lookup_hostname(ip)
    service_names = [_clean_service_name(name) for name in observation.get("service_names", [])]
    model = _advertised_model(observation)
    open_ports = scan_ports(ip)
    classification = classify_details(
        vendor,
        hostname,
        open_ports,
        mdns_services=observation.get("mdns_services", []),
        service_names=service_names,
        ssdp_types=observation.get("ssdp_types", []),
        ssdp_server=observation.get("server"),
        model=model,
    )
    services = sorted(
        set(observation.get("mdns_services", []))
        | set(observation.get("ssdp_types", []))
    )
    return {
        "ip": ip,
        "mac": mac.upper(),
        "vendor": vendor,
        "hostname": hostname,
        "model": model,
        "open_ports": open_ports,
        "services": services,
        "discovery_sources": sorted(set(observation.get("sources", ["arp"]))),
        "device_type": classification["device_type"],
        "confidence": classification["confidence"],
        "fingerprint": {
            "evidence": classification["evidence"],
            "scores": classification["scores"],
            "service_names": service_names,
            "ssdp_server": observation.get("server"),
            "ssdp_usn": observation.get("usn"),
        },
    }
