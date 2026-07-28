"""Orchestrate multi-source LAN discovery, fingerprinting, persistence, and alerts."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address

from backend import config
from backend.db import models
from backend.discovery.arp_scanner import scan as arp_scan
from backend.discovery.device_fingerprint import fingerprint_device
from backend.discovery.mdns_scanner import discover as mdns_discover
from backend.discovery.neighbor_scanner import scan as neighbor_scan
from backend.discovery.ssdp_scanner import discover as ssdp_discover

logger = logging.getLogger("homeradar.scan_runner")


def _run_source(name: str, function):
    try:
        return function()
    except Exception:
        logger.exception("%s discovery failed", name)
        return {} if name in {"mDNS", "SSDP"} else []


def _merge_observation(target: dict, incoming: dict) -> None:
    for key in ("mdns_services", "service_names", "ssdp_types"):
        if incoming.get(key):
            target[key] = sorted(set(target.get(key, [])) | set(incoming[key]))
    if incoming.get("properties"):
        target.setdefault("properties", {}).update(incoming["properties"])
    for key in ("model", "server", "usn", "location"):
        if incoming.get(key) and not target.get(key):
            target[key] = incoming[key]


def merge_discovery_results(
    arp_hosts: list[dict],
    neighbor_hosts: list[dict],
    mdns_results: dict[str, dict],
    ssdp_results: dict[str, dict],
) -> list[dict]:
    """Combine discovery sources into fingerprintable hosts.

    MAC address remains the stable identity. mDNS/SSDP-only observations are
    retained when the same IP exists in an ARP or operating-system neighbor result.
    """
    by_mac: dict[str, dict] = {}
    mac_by_ip: dict[str, str] = {}

    for default_source, hosts in (("arp", arp_hosts), ("neighbor_cache", neighbor_hosts)):
        for host in hosts:
            mac = str(host.get("mac", "")).upper()
            ip = host.get("ip")
            if not mac or not ip:
                continue
            source_name = str(host.get("source") or default_source)
            entry = by_mac.setdefault(
                mac,
                {"ip": ip, "mac": mac, "observation": {"sources": []}},
            )
            entry["ip"] = ip
            entry["observation"]["sources"] = sorted(
                set(entry["observation"]["sources"]) | {source_name}
            )
            mac_by_ip[ip] = mac

    for source_name, observations in (("mdns", mdns_results), ("ssdp", ssdp_results)):
        for ip, observation in observations.items():
            found_mac = mac_by_ip.get(ip)
            if found_mac is None:
                logger.debug("Skipping %s-only host %s because no MAC address is known", source_name, ip)
                continue
            target = by_mac[found_mac]["observation"]
            target["sources"] = sorted(set(target["sources"]) | {source_name})
            _merge_observation(target, observation)

    return sorted(by_mac.values(), key=lambda host: ip_address(host["ip"]))


def _discover_hosts() -> list[dict]:
    subnet = None if config.LAN_SUBNET == "auto" else config.LAN_SUBNET
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            "ARP": pool.submit(_run_source, "ARP", lambda: arp_scan(subnet=subnet)),
            "neighbors": pool.submit(_run_source, "neighbors", neighbor_scan),
            "mDNS": pool.submit(_run_source, "mDNS", mdns_discover),
            "SSDP": pool.submit(_run_source, "SSDP", ssdp_discover),
        }
        results = {name: future.result() for name, future in futures.items()}

    hosts = merge_discovery_results(
        results["ARP"],
        results["neighbors"],
        results["mDNS"],
        results["SSDP"],
    )
    logger.info(
        "Discovery found %d host(s): ARP=%d neighbor=%d mDNS=%d SSDP=%d",
        len(hosts),
        len(results["ARP"]),
        len(results["neighbors"]),
        len(results["mDNS"]),
        len(results["SSDP"]),
    )
    return hosts


def _fingerprint_hosts(hosts: list[dict]) -> list[dict]:
    if not hosts:
        return []
    workers = max(1, min(config.MAX_FINGERPRINT_WORKERS, len(hosts)))
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                fingerprint_device,
                host["ip"],
                host["mac"],
                host["observation"],
            ): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results.append(future.result())
            except Exception:
                logger.exception("Fingerprinting failed for %s", host["ip"])
    return sorted(results, key=lambda item: ip_address(item["ip"]))


def run_discovery_scan(conn) -> list[dict]:
    """Perform one full discovery pass and return fingerprinted devices."""
    results = _fingerprint_hosts(_discover_hosts())
    for info in results:
        previous = conn.execute(
            "SELECT id, ip, device_type FROM devices WHERE mac = ?",
            (info["mac"],),
        ).fetchone()
        is_new = previous is None

        device_id = models.upsert_device(
            conn,
            mac=info["mac"],
            ip=info["ip"],
            hostname=info["hostname"],
            vendor=info["vendor"],
            model=info["model"],
            device_type=info["device_type"],
            confidence=info["confidence"],
            open_ports=info["open_ports"],
            services=info["services"],
            discovery_sources=info["discovery_sources"],
            fingerprint=info["fingerprint"],
        )
        info["id"] = device_id

        if is_new:
            label = info["hostname"] or info["model"] or info["vendor"] or "Unknown device"
            models.create_alert(
                conn,
                device_id=device_id,
                severity="warning",
                title="New device connected",
                description=(
                    f"{label} joined the network at {info['ip']} "
                    f"({info['mac']}); classified as {info['device_type']} "
                    f"with {round(info['confidence'] * 100)}% confidence."
                ),
            )

    return results
