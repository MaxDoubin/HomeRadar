"""Core REST API: device inventory, alerts, and appliance status."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.db import get_conn, models
from backend.discovery.scan_runner import run_discovery_scan

router = APIRouter()


@router.get("/status")
def get_status():
    with get_conn() as conn:
        devices = models.list_devices(conn)
        open_alerts = models.list_alerts(conn, unresolved_only=True)
    return {
        "device_count": len(devices),
        "open_alert_count": len(open_alerts),
        "security_score": _security_score(devices, open_alerts),
    }


@router.get("/devices")
def get_devices():
    with get_conn() as conn:
        return models.list_devices(conn)


@router.get("/devices/{device_id}")
def get_device(device_id: int):
    with get_conn() as conn:
        device = models.get_device(conn, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/alerts")
def get_alerts(unresolved_only: bool = False):
    with get_conn() as conn:
        return models.list_alerts(conn, unresolved_only=unresolved_only)


@router.post("/scan")
def trigger_scan():
    """Manually trigger a discovery pass (ARP scan + fingerprinting)."""
    with get_conn() as conn:
        found = run_discovery_scan(conn)
    return {"devices_found": len(found), "devices": found}


def _security_score(devices: list[dict], open_alerts: list[dict]) -> int:
    """Household security score (0-100): average device trust score, penalized
    for open alerts. Placeholder until Phase 4's full trust-scoring model lands."""
    if not devices:
        return 100
    avg_trust = sum(d["trust_score"] for d in devices) / len(devices)
    penalty = min(len(open_alerts) * 5, 40)
    return max(0, min(100, round(avg_trust - penalty)))
