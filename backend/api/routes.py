"""REST API for inventory, security operations, traffic, settings, and digests."""
from __future__ import annotations

import random

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from backend import config
from backend import pairing
from backend.alerts.email_digest import build_digest, send_digest
from backend.db import get_conn, models
from backend.discovery.scan_runner import run_discovery_scan
from backend.dns.blocklists import record_update_results
from backend.monitor.traffic_analyzer import record_connection
from backend.monitor.cisa_kev import search_catalog, update_catalog
from backend.monitor.exposure_audit import audit_all, audit_device
from backend.monitor.trust_scoring import household_score, recalculate_all, score_device
from backend.maintenance import (
    backup_path,
    create_backup,
    health_report,
    list_backups,
    prune_backups,
)
from backend.pairing import require_token
from backend.services import blocklists
from backend import services

router = APIRouter()


class AuthorizationUpdate(BaseModel):
    state: int = Field(ge=0, le=2)


class AlertUpdate(BaseModel):
    resolved: bool = True


class SettingsUpdate(BaseModel):
    household_name: str | None = Field(default=None, max_length=120)
    digest_email: str | None = Field(default=None, max_length=320)
    dns_upstream: str | None = Field(default=None, max_length=255)
    notifications_enabled: bool | None = None
    custom_dns_records: str | None = Field(default=None)


class ConnectionObservation(BaseModel):
    source_ip: str
    destination_ip: str
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)


class SetupRequest(BaseModel):
    household_name: str = Field(min_length=1, max_length=120)
    digest_email: str = Field(default="", max_length=320)
    dns_upstream: str = Field(default="1.1.1.1", max_length=255)
    notifications_enabled: bool = True


class PairClaimRequest(BaseModel):
    code: str = Field(min_length=1, max_length=16)


class DemoAttackRequest(BaseModel):
    kind: str = Field(default="deauth", pattern="^(deauth|malicious_dns)$")


class DevicePolicyUpdate(BaseModel):
    internet_enabled: bool = True
    block_start: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}(:\d{2})?$")
    block_end: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}(:\d{2})?$")
    blocked_domains: list[str] = Field(default_factory=list, max_length=500)
    allowed_domains: list[str] = Field(default_factory=list, max_length=500)


@router.get("/status")
def get_status():
    with get_conn() as conn:
        devices = models.list_devices(conn)
        open_alerts = models.list_alerts(conn, unresolved_only=True)
        score = household_score(conn)
    return {
        "device_count": len(devices),
        "open_alert_count": len(open_alerts),
        "security_score": score["score"],
        "dns_enabled": config.DNS_ENABLED,
        "blocklist_domains": blocklists.count,
    }


@router.get("/health")
def get_health():
    with get_conn() as conn:
        return health_report(conn)


@router.get("/dashboard")
def get_dashboard():
    with get_conn() as conn:
        devices = models.list_devices(conn)
        alerts = models.list_alerts(conn, unresolved_only=True)
        traffic = models.traffic_summary(conn, hours=24)
        score = household_score(conn)
        inventory = models.inventory_summary(conn)
    return {
        "status": {
            "device_count": len(devices),
            "open_alert_count": len(alerts),
            "security_score": score["score"],
            "dns_enabled": config.DNS_ENABLED,
            "blocklist_domains": blocklists.count,
        },
        "devices": devices,
        "alerts": alerts[:25],
        "traffic": traffic,
        "inventory": inventory,
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


@router.patch("/devices/{device_id}/authorization", dependencies=[Depends(require_token)])
def update_device_authorization(device_id: int, update: AuthorizationUpdate):
    with get_conn() as conn:
        if not models.set_device_authorization(conn, device_id, update.state):
            raise HTTPException(status_code=404, detail="Device not found")
        device = models.get_device(conn, device_id)
    return device


@router.get("/devices/{device_id}/traffic")
def get_device_traffic(device_id: int, limit: int = 200):
    with get_conn() as conn:
        if models.get_device(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return models.list_traffic(conn, device_id=device_id, limit=limit)


@router.get("/devices/{device_id}/traffic/timeseries")
def get_device_traffic_timeseries(device_id: int, hours: int = 24):
    """Hourly bandwidth buckets for the Devices page sparkline."""
    with get_conn() as conn:
        if models.get_device(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return {"hours": hours, "buckets": models.device_bandwidth_timeseries(conn, device_id, hours=hours)}


@router.get("/devices/{device_id}/trust")
def get_device_trust(device_id: int):
    with get_conn() as conn:
        device = models.get_device(conn, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        result = score_device(conn, device)
        history = models.trust_history(conn, device_id)
    return {
        "score": result.score,
        "reasons": result.reasons,
        "factors": result.factors,
        "history": history,
    }


@router.get("/devices/{device_id}/policy")
def get_device_policy(device_id: int):
    with get_conn() as conn:
        if models.get_device(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return models.get_device_policy(conn, device_id)


@router.put("/devices/{device_id}/policy", dependencies=[Depends(require_token)])
def update_device_policy(device_id: int, update: DevicePolicyUpdate):
    try:
        with get_conn() as conn:
            return models.set_device_policy(conn, device_id, **update.model_dump())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Device not found") from exc


@router.get("/devices/{device_id}/findings")
def get_device_findings(device_id: int):
    with get_conn() as conn:
        device = models.get_device(conn, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return audit_device(conn, device)


@router.get("/inventory/summary")
def get_inventory_summary():
    """Counts by device type and top vendor for dashboard visualizations."""
    with get_conn() as conn:
        return models.inventory_summary(conn)


@router.get("/alerts")
def get_alerts(unresolved_only: bool = False):
    with get_conn() as conn:
        return models.list_alerts(conn, unresolved_only=unresolved_only)


@router.patch("/alerts/{alert_id}", dependencies=[Depends(require_token)])
def update_alert(alert_id: int, update: AlertUpdate):
    with get_conn() as conn:
        if not models.resolve_alert(conn, alert_id, update.resolved):
            raise HTTPException(status_code=404, detail="Alert not found")
    return {"id": alert_id, "is_resolved": update.resolved}


@router.get("/traffic")
def get_traffic(device_id: int | None = None, limit: int = 200):
    with get_conn() as conn:
        return models.list_traffic(conn, device_id=device_id, limit=limit)


@router.get("/traffic/summary")
def get_traffic_summary(hours: int = 24):
    with get_conn() as conn:
        return models.traffic_summary(conn, hours=hours)


@router.post("/traffic/observe", dependencies=[Depends(require_token)])
def observe_connection(observation: ConnectionObservation):
    """Ingest a connection seen by a packet collector or router integration."""
    with get_conn() as conn:
        result = record_connection(
            conn,
            source_ip=observation.source_ip,
            destination_ip=observation.destination_ip,
            bytes_sent=observation.bytes_sent,
            bytes_received=observation.bytes_received,
        )
    return {**result, "reputation": result["reputation"].__dict__}


@router.post("/trust/recalculate", dependencies=[Depends(require_token)])
def recalculate_trust():
    with get_conn() as conn:
        updates = recalculate_all(conn)
        household = household_score(conn)
    return {"devices": updates, "household": household}


@router.get("/findings")
def get_findings(unresolved_only: bool = True):
    with get_conn() as conn:
        return models.list_findings(conn, unresolved_only=unresolved_only)


@router.post("/audit", dependencies=[Depends(require_token)])
def run_exposure_audit():
    with get_conn() as conn:
        findings = audit_all(conn)
    return {"finding_count": len(findings), "findings": findings}


@router.get("/blocklists")
def get_blocklist_status():
    with get_conn() as conn:
        sources = [
            dict(row) for row in conn.execute(
                "SELECT * FROM blocklist_metadata ORDER BY source"
            ).fetchall()
        ]
    return {"domain_count": blocklists.count, "path": str(blocklists.path), "sources": sources}


@router.get("/dns/stats")
def get_dns_stats():
    if services.dns_proxy is None:
        return {"running": False, "cache": {}, "upstreams": {}}
    return {"running": True, **services.dns_proxy.stats()}


@router.post("/dns/cache/clear", dependencies=[Depends(require_token)])
def clear_dns_cache():
    if services.dns_proxy is None:
        raise HTTPException(status_code=503, detail="DNS proxy is not running")
    services.dns_proxy.cache.clear()
    return {"cleared": True, "cache": services.dns_proxy.cache.stats()}


@router.post("/blocklists/update", dependencies=[Depends(require_token)])
def update_blocklists():
    results = blocklists.update()
    with get_conn() as conn:
        record_update_results(conn, results)
    return {
        "domain_count": blocklists.count,
        "sources": [result.__dict__ for result in results],
    }


@router.get("/threat-intel/cisa-kev")
def get_cisa_kev(query: str = "", limit: int = 100):
    with get_conn() as conn:
        return search_catalog(conn, query=query, limit=limit)


@router.post("/threat-intel/cisa-kev/update", dependencies=[Depends(require_token)])
def refresh_cisa_kev():
    try:
        with get_conn() as conn:
            count = update_catalog(conn)
        return {"records": count, "source": config.CISA_KEV_URL}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"CISA KEV update failed: {exc}") from exc


@router.get("/settings")
def get_settings():
    with get_conn() as conn:
        saved = models.get_settings(conn)
    return {
        "household_name": saved.get("household_name", config.HOUSEHOLD_NAME),
        "digest_email": saved.get("digest_email", config.SMTP_TO),
        "dns_upstream": saved.get("dns_upstream", config.DNS_UPSTREAM),
        "notifications_enabled": saved.get("notifications_enabled", "true") == "true",
        "dns_enabled": config.DNS_ENABLED,
        "setup_complete": saved.get("setup_complete", "false") == "true",
        "custom_dns_records": saved.get("custom_dns_records", "{}"),
    }


@router.patch("/settings", dependencies=[Depends(require_token)])
def update_settings(update: SettingsUpdate):
    values = {
        key: str(value).lower() if isinstance(value, bool) else value
        for key, value in update.model_dump(exclude_none=True).items()
    }
    with get_conn() as conn:
        models.set_settings(conn, values)
    return get_settings()


@router.get("/setup")
def get_setup_status():
    settings = get_settings()
    return {
        "complete": settings["setup_complete"],
        "defaults": settings,
        "requirements": {
            "dns_restart_required": True,
            "router_change_required": True,
        },
    }


@router.post("/setup")
def complete_setup(setup: SetupRequest):
    with get_conn() as conn:
        models.set_settings(
            conn,
            {
                **setup.model_dump(),
                "notifications_enabled": str(setup.notifications_enabled).lower(),
                "setup_complete": "true",
            },
        )
    return {
        "complete": True,
        "settings": get_settings(),
        "next_step": (
            "Restart the appliance after applying DNS environment changes, test one "
            "client, then update the router DHCP DNS setting."
        ),
    }


@router.get("/backups")
def get_backups():
    return {"backups": list_backups(), "retention": config.BACKUP_RETENTION_COUNT}


@router.post("/backups", dependencies=[Depends(require_token)])
def create_database_backup():
    path = create_backup()
    prune_backups()
    return {"backup": next(item for item in list_backups() if item["name"] == path.name)}


@router.get("/backups/{name}", dependencies=[Depends(require_token)])
def download_database_backup(name: str):
    path = backup_path(name)
    if path is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path, filename=path.name, media_type="application/x-sqlite3")


@router.get("/digest/preview")
def preview_digest():
    with get_conn() as conn:
        subject, body = build_digest(conn)
    return {"subject": subject, "body": body}


@router.post("/digest/send", dependencies=[Depends(require_token)])
def send_security_digest():
    try:
        with get_conn() as conn:
            return send_digest(conn, models.get_setting(conn, "digest_email", config.SMTP_TO))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/scan", dependencies=[Depends(require_token)])
def trigger_scan():
    """Manually trigger a discovery pass (ARP scan + fingerprinting)."""
    with get_conn() as conn:
        found = run_discovery_scan(conn)
    return {"devices_found": len(found), "devices": found}


@router.post("/pair/start")
def start_pairing():
    """Issue a short-lived pairing code, meant to be read off the dashboard
    or kiosk screen and typed into a mobile device to claim an API token."""
    with get_conn() as conn:
        return pairing.issue_pairing_code(conn)


@router.get("/pair/status")
def get_pairing_status():
    with get_conn() as conn:
        return pairing.pairing_status(conn)


@router.post("/pair/claim")
def claim_pairing(request: PairClaimRequest):
    with get_conn() as conn:
        token = pairing.redeem_pairing_code(conn, request.code)
    if token is None:
        raise HTTPException(status_code=400, detail="Invalid, expired, or locked-out pairing code")
    return {"token": token}


@router.get("/pair/local-token")
def get_local_token():
    """Lets the already-LAN-trusted browser dashboard self-provision a token
    without the human pairing-code ceremony meant for new mobile devices."""
    with get_conn() as conn:
        return {"token": pairing.get_or_create_token(conn)}


@router.post("/pair/regenerate", dependencies=[Depends(require_token)])
def regenerate_pairing_token():
    """Invalidate the current token and mint a new one. Requires the current
    token so a stranger can't lock the household out of their own appliance."""
    with get_conn() as conn:
        return {"token": pairing.regenerate_token(conn)}


@router.post("/demo/simulate-attack", dependencies=[Depends(require_token)])
def simulate_demo_attack(request: DemoAttackRequest):
    """Injects one clearly-labeled synthetic security event through the same
    create_alert/log_traffic code paths a real detection would use, so a demo
    audience sees the exact dashboard experience a genuine attack produces --
    without needing real attack traffic. Only available when the operator has
    explicitly set HOMERADAR_DEMO_MODE=true; a real appliance should never be
    able to fabricate its own alerts."""
    if not config.DEMO_MODE_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    with get_conn() as conn:
        device = conn.execute(
            "SELECT id, ip, mac FROM devices ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        device_id = device["id"] if device else None

        if request.kind == "malicious_dns":
            fake_ip = f"203.0.113.{random.randint(2, 254)}"  # RFC 5737 TEST-NET-3
            models.log_traffic(
                conn,
                device_id=device_id,
                dest_ip=fake_ip,
                was_blocked=True,
                threat_level="critical",
                threat_reason="Simulated for demonstration",
                query_type="A",
            )
            source = device["ip"] if device else "a device on your network"
            alert_id = models.create_alert(
                conn,
                device_id=device_id,
                severity="critical",
                title=f"Suspicious connection: {fake_ip}",
                description=(
                    f"{source} contacted {fake_ip}; demo confidence 98%. "
                    "(Simulated for demonstration -- no real threat-intel lookup "
                    "was performed.)"
                ),
            )
        else:
            fake_mac = device["mac"] if device else "aa:bb:cc:dd:ee:ff"
            alert_id = models.create_alert(
                conn,
                device_id=device_id,
                severity="critical",
                title="Wi-Fi Deauthentication Attack Detected",
                description=(
                    f"Detected 14 deauth frames from MAC {fake_mac}. This may be a "
                    "Flipper Zero or similar tool attempting to disconnect devices. "
                    "(Simulated for demonstration.)"
                ),
            )
    return {"alert_id": alert_id, "kind": request.kind}
