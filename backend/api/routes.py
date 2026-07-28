"""REST API for inventory, security operations, traffic, settings, and digests."""
from __future__ import annotations

import ipaddress
import json
from datetime import time as clock_time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from backend import config
from backend import pairing
from backend import services
from backend.alerts.email_digest import build_digest, send_digest
from backend.db import get_conn, models
from backend.discovery.scan_runner import run_discovery_scan
from backend.dns.blocklists import normalize_domain, record_update_results
from backend.maintenance import (
    backup_path,
    create_backup,
    health_report,
    list_backups,
    prune_backups,
)
from backend.monitor.cisa_kev import search_catalog, update_catalog
from backend.monitor.exposure_audit import audit_all, audit_device
from backend.monitor.traffic_analyzer import record_connection
from backend.monitor.trust_scoring import household_score, recalculate_all, score_device
from backend.pairing import require_token
from backend.services import blocklists

router = APIRouter()


def _normalize_dns_upstreams(value: str) -> str:
    candidates = [item.strip() for item in value.split(",") if item.strip()]
    if not candidates:
        raise ValueError("At least one DNS upstream IP address is required")
    normalized: list[str] = []
    for candidate in candidates:
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError(f"Invalid DNS upstream IP address: {candidate}") from exc
        if address not in normalized:
            normalized.append(address)
    return ",".join(normalized)


def _normalize_custom_dns_records(value: str) -> str:
    if not value.strip():
        return "{}"
    try:
        records = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Custom DNS records must be a valid JSON object") from exc
    if not isinstance(records, dict):
        raise ValueError("Custom DNS records must be a JSON object")
    if len(records) > 500:
        raise ValueError("Custom DNS records cannot contain more than 500 entries")

    normalized: dict[str, str] = {}
    for raw_domain, raw_address in records.items():
        if not isinstance(raw_domain, str) or not isinstance(raw_address, str):
            raise ValueError("Custom DNS record names and addresses must be strings")
        domain = normalize_domain(raw_domain)
        if domain is None:
            raise ValueError(f"Invalid custom DNS domain: {raw_domain}")
        try:
            address = str(ipaddress.ip_address(raw_address.strip()))
        except ValueError as exc:
            raise ValueError(f"Invalid custom DNS address for {raw_domain}") from exc
        normalized[domain] = address
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


class AuthorizationUpdate(BaseModel):
    state: int = Field(ge=0, le=2)


class AlertUpdate(BaseModel):
    resolved: bool = True


class SettingsUpdate(BaseModel):
    household_name: str | None = Field(default=None, min_length=1, max_length=120)
    digest_email: str | None = Field(default=None, max_length=320)
    dns_upstream: str | None = Field(default=None, min_length=1, max_length=255)
    notifications_enabled: bool | None = None
    custom_dns_records: str | None = Field(default=None, max_length=65_536)

    @field_validator("dns_upstream")
    @classmethod
    def validate_dns_upstream(cls, value: str | None) -> str | None:
        return None if value is None else _normalize_dns_upstreams(value)

    @field_validator("custom_dns_records")
    @classmethod
    def validate_custom_dns_records(cls, value: str | None) -> str | None:
        return None if value is None else _normalize_custom_dns_records(value)


class ConnectionObservation(BaseModel):
    source_ip: str
    destination_ip: str
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required") from exc


class SetupRequest(BaseModel):
    household_name: str = Field(min_length=1, max_length=120)
    digest_email: str = Field(default="", max_length=320)
    dns_upstream: str = Field(default="1.1.1.1", min_length=1, max_length=255)
    notifications_enabled: bool = True

    @field_validator("dns_upstream")
    @classmethod
    def validate_dns_upstream(cls, value: str) -> str:
        return _normalize_dns_upstreams(value)


class PairClaimRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class DevicePolicyUpdate(BaseModel):
    internet_enabled: bool = True
    block_start: str | None = None
    block_end: str | None = None
    blocked_domains: list[str] = Field(default_factory=list, max_length=500)
    allowed_domains: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("block_start", "block_end")
    @classmethod
    def validate_schedule_time(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return clock_time.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise ValueError("Schedule times must be valid ISO times such as 22:30") from exc

    @field_validator("blocked_domains", "allowed_domains")
    @classmethod
    def validate_domains(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            domain = normalize_domain(value)
            if domain is None:
                raise ValueError(f"Invalid domain rule: {value}")
            if domain not in normalized:
                normalized.append(domain)
        return normalized


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
def get_device_traffic(
    device_id: int,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 200,
):
    with get_conn() as conn:
        if models.get_device(conn, device_id) is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return models.list_traffic(conn, device_id=device_id, limit=limit)


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
def get_traffic(
    device_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 200,
):
    with get_conn() as conn:
        return models.list_traffic(conn, device_id=device_id, limit=limit)


@router.get("/traffic/summary")
def get_traffic_summary(hours: Annotated[int, Query(ge=1, le=8_760)] = 24):
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
            dict(row)
            for row in conn.execute("SELECT * FROM blocklist_metadata ORDER BY source").fetchall()
        ]
    return {"domain_count": blocklists.count, "path": str(blocklists.path), "sources": sources}


@router.get("/dns/stats")
def get_dns_stats():
    if services.dns_proxy is None:
        return {"running": False, "listeners": {}, "cache": {}, "upstreams": {}}
    stats = services.dns_proxy.stats()
    return {"running": bool(stats.get("running", True)), **stats}


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
def get_cisa_kev(
    query: Annotated[str, Query(max_length=200)] = "",
    limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
):
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
