"""Household insight endpoints: bedtime, tracker report, and vulnerability check."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend import config
from backend.db import get_conn, models
from backend.dns.policy import resolve_timezone
from backend.insights.bedtime import list_bedtimes
from backend.insights.demo_household import seed_household_activity
from backend.insights.trackers import build_device_privacy, build_privacy_report
from backend.insights.vulnerabilities import check_device, check_household
from backend.pairing import require_token

router = APIRouter()


class TimezoneUpdate(BaseModel):
    timezone: str = Field(min_length=1, max_length=64)


def _device_or_404(conn, device_id: int) -> dict:
    device = models.get_device(conn, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/bedtime")
def get_bedtimes():
    with get_conn() as conn:
        return list_bedtimes(conn)


@router.put("/bedtime/timezone", dependencies=[Depends(require_token)])
def set_household_timezone(update: TimezoneUpdate):
    """Quiet hours are wall-clock times, so record the family's IANA timezone."""
    if resolve_timezone(update.timezone) is None:
        raise HTTPException(status_code=422, detail="Unknown timezone")
    with get_conn() as conn:
        models.set_settings(conn, {"household_timezone": update.timezone})
        return list_bedtimes(conn)


@router.get("/privacy/report")
def get_privacy_report(hours: int = Query(default=24, ge=1, le=720)):
    with get_conn() as conn:
        return build_privacy_report(conn, hours)


@router.get("/devices/{device_id}/privacy")
def get_device_privacy(device_id: int, hours: int = Query(default=24, ge=1, le=720)):
    with get_conn() as conn:
        return build_device_privacy(conn, _device_or_404(conn, device_id), hours)


@router.get("/vulnerabilities")
def get_vulnerabilities():
    with get_conn() as conn:
        return check_household(conn)


@router.get("/devices/{device_id}/vulnerabilities")
def get_device_vulnerabilities(device_id: int):
    with get_conn() as conn:
        return check_device(conn, _device_or_404(conn, device_id))


@router.post("/demo/household-activity", dependencies=[Depends(require_token)])
def seed_demo_household_activity():
    """Adds clearly-labeled simulated activity so the bedtime, tracker, and
    vulnerability views have something to show in a demonstration. Only
    available when HOMERADAR_DEMO_MODE=true, exactly like /demo/simulate-attack."""
    if not config.DEMO_MODE_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    with get_conn() as conn:
        return seed_household_activity(conn)
