"""Authenticated real-time dashboard snapshots over WebSocket."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.db import get_conn, models
from backend.monitor.trust_scoring import household_score
from backend.pairing import verify_token
from backend.security import is_local_host

router = APIRouter()


def dashboard_snapshot() -> dict:
    with get_conn() as conn:
        devices = models.list_devices(conn)
        alerts = models.list_alerts(conn, unresolved_only=True)
        traffic = models.traffic_summary(conn, hours=24)
        score = household_score(conn)
    return {
        "type": "snapshot",
        "status": {
            "device_count": len(devices),
            "open_alert_count": len(alerts),
            "security_score": score["score"],
        },
        "devices": devices,
        "alerts": alerts[:25],
        "traffic": traffic,
    }


def _websocket_token(websocket: WebSocket) -> str | None:
    token = websocket.query_params.get("token")
    if not token:
        token = websocket.headers.get("x-homeradar-token")
    authorization = websocket.headers.get("authorization", "")
    if not token and authorization:
        scheme, separator, value = authorization.partition(" ")
        if separator and scheme.lower() == "bearer":
            token = value.strip()
    if not token:
        token = websocket.cookies.get("homeradar_token")
    return token or None


def _token_is_valid(token: str | None) -> bool:
    if not token:
        return False
    with get_conn() as conn:
        return verify_token(conn, token)


@router.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket):
    local = is_local_host(websocket.client.host if websocket.client else None)
    token = _websocket_token(websocket)
    token_valid = _token_is_valid(token)

    # A supplied bad credential is always rejected, even from loopback. A
    # credential-free connection is allowed only for the appliance's own UI.
    if (token and not token_valid) or (not local and not token_valid):
        await websocket.close(code=4401, reason="Pairing token required")
        return

    await websocket.accept()
    try:
        while True:
            if token and not _token_is_valid(token):
                await websocket.close(code=4401, reason="Pairing token was revoked")
                return
            await websocket.send_json(dashboard_snapshot())
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=3)
            except TimeoutError:
                pass
    except WebSocketDisconnect:
        return
