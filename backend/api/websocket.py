"""Real-time dashboard snapshots over WebSocket."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.db import get_conn, models
from backend.monitor.trust_scoring import household_score

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


@router.websocket("/ws")
async def dashboard_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(dashboard_snapshot())
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=3)
            except TimeoutError:
                pass
    except WebSocketDisconnect:
        return
