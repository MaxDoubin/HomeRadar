"""Tests for the /ws real-time dashboard snapshot endpoint."""
from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from backend.db import models


@pytest.fixture
def seeded(client, db_path):
    with models.get_conn(db_path) as conn:
        device_a = models.upsert_device(
            conn, mac="AA:BB:CC:DD:EE:01", ip="192.168.1.50",
            hostname="host1", vendor="Vendor1", device_type="computer", confidence=0.8,
        )
        device_b = models.upsert_device(
            conn, mac="AA:BB:CC:DD:EE:02", ip="192.168.1.51",
            hostname="host2", vendor="Vendor2", device_type="phone", confidence=0.6,
        )
        open_alert = models.create_alert(conn, device_a, "warning", "Open alert", "still open")
        resolved_alert = models.create_alert(conn, device_b, "info", "Resolved alert", "already handled")
        models.resolve_alert(conn, resolved_alert, True)
    return {
        "device_a": device_a,
        "device_b": device_b,
        "open_alert": open_alert,
        "resolved_alert": resolved_alert,
    }


def test_snapshot_reflects_seeded_devices_and_unresolved_alerts_only(client, seeded):
    with client.websocket_connect("/ws") as ws:
        snapshot = ws.receive_json()

    assert snapshot["type"] == "snapshot"
    assert snapshot["status"]["device_count"] == 2
    assert snapshot["status"]["open_alert_count"] == 1
    assert len(snapshot["devices"]) == 2
    assert len(snapshot["alerts"]) == 1
    assert snapshot["alerts"][0]["id"] == seeded["open_alert"]
    assert "traffic" in snapshot


def test_snapshot_caps_alerts_at_25(client, db_path, seeded):
    with models.get_conn(db_path) as conn:
        for index in range(30):
            models.create_alert(conn, seeded["device_a"], "info", f"Alert {index}")

    with client.websocket_connect("/ws") as ws:
        snapshot = ws.receive_json()

    assert snapshot["status"]["open_alert_count"] == 31  # 30 new + 1 from seeded fixture
    assert len(snapshot["alerts"]) == 25


def test_second_snapshot_reflects_db_mutation(client, db_path, seeded):
    with client.websocket_connect("/ws") as ws:
        first = ws.receive_json()
        assert first["status"]["open_alert_count"] == 1

        # Resolve the open alert in between snapshots, then nudge the server
        # loop past its `await websocket.receive_text()` wait so it re-sends
        # a snapshot without waiting out the real ~3s timeout.
        with models.get_conn(db_path) as conn:
            models.resolve_alert(conn, seeded["open_alert"], True)
        ws.send_text("x")

        second = ws.receive_json()

    assert second["type"] == "snapshot"
    assert second["status"]["open_alert_count"] == 0
    assert second["alerts"] == []


def test_connect_with_valid_token_succeeds(client, auth_token):
    with client.websocket_connect(f"/ws?token={auth_token}") as ws:
        snapshot = ws.receive_json()
    assert snapshot["type"] == "snapshot"


def test_connect_with_invalid_token_is_rejected(client, auth_token):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=wrongvalue") as ws:
            ws.receive_json()


def test_connect_with_no_token_param_still_succeeds(client):
    """Back-compat: omitting ?token entirely must keep working with no auth."""
    with client.websocket_connect("/ws") as ws:
        snapshot = ws.receive_json()
    assert snapshot["type"] == "snapshot"
