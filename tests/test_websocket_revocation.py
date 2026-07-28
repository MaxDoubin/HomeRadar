"""Regression test for immediate token rotation across live sockets."""

import pytest
from starlette.websockets import WebSocketDisconnect

from backend import pairing
from backend.db import models


def test_rotating_token_revokes_existing_websocket(client, db_path, auth_token):
    with client.websocket_connect(f"/ws?token={auth_token}") as websocket:
        assert websocket.receive_json()["type"] == "snapshot"
        with models.get_conn(db_path) as conn:
            replacement = pairing.regenerate_token(conn)
        assert replacement != auth_token
        websocket.send_text("next")
        with pytest.raises(WebSocketDisconnect):
            websocket.receive_json()
