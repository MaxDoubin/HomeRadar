"""Lightweight pairing-token authentication for the Home Radar appliance.

Home Radar is a single-family appliance, not a multi-tenant service. It uses one
long-lived opaque management token and short-lived, single-use six-digit codes
to hand that token to newly paired browsers or mobile devices.
"""
from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Header, HTTPException

from backend.db import get_conn, models

_TOKEN_KEY = "pairing_token"
_CODE_KEY = "pairing_code"
_CODE_EXPIRES_KEY = "pairing_code_expires_at"
_FAIL_COUNT_KEY = "pairing_fail_count"
_LOCKED_UNTIL_KEY = "pairing_locked_until"

_MAX_FAILURES = 5
_LOCKOUT_SECONDS = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def get_or_create_token(conn) -> str:
    """Return the appliance management token, minting one on first use."""
    token = models.get_setting(conn, _TOKEN_KEY)
    if not token:
        token = generate_token()
        models.set_settings(conn, {_TOKEN_KEY: token})
    return token


def regenerate_token(conn) -> str:
    """Mint a fresh token, invalidating every previously paired client."""
    token = generate_token()
    models.set_settings(conn, {_TOKEN_KEY: token})
    return token


def verify_token(conn, presented: str | None) -> bool:
    if not presented:
        return False
    token = get_or_create_token(conn)
    return hmac.compare_digest(presented, token)


def _is_locked(conn) -> bool:
    locked_until = _parse_iso(models.get_setting(conn, _LOCKED_UNTIL_KEY))
    return locked_until is not None and _now() < locked_until


def _register_failure(conn) -> None:
    try:
        count = int(models.get_setting(conn, _FAIL_COUNT_KEY, "0") or "0") + 1
    except ValueError:
        count = 1
    updates = {_FAIL_COUNT_KEY: str(count)}
    if count >= _MAX_FAILURES:
        updates[_LOCKED_UNTIL_KEY] = (_now() + timedelta(seconds=_LOCKOUT_SECONDS)).isoformat()
    models.set_settings(conn, updates)


def _clear_failures(conn) -> None:
    models.set_settings(conn, {_FAIL_COUNT_KEY: "0", _LOCKED_UNTIL_KEY: ""})


def issue_pairing_code(conn, ttl_seconds: int = 600) -> dict:
    ttl_seconds = max(60, min(int(ttl_seconds), 3600))
    code = generate_code()
    expires_at = _now() + timedelta(seconds=ttl_seconds)
    models.set_settings(
        conn,
        {_CODE_KEY: code, _CODE_EXPIRES_KEY: expires_at.isoformat()},
    )
    _clear_failures(conn)
    return {"code": code, "expires_in": ttl_seconds}


def pairing_status(conn) -> dict:
    code = models.get_setting(conn, _CODE_KEY)
    expires_at = _parse_iso(models.get_setting(conn, _CODE_EXPIRES_KEY))
    if not code or expires_at is None or _now() >= expires_at:
        return {"pending": False, "expires_in": 0}
    return {"pending": True, "expires_in": max(0, int((expires_at - _now()).total_seconds()))}


def redeem_pairing_code(conn, presented_code: str) -> str | None:
    """Exchange a valid, unexpired, unused pairing code for the API token."""
    if _is_locked(conn):
        return None
    code = models.get_setting(conn, _CODE_KEY)
    expires_at = _parse_iso(models.get_setting(conn, _CODE_EXPIRES_KEY))
    valid = (
        bool(code)
        and expires_at is not None
        and _now() < expires_at
        and bool(presented_code)
        and hmac.compare_digest(presented_code, code)
    )
    if not valid:
        _register_failure(conn)
        return None
    models.set_settings(conn, {_CODE_KEY: "", _CODE_EXPIRES_KEY: ""})
    _clear_failures(conn)
    return get_or_create_token(conn)


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, separator, value = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


def require_token(
    x_homeradar_token: str | None = Header(default=None, alias="X-HomeRadar-Token"),
    authorization: str | None = Header(default=None),
    homeradar_token: str | None = Cookie(default=None),
) -> None:
    """Gate protected routes behind header, Bearer, or same-site cookie auth."""
    presented = x_homeradar_token or _bearer_token(authorization) or homeradar_token
    with get_conn() as conn:
        if not verify_token(conn, presented):
            raise HTTPException(status_code=401, detail="Missing or invalid pairing token")
