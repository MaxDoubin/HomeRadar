"""Production request hardening for the Home Radar appliance.

The appliance serves both the dashboard and API from the same process. Browsers
running directly on the appliance are trusted for bootstrap, while every other
LAN client must present the pairing token. Forwarded headers are deliberately
ignored so an untrusted reverse proxy cannot make a remote client look local.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.db import get_conn
from backend.pairing import verify_token

_PUBLIC_PATHS = frozenset({"/status", "/health", "/pair/claim"})
_LOCAL_ONLY_PATHS = frozenset({"/pair/local-token"})
_BOOTSTRAP_PATHS = frozenset({"/pair/start", "/setup"})
_PROTECTED_PREFIXES = (
    "/dashboard",
    "/devices",
    "/inventory",
    "/alerts",
    "/traffic",
    "/trust",
    "/findings",
    "/audit",
    "/blocklists",
    "/dns",
    "/threat-intel",
    "/settings",
    "/backups",
    "/digest",
    "/scan",
    "/pair",
)


def is_local_host(host: str | None) -> bool:
    """Return True only for loopback clients and Starlette's test client."""
    if not host:
        return False
    normalized = host.strip().strip("[]").lower()
    if normalized in {"localhost", "testclient"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def extract_presented_token(
    headers: Mapping[str, str],
    cookies: Mapping[str, str] | None = None,
) -> str | None:
    token = headers.get("x-homeradar-token")
    authorization = headers.get("authorization", "")
    if not token and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    if not token and cookies:
        token = cookies.get("homeradar_token")
    return token or None


def path_requires_auth(path: str) -> bool:
    if path in _PUBLIC_PATHS:
        return False
    return path.startswith(_PROTECTED_PREFIXES)


def authorization_decision(path: str, *, local: bool, token_valid: bool) -> tuple[bool, int]:
    """Return ``(allowed, failure_status)`` for one request path."""
    if not path_requires_auth(path):
        return True, 200
    if path in _LOCAL_ONLY_PATHS:
        return (local, 403)
    if path in _BOOTSTRAP_PATHS:
        return (local or token_valid, 403)
    return (local or token_valid, 401)


def _apply_security_headers(response: Response) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'",
    )
    response.headers.setdefault("Cache-Control", "no-store")
    return response


class ApplianceSecurityMiddleware(BaseHTTPMiddleware):
    """Require pairing authentication for non-local appliance API access."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return _apply_security_headers(await call_next(request))

        path = request.url.path.rstrip("/") or "/"
        if path_requires_auth(path):
            local = is_local_host(request.client.host if request.client else None)
            token = extract_presented_token(request.headers, request.cookies)
            token_valid = False
            if token:
                with get_conn() as conn:
                    try:
                        token_valid = verify_token(conn, token)
                    except Exception:
                        token_valid = False
            allowed, status = authorization_decision(path, local=local, token_valid=token_valid)
            if not allowed:
                detail = (
                    "This endpoint is available only from the appliance itself."
                    if status == 403
                    else "Pair this device with Home Radar before accessing the dashboard."
                )
                return _apply_security_headers(JSONResponse({"detail": detail}, status_code=status))

        response = await call_next(request)
        return _apply_security_headers(response)
