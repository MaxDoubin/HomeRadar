"""Home Radar appliance entrypoint: API, workers, DNS proxy, and dashboard."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend import config, pairing, services
from backend.api.routes import router as api_router
from backend.api.insights_routes import router as insights_router
from backend.api.websocket import router as websocket_router
from backend.db import get_conn, init_db, models
from backend.discovery.scan_runner import run_discovery_scan
from backend.dns.blocklists import record_update_results
from backend.dns.proxy import DNSProxy
from backend.maintenance import backup_if_due, cleanup_database
from backend.monitor.exposure_audit import audit_all
from backend.monitor.traffic_analyzer import PassiveTrafficMonitor
from backend.monitor.trust_scoring import recalculate_all
from backend.security import ApplianceSecurityMiddleware
from backend.services import blocklists

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("homeradar.main")


async def _discovery_loop():
    while True:
        try:
            await asyncio.to_thread(_run_discovery)
        except Exception:
            logger.exception("Discovery scan failed")
        await asyncio.sleep(config.ARP_SCAN_INTERVAL_SECONDS)


def _run_discovery() -> None:
    with get_conn() as conn:
        run_discovery_scan(conn)


async def _trust_loop():
    while True:
        try:
            with get_conn() as conn:
                audit_all(conn)
                recalculate_all(conn)
        except Exception:
            logger.exception("Trust score recalculation failed")
        await asyncio.sleep(config.TRUST_SCORE_INTERVAL_SECONDS)


async def _blocklist_loop():
    while True:
        if config.BLOCKLIST_AUTO_UPDATE and config.BLOCKLIST_URLS:
            try:
                results = await asyncio.to_thread(blocklists.update)
                with get_conn() as conn:
                    record_update_results(conn, results)
            except Exception:
                logger.exception("Blocklist update failed")
        await asyncio.sleep(max(1, config.BLOCKLIST_UPDATE_HOURS) * 3600)


async def _maintenance_loop():
    while True:
        try:
            with get_conn() as conn:
                cleanup_database(conn)
            await asyncio.to_thread(backup_if_due)
        except Exception:
            logger.exception("Maintenance pass failed")
        await asyncio.sleep(max(300, config.MAINTENANCE_INTERVAL_SECONDS))


def _prepare_first_run_pairing() -> None:
    """Create a temporary code for headless first-run installations.

    A desktop or kiosk browser can bootstrap through loopback. Docker and
    headless Debian users instead read this code from the local service logs and
    enter it into the remote browser pairing screen. The code is replaced on
    each pre-setup restart and expires after thirty minutes.
    """
    with get_conn() as conn:
        setup_complete = models.get_setting(conn, "setup_complete", "false") == "true"
        if setup_complete:
            return
        result = pairing.issue_pairing_code(conn, ttl_seconds=1800)
    logger.warning("=" * 72)
    logger.warning("HOME RADAR FIRST-RUN PAIRING CODE: %s", result["code"])
    logger.warning("Enter this code in the dashboard within 30 minutes.")
    logger.warning("Docker: docker logs homeradar | grep 'PAIRING CODE'")
    logger.warning("systemd: journalctl -u homeradar | grep 'PAIRING CODE'")
    logger.warning("=" * 72)


def _lan_ipv4() -> str | None:
    # A UDP connect does a routing lookup without sending anything.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    return None if address.startswith("127.") else address


def _start_mdns_advertisement():
    """Advertise `_http._tcp` as "HomeRadar on <host>" so the phone apps can find this appliance."""
    try:
        from zeroconf import ServiceInfo, Zeroconf

        address = _lan_ipv4()
        if address is None:
            logger.info("mDNS advertisement skipped: no LAN address")
            return None
        hostname = socket.gethostname().split(".")[0] or "appliance"
        info = ServiceInfo(
            "_http._tcp.local.",
            f"HomeRadar on {hostname}._http._tcp.local.",
            addresses=[socket.inet_aton(address)],
            port=config.API_PORT,
            properties={"path": "/", "app": "homeradar"},
            server=f"{hostname}.local.",
        )
        zeroconf = Zeroconf()
        try:
            zeroconf.register_service(info, allow_name_change=True)
        except Exception:
            zeroconf.close()
            raise
        logger.info("Advertising Home Radar over mDNS at %s:%s", address, config.API_PORT)
        return zeroconf, info
    except Exception:
        logger.warning("mDNS advertisement unavailable; phone apps can still connect by IP address", exc_info=True)
        return None


def _stop_mdns_advertisement(advertisement) -> None:
    zeroconf, info = advertisement
    with contextlib.suppress(Exception):
        zeroconf.unregister_service(info)
    with contextlib.suppress(Exception):
        zeroconf.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _prepare_first_run_pairing()
    tasks = [
        asyncio.create_task(_discovery_loop()),
        asyncio.create_task(_trust_loop()),
        asyncio.create_task(_blocklist_loop()),
        asyncio.create_task(_maintenance_loop()),
    ]
    dns_proxy: DNSProxy | None = None
    dns_thread: threading.Thread | None = None
    traffic_monitor: PassiveTrafficMonitor | None = None
    traffic_thread: threading.Thread | None = None
    if config.DNS_ENABLED:
        dns_proxy = DNSProxy(blocklists)
        services.dns_proxy = dns_proxy
        dns_thread = threading.Thread(
            target=dns_proxy.serve_forever,
            daemon=True,
            name="homeradar-dns",
        )
        dns_thread.start()
    if config.TRAFFIC_MONITOR_ENABLED:
        traffic_monitor = PassiveTrafficMonitor()
        traffic_thread = threading.Thread(
            target=traffic_monitor.run,
            daemon=True,
            name="homeradar-traffic",
        )
        traffic_thread.start()
    mdns = await asyncio.to_thread(_start_mdns_advertisement) if config.MDNS_ADVERTISE else None
    try:
        yield
    finally:
        if mdns:
            await asyncio.to_thread(_stop_mdns_advertisement, mdns)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if dns_proxy:
            dns_proxy.stop()
            services.dns_proxy = None
        if dns_thread:
            dns_thread.join(timeout=2)
        if traffic_monitor:
            traffic_monitor.stop()
        if traffic_thread:
            traffic_thread.join(timeout=2)


app = FastAPI(
    title="Home Radar",
    version="0.3.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# Cross-origin access is disabled by default. The dashboard is served from this
# same process, and native mobile clients do not require browser CORS. Operators
# can explicitly opt in trusted origins through HOMERADAR_CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOW_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-HomeRadar-Token"],
)
app.add_middleware(ApplianceSecurityMiddleware)

app.include_router(api_router)
app.include_router(insights_router)
app.include_router(websocket_router)

kiosk_dir = config.BASE_DIR / "kiosk"
if kiosk_dir.exists():
    app.mount("/kiosk", StaticFiles(directory=kiosk_dir, html=True), name="kiosk")

frontend_dist = config.BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    # Pass the already-imported ASGI object. A string such as
    # ``backend.main:app`` asks Uvicorn to import this source module again, which
    # is unreliable once PyInstaller freezes this file as ``__main__``.
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT, reload=False)
