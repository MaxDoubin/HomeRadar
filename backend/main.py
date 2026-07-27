"""Home Radar appliance entrypoint: API, workers, DNS proxy, and dashboard."""
from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend import config
from backend.api.routes import router as api_router
from backend.api.websocket import router as websocket_router
from backend.db import get_conn, init_db
from backend.discovery.scan_runner import run_discovery_scan
from backend.dns.blocklists import record_update_results
from backend.dns.proxy import DNSProxy
from backend.monitor.trust_scoring import recalculate_all
from backend.monitor.traffic_analyzer import PassiveTrafficMonitor
from backend.monitor.exposure_audit import audit_all
from backend.maintenance import backup_if_due, cleanup_database
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    tasks = [
        asyncio.create_task(_discovery_loop()),
        asyncio.create_task(_trust_loop()),
        asyncio.create_task(_blocklist_loop()),
        asyncio.create_task(_maintenance_loop()),
    ]
    dns_proxy = None
    dns_thread = None
    traffic_monitor = None
    traffic_thread = None
    if config.DNS_ENABLED:
        dns_proxy = DNSProxy(blocklists)
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
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if dns_proxy:
            dns_proxy.stop()
        if dns_thread:
            dns_thread.join(timeout=2)
        if traffic_monitor:
            traffic_monitor.stop()
        if traffic_thread:
            traffic_thread.join(timeout=2)


app = FastAPI(title="Home Radar", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOW_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(websocket_router)

kiosk_dir = config.BASE_DIR / "kiosk"
if kiosk_dir.exists():
    app.mount("/kiosk", StaticFiles(directory=kiosk_dir, html=True), name="kiosk")

frontend_dist = config.BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=config.API_HOST, port=config.API_PORT, reload=False)
