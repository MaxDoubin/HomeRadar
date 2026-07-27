"""Home Radar backend entrypoint: FastAPI app + background discovery loop."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend import config
from backend.api.routes import router as api_router
from backend.db import get_conn, init_db
from backend.discovery.scan_runner import run_discovery_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("homeradar.main")


async def _discovery_loop():
    while True:
        try:
            with get_conn() as conn:
                run_discovery_scan(conn)
        except Exception:
            logger.exception("Discovery scan failed")
        await asyncio.sleep(config.ARP_SCAN_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(_discovery_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Home Radar", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOW_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host=config.API_HOST, port=config.API_PORT, reload=False)
