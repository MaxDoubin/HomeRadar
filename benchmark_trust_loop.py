import asyncio
import time
import logging
import sqlite3
from backend.main import _trust_loop
from backend.db import get_conn, init_db, models
from backend import config
import os

logging.basicConfig(level=logging.ERROR)

config.TRUST_SCORE_INTERVAL_SECONDS = 3600

def generate_load():
    with get_conn() as conn:
        for i in range(3000):
            mac = f"02:00:00:{(i//65536)%256:02x}:{(i//256)%256:02x}:{i%256:02x}"
            conn.execute("INSERT OR REPLACE INTO devices (mac, ip, first_seen, last_seen) VALUES (?, ?, datetime('now'), datetime('now'))", (mac, f"192.168.1.{i%256}"))
        conn.commit()
    print("Database populated with 3,000 devices.")

async def dummy_slow_task():
    iterations = 0
    start_time = time.monotonic()

    # We want to measure the maximum delay caused by blocking code
    max_delay = 0

    while iterations < 50:
        t0 = time.monotonic()
        await asyncio.sleep(0.01) # Try to sleep for 10ms
        t1 = time.monotonic()

        delay = t1 - t0 - 0.01
        if delay > max_delay:
            max_delay = delay

        iterations += 1

    duration = time.monotonic() - start_time
    print(f"Async loop total duration: {duration:.4f}s for 50x10ms sleeps")
    print(f"Maximum event loop blockage: {max_delay:.4f}s")
    return max_delay

async def main():
    if os.path.exists("test_benchmark_3k.db"):
        os.remove("test_benchmark_3k.db")
    config.DB_PATH = "test_benchmark_3k.db"

    init_db()
    generate_load()

    print("Starting benchmark...")

    # Start the trust loop
    loop_task = asyncio.create_task(_trust_loop())

    # Give it a small delay so it blocks the event loop
    await asyncio.sleep(0.01)

    # Run the dummy task while the loop is running
    task1 = asyncio.create_task(dummy_slow_task())

    max_delay = await task1
    loop_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
