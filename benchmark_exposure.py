import time
import sqlite3
import json
import os
from datetime import datetime, timezone
from backend.db import models
from backend.monitor.exposure_audit import audit_all

def create_mock_devices(conn, num_devices):
    now = datetime.now(timezone.utc).isoformat()
    devices_data = []
    for i in range(num_devices):
        mac = f"00:11:22:{i//65536:02x}:{(i//256)%256:02x}:{i%256:02x}"
        ip = f"10.0.0.{i%254 + 1}"
        open_ports = json.dumps([21, 23, 80, 445, 554, 3389])
        device_type = "unknown"
        devices_data.append((mac, ip, open_ports, device_type, now, now))

    conn.executemany(
        """INSERT INTO devices (
            mac, ip, open_ports, device_type, first_seen, last_seen
           ) VALUES (?, ?, ?, ?, ?, ?)""",
        devices_data
    )
    conn.commit()

def run_benchmark():
    db_path = "benchmark_test.db"

    if os.path.exists(db_path):
        os.remove(db_path)

    # Initialize DB
    models.init_db(db_path)

    # Run with context manager
    with models.get_conn(db_path) as conn:
        print("Creating mock devices...")
        create_mock_devices(conn, 500)

        print("Running benchmark (1st run, inserts)...")
        start_time = time.perf_counter()
        audit_all(conn)
        end_time = time.perf_counter()

        duration_insert = end_time - start_time
        print(f"audit_all (inserts) took {duration_insert:.4f} seconds for 500 devices")

        print("Running benchmark (2nd run, updates)...")
        start_time = time.perf_counter()
        audit_all(conn)
        end_time = time.perf_counter()

        duration_update = end_time - start_time
        print(f"audit_all (updates) took {duration_update:.4f} seconds for 500 devices")

if __name__ == "__main__":
    run_benchmark()
