"""Central configuration for the Home Radar backend, sourced from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("HOMERADAR_DB_PATH", str(BASE_DIR / "data" / "homeradar.db"))

# Network scanning
LAN_SUBNET = os.environ.get("HOMERADAR_LAN_SUBNET", "auto")  # "auto" = detect from default interface
ARP_SCAN_INTERVAL_SECONDS = int(os.environ.get("HOMERADAR_ARP_SCAN_INTERVAL", "60"))
PORT_SCAN_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_PORT_SCAN_TIMEOUT", "0.5"))
COMMON_PORTS = [22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 5000, 5353, 8008, 8009, 8080, 8443, 9100, 32400]

# API
API_HOST = os.environ.get("HOMERADAR_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("HOMERADAR_API_PORT", "8000"))
CORS_ALLOW_ORIGINS = os.environ.get("HOMERADAR_CORS_ORIGINS", "*").split(",")
