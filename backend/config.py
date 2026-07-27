"""Central configuration for the Home Radar backend, sourced from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("HOMERADAR_DB_PATH", str(BASE_DIR / "data" / "homeradar.db"))

# Network scanning
LAN_SUBNET = os.environ.get("HOMERADAR_LAN_SUBNET", "auto")  # "auto" = detect from default interface
ARP_SCAN_INTERVAL_SECONDS = int(os.environ.get("HOMERADAR_ARP_SCAN_INTERVAL", "60"))
PORT_SCAN_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_PORT_SCAN_TIMEOUT", "0.5"))
MDNS_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_MDNS_TIMEOUT", "2.0"))
SSDP_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_SSDP_TIMEOUT", "2.0"))
MAX_FINGERPRINT_WORKERS = int(os.environ.get("HOMERADAR_FINGERPRINT_WORKERS", "12"))

# TCP services that reveal useful device identity without performing an invasive scan.
# This intentionally favors common home, media, printer, NAS, camera, and management
# services over a broad vulnerability-style port sweep.
COMMON_PORTS = [
    21, 22, 23, 53, 80, 81, 139, 443, 445, 515, 548, 554, 631,
    1400, 1883, 2869, 3389, 3689, 5000, 5001, 5357, 7000, 8000,
    8008, 8009, 8060, 8080, 8123, 8443, 8883, 9000, 9090, 9100,
    32400, 49152, 62078,
]

# API
API_HOST = os.environ.get("HOMERADAR_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("HOMERADAR_API_PORT", "8000"))
CORS_ALLOW_ORIGINS = os.environ.get("HOMERADAR_CORS_ORIGINS", "*").split(",")
