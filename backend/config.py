"""Central configuration for the Home Radar backend, sourced from environment variables."""
import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    # PyInstaller case
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("HOMERADAR_DB_PATH", str(BASE_DIR / "data" / "homeradar.db"))
DATA_DIR = Path(os.environ.get("HOMERADAR_DATA_DIR", str(BASE_DIR / "data")))

# Network scanning
LAN_SUBNET = os.environ.get("HOMERADAR_LAN_SUBNET", "auto")
ARP_SCAN_INTERVAL_SECONDS = int(os.environ.get("HOMERADAR_ARP_SCAN_INTERVAL", "60"))
PORT_SCAN_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_PORT_SCAN_TIMEOUT", "0.5"))
MDNS_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_MDNS_TIMEOUT", "2.0"))
SSDP_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_SSDP_TIMEOUT", "2.0"))
MAX_FINGERPRINT_WORKERS = int(os.environ.get("HOMERADAR_FINGERPRINT_WORKERS", "12"))

# TCP services that reveal useful device identity without performing an invasive scan.
COMMON_PORTS = [
    21, 22, 23, 53, 80, 81, 139, 443, 445, 515, 548, 554, 631,
    1400, 1883, 2869, 3389, 3689, 5000, 5001, 5357, 7000, 8000,
    8008, 8009, 8060, 8080, 8123, 8443, 8883, 9000, 9090, 9100,
    32400, 49152, 62078,
]

# API. Browser cross-origin access is denied unless explicitly configured.
API_HOST = os.environ.get("HOMERADAR_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("HOMERADAR_API_PORT", "8000"))
CORS_ALLOW_ORIGINS = [
    value.strip()
    for value in os.environ.get("HOMERADAR_CORS_ORIGINS", "").split(",")
    if value.strip()
]

# DNS proxy and blocklists. Binding port 53 normally requires root/CAP_NET_BIND_SERVICE;
# development defaults to 5354 so the API can run unprivileged.
DNS_ENABLED = os.environ.get("HOMERADAR_DNS_ENABLED", "false").lower() in {"1", "true", "yes"}
DNS_HOST = os.environ.get("HOMERADAR_DNS_HOST", "0.0.0.0")
DNS_PORT = int(os.environ.get("HOMERADAR_DNS_PORT", "5354"))
DNS_UPSTREAM = os.environ.get("HOMERADAR_DNS_UPSTREAM", "1.1.1.1")
DNS_UPSTREAMS = [
    value.strip()
    for value in os.environ.get("HOMERADAR_DNS_UPSTREAMS", DNS_UPSTREAM).split(",")
    if value.strip()
]
DNS_UPSTREAM_PORT = int(os.environ.get("HOMERADAR_DNS_UPSTREAM_PORT", "53"))
DNS_TIMEOUT_SECONDS = float(os.environ.get("HOMERADAR_DNS_TIMEOUT", "3"))
DNS_CACHE_SIZE = int(os.environ.get("HOMERADAR_DNS_CACHE_SIZE", "4096"))
DNS_CACHE_MAX_TTL = int(os.environ.get("HOMERADAR_DNS_CACHE_MAX_TTL", "3600"))
BLOCKLIST_PATH = Path(
    os.environ.get("HOMERADAR_BLOCKLIST_PATH", str(DATA_DIR / "blocklist.txt"))
)
BLOCKLIST_UPDATE_HOURS = int(os.environ.get("HOMERADAR_BLOCKLIST_UPDATE_HOURS", "24"))
BLOCKLIST_AUTO_UPDATE = os.environ.get(
    "HOMERADAR_BLOCKLIST_AUTO_UPDATE", "false"
).lower() in {"1", "true", "yes"}
BLOCKLIST_URLS = [
    url.strip()
    for url in os.environ.get(
        "HOMERADAR_BLOCKLIST_URLS",
        (
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts,"
            "https://big.oisd.nl/domainswild2"
        ),
    ).split(",")
    if url.strip()
]

# Threat intelligence and scoring
ABUSEIPDB_API_KEY = os.environ.get("HOMERADAR_ABUSEIPDB_API_KEY", "")
ABUSEIPDB_MIN_CONFIDENCE = int(os.environ.get("HOMERADAR_ABUSEIPDB_MIN_CONFIDENCE", "70"))
THREAT_CACHE_HOURS = int(os.environ.get("HOMERADAR_THREAT_CACHE_HOURS", "24"))
TRUST_SCORE_INTERVAL_SECONDS = int(os.environ.get("HOMERADAR_TRUST_SCORE_INTERVAL", "300"))
MAINTENANCE_INTERVAL_SECONDS = int(os.environ.get("HOMERADAR_MAINTENANCE_INTERVAL", "3600"))
TRAFFIC_RETENTION_DAYS = int(os.environ.get("HOMERADAR_TRAFFIC_RETENTION_DAYS", "30"))
ALERT_RETENTION_DAYS = int(os.environ.get("HOMERADAR_ALERT_RETENTION_DAYS", "180"))
BACKUP_RETENTION_COUNT = int(os.environ.get("HOMERADAR_BACKUP_RETENTION_COUNT", "7"))
BACKUP_DIR = Path(os.environ.get("HOMERADAR_BACKUP_DIR", str(DATA_DIR / "backups")))
TRAFFIC_MONITOR_ENABLED = os.environ.get(
    "HOMERADAR_TRAFFIC_MONITOR_ENABLED", "false"
).lower() in {"1", "true", "yes"}
TRAFFIC_INTERFACE = os.environ.get("HOMERADAR_TRAFFIC_INTERFACE", "") or None
TRAFFIC_FLUSH_SECONDS = int(os.environ.get("HOMERADAR_TRAFFIC_FLUSH_SECONDS", "30"))
CISA_KEV_URL = os.environ.get(
    "HOMERADAR_CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

# Household and digest settings
HOUSEHOLD_NAME = os.environ.get("HOMERADAR_HOUSEHOLD_NAME", "My Home")
PUBLIC_BASE_URL = os.environ.get("HOMERADAR_PUBLIC_URL", "http://homeradar.local:8000")
SMTP_HOST = os.environ.get("HOMERADAR_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("HOMERADAR_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("HOMERADAR_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("HOMERADAR_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("HOMERADAR_SMTP_FROM", "")
SMTP_TO = os.environ.get("HOMERADAR_SMTP_TO", "")
SMTP_USE_TLS = os.environ.get("HOMERADAR_SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
