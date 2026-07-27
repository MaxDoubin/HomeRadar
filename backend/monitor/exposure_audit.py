"""Non-invasive device exposure assessment from already observed services."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from backend.db import models


@dataclass(frozen=True)
class Finding:
    key: str
    severity: str
    title: str
    description: str
    recommendation: str
    evidence: list[str]


PORT_RULES = {
    21: ("ftp", "warning", "Unencrypted FTP service", "FTP can expose credentials and files in clear text.", "Disable FTP or replace it with SFTP."),
    23: ("telnet", "critical", "Telnet management exposed", "Telnet sends administration credentials without encryption.", "Disable Telnet and use SSH or the vendor's encrypted management interface."),
    80: ("http-admin", "info", "Unencrypted web service", "This device answers over HTTP. If it is an admin page, credentials may be exposed.", "Prefer HTTPS and disable remote administration when it is not needed."),
    445: ("smb", "warning", "SMB file sharing exposed", "File sharing is reachable on the household network and increases lateral-movement risk.", "Install security updates, require authentication, and disable SMBv1."),
    554: ("rtsp", "warning", "RTSP video service exposed", "Camera or media video is reachable on the local network.", "Require a strong unique password and isolate the device on an IoT network if possible."),
    3389: ("rdp", "warning", "Remote Desktop exposed", "Remote Desktop is reachable from the household LAN.", "Require Network Level Authentication, updates, and a strong account password."),
}


def assess_device(device: dict) -> list[Finding]:
    findings = []
    ports = set(device.get("open_ports") or [])
    for port, (key, severity, title, description, recommendation) in PORT_RULES.items():
        if port in ports:
            findings.append(
                Finding(
                    f"port-{key}",
                    severity,
                    title,
                    description,
                    recommendation,
                    [f"TCP port {port} accepted a connection"],
                )
            )
    if device.get("device_type") == "unknown" and float(device.get("fingerprint_confidence") or 0) < 0.5:
        findings.append(
            Finding(
                "unknown-device",
                "warning",
                "Unidentified device",
                "Home Radar cannot confidently identify this device yet.",
                "Confirm who owns it. Authorize it only after matching its MAC address.",
                [f"fingerprint confidence {round(float(device.get('fingerprint_confidence') or 0) * 100)}%"],
            )
        )
    if device.get("is_authorized") == 0:
        findings.append(
            Finding(
                "pending-authorization",
                "info",
                "Device awaiting household review",
                "No household member has authorized or blocked this device.",
                "Review its identity and choose an authorization state.",
                ["authorization state is pending"],
            )
        )
    return findings


def audit_device(conn, device: dict) -> list[dict]:
    findings = assess_device(device)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE exposure_findings SET is_resolved = 1
           WHERE device_id = ?""",
        (device["id"],),
    )
    for finding in findings:
        conn.execute(
            """INSERT INTO exposure_findings (
                   device_id, finding_key, severity, title, description,
                   recommendation, evidence, is_resolved, first_seen, last_seen
               ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
               ON CONFLICT(device_id, finding_key) DO UPDATE SET
                   severity = excluded.severity,
                   title = excluded.title,
                   description = excluded.description,
                   recommendation = excluded.recommendation,
                   evidence = excluded.evidence,
                   is_resolved = 0,
                   last_seen = excluded.last_seen""",
            (
                device["id"],
                finding.key,
                finding.severity,
                finding.title,
                finding.description,
                finding.recommendation,
                json.dumps(finding.evidence),
                now,
                now,
            ),
        )
    return models.list_findings(conn, device_id=device["id"])


def audit_all(conn) -> list[dict]:
    for device in models.list_devices(conn):
        audit_device(conn, device)
    return models.list_findings(conn)
