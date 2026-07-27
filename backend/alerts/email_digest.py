"""Build and optionally send a plain-text weekly household security digest."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from backend import config
from backend.db import models
from backend.monitor.trust_scoring import household_score


def build_digest(conn) -> tuple[str, str]:
    household_name = models.get_setting(conn, "household_name", config.HOUSEHOLD_NAME)
    score = household_score(conn)
    new_devices = conn.execute(
        """SELECT hostname, vendor, ip, device_type FROM devices
           WHERE julianday(first_seen) >= julianday('now', '-7 days')
           ORDER BY first_seen DESC"""
    ).fetchall()
    traffic = models.traffic_summary(conn, hours=24 * 7)
    alerts = conn.execute(
        """SELECT severity, title, description FROM alerts
           WHERE julianday(created_at) >= julianday('now', '-7 days')
           ORDER BY created_at DESC LIMIT 20"""
    ).fetchall()
    subject = f"{household_name} Home Radar digest: security score {score['score']}"
    lines = [
        f"{household_name} weekly security digest",
        "=" * 42,
        f"Household security score: {score['score']}/100",
        f"DNS queries observed: {traffic['queries']}",
        f"Threats and trackers blocked: {traffic['blocked']}",
        f"New devices: {len(new_devices)}",
        "",
        "New devices",
        "-----------",
    ]
    lines.extend(
        f"- {row['hostname'] or row['vendor'] or 'Unknown'} "
        f"({row['device_type']}, {row['ip']})"
        for row in new_devices
    )
    if not new_devices:
        lines.append("- None")
    lines.extend(["", "Recent alerts", "-------------"])
    lines.extend(
        f"- [{row['severity'].upper()}] {row['title']}: {row['description'] or ''}"
        for row in alerts
    )
    if not alerts:
        lines.append("- None")
    lines.extend(
        [
            "",
            "This week's action",
            "------------------",
            (
                "Review pending devices and resolve open alerts."
                if score["score"] < 85
                else "Your network looks healthy. Keep device software and router firmware updated."
            ),
            "",
            f"Open Home Radar: {config.PUBLIC_BASE_URL}",
        ]
    )
    return subject, "\n".join(lines)


def send_digest(conn, recipient: str | None = None) -> dict:
    recipient = recipient or config.SMTP_TO
    if not config.SMTP_HOST or not config.SMTP_FROM or not recipient:
        raise RuntimeError("SMTP host, sender, and recipient must be configured")
    subject, body = build_digest(conn)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.SMTP_FROM
    message["To"] = recipient
    message.set_content(body)

    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as smtp:
        if config.SMTP_USE_TLS:
            smtp.starttls(context=ssl.create_default_context())
        if config.SMTP_USERNAME:
            smtp.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
        smtp.send_message(message)
    return {"sent": True, "recipient": recipient, "subject": subject}
