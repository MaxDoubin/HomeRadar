"""Explainable trust scoring from identity, authorization, alerts, and behavior."""
from __future__ import annotations

from dataclasses import dataclass

from backend.db import models
from backend.insights.trackers import match_tracker
from backend.monitor import habits
from backend.monitor.anomaly_detection import analyze_device


@dataclass(frozen=True)
class TrustResult:
    score: int
    reasons: list[str]
    factors: dict[str, int]


def score_device(conn, device: dict) -> TrustResult:
    factors: dict[str, int] = {}

    if device.get("vendor") and device["vendor"] not in {"Unknown", "Private / randomized MAC"}:
        factors["recognized manufacturer"] = 8
    if device.get("device_type") != "unknown":
        factors["recognized device type"] = 7
    confidence = float(device.get("fingerprint_confidence") or 0)
    if confidence >= 0.75:
        factors["strong fingerprint"] = 5

    authorization = int(device.get("is_authorized") or 0)
    if authorization == 1:
        factors["household authorized"] = 15
    elif authorization == 2:
        factors["household blocked"] = -50

    window = "julianday(created_at) >= julianday('now', '-24 hours')"
    variance = int(
        conn.execute(
            f"SELECT COUNT(DISTINCT domain) FROM traffic_logs WHERE device_id = ? AND {window}",
            (device["id"],),
        ).fetchone()[0]
    )
    # Blocked ad/analytics lookups are a privacy matter (see the privacy report),
    # not evidence of compromise; nearly every phone and TV makes them, so they
    # must not count as blocked requests or as threat-intel matches here.
    blocked = threats = 0
    for row in conn.execute(
        f"""SELECT domain,
                   COALESCE(SUM(was_blocked), 0) AS blocked,
                   COALESCE(SUM(CASE WHEN threat_level IN ('warning', 'critical') THEN 1 ELSE 0 END), 0)
                       AS threats
            FROM traffic_logs WHERE device_id = ? AND {window}
            GROUP BY domain""",
        (device["id"],),
    ).fetchall():
        if match_tracker(row["domain"]) is None:
            blocked += int(row["blocked"])
            threats += int(row["threats"])
    if blocked:
        factors["blocked requests"] = -min(25, blocked * 3)
    if threats:
        factors["threat-intel matches"] = -min(35, threats * 7)
    if variance > 150:
        factors["unusually broad domain activity"] = -10

    alert_count = conn.execute(
        """SELECT COUNT(*) FROM alerts
           WHERE device_id = ? AND is_resolved = 0
             AND severity IN ('warning', 'critical')""",
        (device["id"],),
    ).fetchone()[0]
    if alert_count:
        factors["unresolved alerts"] = -min(20, alert_count * 4)
    if habits.unresolved_habit_alerts(conn, device["id"]):
        factors["out-of-character activity"] = -10
    elif authorization == 1 and not (blocked or threats or alert_count or variance > 150):
        factors["clean recent activity"] = 10

    findings = conn.execute(
        """SELECT severity, COUNT(*) AS count FROM exposure_findings
           WHERE device_id = ? AND is_resolved = 0 GROUP BY severity""",
        (device["id"],),
    ).fetchall()
    finding_penalty = sum(
        {"critical": 12, "warning": 5, "info": 1}.get(row["severity"], 1) * row["count"]
        for row in findings
    )
    if finding_penalty:
        factors["network exposure findings"] = -min(25, finding_penalty)

    score = max(0, min(100, 50 + sum(factors.values())))
    reasons = [f"{label}: {points:+d}" for label, points in factors.items()]
    return TrustResult(score, reasons or ["No behavior history yet"], factors)


def recalculate_all(conn) -> list[dict]:
    updates = []
    for device in models.list_devices(conn):
        anomalies = analyze_device(conn, device["id"])
        result = score_device(conn, device)
        models.set_trust_score(conn, device["id"], result.score, "; ".join(result.reasons))
        updates.append(
            {
                "device_id": device["id"],
                "score": result.score,
                "reasons": result.reasons,
                "factors": result.factors,
                "anomalies": [anomaly.__dict__ for anomaly in anomalies],
            }
        )
    return updates


def household_score(conn) -> dict:
    devices = models.list_devices(conn)
    if not devices:
        return {"score": 100, "device_average": 100, "alert_penalty": 0}
    device_average = round(sum(device["trust_score"] for device in devices) / len(devices))
    open_alerts = models.list_alerts(conn, unresolved_only=True)
    severity_weights = {"info": 1, "warning": 4, "critical": 10}
    alert_penalty = min(35, sum(severity_weights.get(alert["severity"], 2) for alert in open_alerts))
    return {
        "score": max(0, min(100, device_average - alert_penalty)),
        "device_average": device_average,
        "alert_penalty": alert_penalty,
    }
