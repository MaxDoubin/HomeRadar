"""Small-data behavioral anomaly detection using online statistical baselines."""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from backend.db import models


@dataclass(frozen=True)
class Anomaly:
    metric: str
    value: float
    expected: float
    z_score: float


def observe_metric(conn, device_id: int, metric: str, value: float) -> Anomaly | None:
    row = conn.execute(
        "SELECT * FROM behavior_baselines WHERE device_id = ? AND metric = ?",
        (device_id, metric),
    ).fetchone()
    now = datetime.now(timezone.utc).isoformat()
    if row is None:
        conn.execute(
            """INSERT INTO behavior_baselines
               (device_id, metric, mean, variance, samples, updated_at)
               VALUES (?, ?, ?, 0, 1, ?)""",
            (device_id, metric, value, now),
        )
        return None

    samples = int(row["samples"])
    mean = float(row["mean"])
    m2 = float(row["variance"])
    standard_deviation = math.sqrt(m2 / max(1, samples - 1)) if samples > 1 else 0
    z_score = (value - mean) / standard_deviation if standard_deviation > 0 else 0
    anomaly = (
        Anomaly(metric, value, mean, round(z_score, 2))
        if samples >= 5 and value > mean and z_score >= 3
        else None
    )

    new_samples = samples + 1
    delta = value - mean
    new_mean = mean + delta / new_samples
    new_m2 = m2 + delta * (value - new_mean)
    conn.execute(
        """UPDATE behavior_baselines SET mean = ?, variance = ?, samples = ?, updated_at = ?
           WHERE device_id = ? AND metric = ?""",
        (new_mean, new_m2, new_samples, now, device_id, metric),
    )
    return anomaly


def analyze_device(conn, device_id: int) -> list[Anomaly]:
    current = conn.execute(
        """SELECT COUNT(*) AS queries,
                  COUNT(DISTINCT domain) AS unique_domains,
                  COALESCE(SUM(bytes_sent + bytes_received), 0) AS bytes
           FROM traffic_logs
           WHERE device_id = ?
             AND julianday(created_at) >= julianday('now', '-1 hour')""",
        (device_id,),
    ).fetchone()
    anomalies = []
    for metric in ("queries", "unique_domains", "bytes"):
        anomaly = observe_metric(conn, device_id, metric, float(current[metric]))
        if anomaly:
            anomalies.append(anomaly)
            models.create_alert_once(
                conn,
                device_id,
                "warning",
                f"Unusual {metric.replace('_', ' ')}",
                (
                    f"Observed {anomaly.value:g}; usual level is about "
                    f"{anomaly.expected:.1f} ({anomaly.z_score:.1f} standard deviations high)."
                ),
                window_minutes=180,
            )
    return anomalies
