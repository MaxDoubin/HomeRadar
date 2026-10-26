"""Learns each device's normal hourly rhythm and flags out-of-character hours.

The model is an Isolation Forest (Liu, Ting & Zhou, 2008), implemented here in
plain Python so the desktop bundle stays small. Every hour of a device's recent
history becomes one point described relative to that device's own normal for
that time of day: how far its data volume, DNS requests, and distinct domains
sit above or below the device's median at similar hours, plus how many
never-before-seen and blocked domains it touched. Each of the 100 trees is
grown on a random subsample of 64 hours by repeatedly picking a random feature
and a random split value between that feature's min and max, until points are
isolated or a height limit of ceil(log2(64)) is reached. Ordinary hours look
like many others, so it takes many splits to isolate them; unusual hours get
isolated after only a few. An hour's anomaly score is 2^(-E[h(x)] / c(n)),
where E[h(x)] is its average isolation depth across trees and c(n) is the
expected depth for a sample of size n. Scores near 1 mean "very unusual",
around 0.5 or below mean "ordinary". The model learns without labels: nobody
has to tell it what an attack looks like, only what normal is.

An hour only becomes an alert when the model's score crosses the threshold
AND the hour is concretely higher than the device's own history at similar
times of day on at least one measured dimension, so every alert comes with a
plain-English reason a household can check.
"""
from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from backend.db import models

WINDOW_HOURS = 7 * 24
SAMPLES_NEEDED = 48
N_TREES = 100
SUBSAMPLE_SIZE = 64
ANOMALY_THRESHOLD = 0.70
ALERT_TITLE_PREFIX = "Unusual activity from "
SIMULATED_REASON = "Simulated for demonstration"

_EULER_GAMMA = 0.5772156649015329
_HOUR = timedelta(hours=1)


# ---------------------------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------------------------


def average_path_length(n: int) -> float:
    """c(n): expected path length of an unsuccessful binary-search-tree lookup."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER_GAMMA) - 2.0 * (n - 1) / n


class IsolationForest:
    def __init__(self, n_trees: int = N_TREES, sample_size: int = SUBSAMPLE_SIZE, seed: int = 0):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self._trees: list[tuple] = []
        self._fitted_sample = 0

    def fit(self, rows: list[list[float]]) -> "IsolationForest":
        if len(rows) < 2:
            raise ValueError("an Isolation Forest needs at least two samples")
        rng = random.Random(self.seed)  # nosec B311: model randomness, not security
        self._fitted_sample = min(self.sample_size, len(rows))
        height_limit = math.ceil(math.log2(self._fitted_sample))
        self._trees = [
            self._grow(rng.sample(rows, self._fitted_sample), 0, height_limit, rng)
            for _ in range(self.n_trees)
        ]
        return self

    def _grow(self, rows: list[list[float]], depth: int, limit: int, rng: random.Random) -> tuple:
        if depth >= limit or len(rows) <= 1:
            return ("leaf", len(rows))
        splittable = []
        for feature in range(len(rows[0])):
            low = min(row[feature] for row in rows)
            high = max(row[feature] for row in rows)
            if high > low:
                splittable.append((feature, low, high))
        if not splittable:
            return ("leaf", len(rows))
        feature, low, high = rng.choice(splittable)
        threshold = rng.uniform(low, high)
        left = [row for row in rows if row[feature] < threshold]
        right = [row for row in rows if row[feature] >= threshold]
        return (
            "split",
            feature,
            threshold,
            self._grow(left, depth + 1, limit, rng),
            self._grow(right, depth + 1, limit, rng),
        )

    @staticmethod
    def _path_length(point: list[float], node: tuple) -> float:
        depth = 0
        while node[0] == "split":
            _, feature, threshold, left, right = node
            node = left if point[feature] < threshold else right
            depth += 1
        return depth + average_path_length(node[1])

    def score(self, point: list[float]) -> float:
        if not self._trees:
            raise RuntimeError("fit() must be called before score()")
        mean_depth = sum(self._path_length(point, tree) for tree in self._trees) / len(self._trees)
        return 2.0 ** (-mean_depth / average_path_length(self._fitted_sample))


# ---------------------------------------------------------------------------
# Hourly features from recorded traffic
# ---------------------------------------------------------------------------


@dataclass
class HourBucket:
    start: datetime
    bytes: int = 0
    queries: int = 0
    domains: set[str] = field(default_factory=set)
    new_domains: int = 0
    blocked: int = 0

    @property
    def local_hour(self) -> int:
        return self.start.astimezone().hour


def floor_hour(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _julian_to_datetime(julian_day: float) -> datetime:
    # A float Julian day is only precise to ~50 microseconds; rounding to the
    # millisecond keeps an on-the-hour timestamp from landing in the hour before.
    return datetime.fromtimestamp(round((julian_day - 2440587.5) * 86400, 3), tz=timezone.utc)


def _first_activity(conn, device_id: int) -> datetime | None:
    row = conn.execute(
        "SELECT MIN(julianday(created_at)) FROM traffic_logs WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    return _julian_to_datetime(row[0]) if row and row[0] is not None else None


def _sample_count(first_activity: datetime | None, end: datetime) -> int:
    if first_activity is None:
        return 0
    start = max(floor_hour(first_activity), end - WINDOW_HOURS * _HOUR)
    return max(0, int((end - start) / _HOUR))


def hourly_buckets(conn, device_id: int, end: datetime) -> list[HourBucket]:
    """Hourly buckets from the device's first activity (at most a week back) up
    to, but not including, ``end``. Hours with no traffic are real samples too:
    a camera that is silent at 3 AM every night is exactly the habit to learn."""
    end = floor_hour(end)
    count = _sample_count(_first_activity(conn, device_id), end)
    if count == 0:
        return []
    start = end - count * _HOUR
    buckets = [HourBucket(start + index * _HOUR) for index in range(count)]

    first_seen = {
        row["domain"]: _julian_to_datetime(row["first_seen"])
        for row in conn.execute(
            """SELECT domain, MIN(julianday(created_at)) AS first_seen FROM traffic_logs
               WHERE device_id = ? AND domain IS NOT NULL AND domain != ''
               GROUP BY domain""",
            (device_id,),
        ).fetchall()
    }
    rows = conn.execute(
        """SELECT domain, bytes_sent + bytes_received AS bytes, was_blocked, created_at
           FROM traffic_logs
           WHERE device_id = ?
             AND julianday(created_at) >= julianday(?) AND julianday(created_at) < julianday(?)""",
        (device_id, start.isoformat(), end.isoformat()),
    ).fetchall()
    for row in rows:
        moment = datetime.fromisoformat(row["created_at"])
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        index = int((floor_hour(moment) - start) / _HOUR)
        if not 0 <= index < count:
            continue
        bucket = buckets[index]
        bucket.bytes += int(row["bytes"] or 0)
        bucket.queries += 1
        bucket.blocked += int(row["was_blocked"] or 0)
        domain = row["domain"]
        if domain:
            bucket.domains.add(domain)
    for bucket in buckets:
        bucket.new_domains = sum(
            1
            for domain in bucket.domains
            if domain in first_seen and floor_hour(first_seen[domain]) == bucket.start
        )
    return buckets


def _hours_apart(first: int, second: int) -> int:
    return min((first - second) % 24, (second - first) % 24)


def _volume(bucket: HourBucket) -> list[float]:
    return [math.log1p(bucket.bytes), math.log1p(bucket.queries), math.log1p(len(bucket.domains))]


def hour_baselines(history: list[HourBucket]) -> list[list[float]]:
    """Per local hour, the device's median (log) volume at that hour +/- 1."""
    baselines = []
    for hour in range(24):
        similar = [_volume(bucket) for bucket in history if _hours_apart(bucket.local_hour, hour) <= 1]
        similar = similar or [_volume(bucket) for bucket in history]
        baselines.append([statistics.median(values[index] for values in similar) for index in range(3)])
    return baselines


def features(bucket: HourBucket, baselines: list[list[float]]) -> list[float]:
    usual = baselines[bucket.local_hour]
    volume = _volume(bucket)
    return [volume[index] - usual[index] for index in range(3)] + [
        math.log1p(bucket.new_domains),
        math.log1p(bucket.blocked),
    ]


# ---------------------------------------------------------------------------
# Scoring and plain-English explanations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HabitResult:
    bucket_start: datetime
    score: float
    reasons: list[str]

    @property
    def is_anomaly(self) -> bool:
        return self.score >= ANOMALY_THRESHOLD and bool(self.reasons)


def hour_label(hour: int) -> str:
    if hour == 0:
        return "midnight"
    if hour == 12:
        return "noon"
    return f"{hour % 12} {'AM' if hour < 12 else 'PM'}"


def format_bytes(value: float) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f} GB"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.0f} MB" if value >= 10_000_000 else f"{value / 1_000_000:.1f} MB"
    if value >= 1_000:
        return f"{value / 1_000:.0f} KB"
    return f"{int(value)} bytes"


def _similar_hours(target: HourBucket, history: list[HourBucket]) -> list[HourBucket]:
    hour = target.local_hour
    similar = [bucket for bucket in history if _hours_apart(bucket.local_hour, hour) <= 1]
    return similar or history


def explain(target: HourBucket, history: list[HourBucket]) -> list[str]:
    """Reasons this hour is higher than the device's own history at similar
    times of day, most meaningful first (data volume, then never-seen sites,
    then blocked requests, then raw request counts). Only increases count:
    going quiet is not a security concern."""
    similar = _similar_hours(target, history)
    around = f"around {hour_label(target.local_hour)}"

    def typical(values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    reasons: list[str] = []

    usual_bytes = typical([bucket.bytes for bucket in similar])
    if target.bytes >= 1_000_000 and target.bytes >= 5 * max(usual_bytes, 1):
        if usual_bytes < 100_000:
            reasons.append(
                f"sent {format_bytes(target.bytes)} {around}, when it is usually almost idle "
                f"(about {format_bytes(usual_bytes)})"
            )
        else:
            reasons.append(
                f"sent {target.bytes / usual_bytes:.0f}x more data than it usually does {around} "
                f"({format_bytes(target.bytes)} vs. about {format_bytes(usual_bytes)})"
            )

    usual_new = typical([bucket.new_domains for bucket in history[-48:]])
    if target.new_domains >= 3 and target.new_domains >= 3 * (usual_new + 0.5):
        reasons.append(f"contacted {target.new_domains} websites it has never used before")

    usual_blocked = typical([bucket.blocked for bucket in similar])
    if target.blocked >= 3 and target.blocked >= 3 * (usual_blocked + 0.5):
        reasons.append(f"had {target.blocked} requests blocked by your filters")

    usual_queries = typical([bucket.queries for bucket in similar])
    if target.queries >= 20 and target.queries >= 4 * max(usual_queries, 1):
        if usual_queries < 1:
            reasons.append(f"made {target.queries} DNS requests {around}, when it usually makes almost none")
        else:
            reasons.append(
                f"made {target.queries} DNS requests {around}, about "
                f"{target.queries / usual_queries:.0f}x its usual {usual_queries:.0f}"
            )

    return reasons[:2]


def score_hour(conn, device_id: int, bucket_start: datetime, *, seed: int | None = None) -> HabitResult | None:
    """Train on the device's history before ``bucket_start`` and score that hour.
    Returns None while the device is still learning."""
    bucket_start = floor_hour(bucket_start)
    buckets = hourly_buckets(conn, device_id, bucket_start + _HOUR)
    if not buckets or buckets[-1].start != bucket_start:
        return None
    target, history = buckets[-1], buckets[:-1]
    if len(history) < SAMPLES_NEEDED:
        return None
    baselines = hour_baselines(history)
    forest = IsolationForest(seed=device_id if seed is None else seed)
    forest.fit([features(bucket, baselines) for bucket in history])
    score = forest.score(features(target, baselines))
    return HabitResult(bucket_start, round(score, 3), explain(target, history))


def device_label(device: dict) -> str:
    return (
        device.get("hostname")
        or device.get("model")
        or (f"{device['vendor']} device" if device.get("vendor") else None)
        or device.get("ip")
        or "a device"
    )


def describe(device: dict, result: HabitResult) -> str:
    reasons = result.reasons
    joined = reasons[0] if len(reasons) == 1 else f"{reasons[0]}, and {reasons[1]}"
    return (
        f"{device_label(device)} {joined}. Home Radar's habit model rated this hour "
        f"{result.score:.2f} on a 0-1 unusualness scale (alerts start at {ANOMALY_THRESHOLD:.2f})."
    )


def _save_state(conn, device_id: int, result: HabitResult, explanation: str) -> None:
    conn.execute(
        """INSERT INTO device_habits (device_id, last_bucket, last_scored_at, last_score, last_explanation)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(device_id) DO UPDATE SET
               last_bucket = excluded.last_bucket,
               last_scored_at = excluded.last_scored_at,
               last_score = excluded.last_score,
               last_explanation = excluded.last_explanation""",
        (
            device_id,
            result.bucket_start.isoformat(),
            datetime.now(timezone.utc).isoformat(),
            result.score,
            explanation,
        ),
    )


def record_result(conn, device: dict, result: HabitResult, *, note: str = "", dedupe: bool = True) -> int | None:
    """Persist the latest score and raise an alert when the hour is out of character."""
    if not result.is_anomaly:
        _save_state(conn, device["id"], result, "Nothing out of the ordinary in the hour checked.")
        return None
    explanation = describe(device, result)
    _save_state(conn, device["id"], result, explanation)
    title = f"{ALERT_TITLE_PREFIX}{device_label(device)}"
    description = f"{explanation} {note}".strip()
    if dedupe:
        return models.create_alert_once(conn, device["id"], "warning", title, description, window_minutes=180)
    return models.create_alert(conn, device["id"], "warning", title, description)


def analyze_device_habits(conn, device_id: int, now: datetime | None = None) -> HabitResult | None:
    """Score the most recent completed hour once; cheap to call every trust cycle."""
    device = models.get_device(conn, device_id)
    if device is None:
        return None
    bucket_start = floor_hour(now or datetime.now(timezone.utc)) - _HOUR
    state = conn.execute(
        "SELECT last_bucket FROM device_habits WHERE device_id = ?", (device_id,)
    ).fetchone()
    if state and state["last_bucket"] == bucket_start.isoformat():
        return None
    result = score_hour(conn, device_id, bucket_start)
    if result is not None:
        record_result(conn, device, result)
    return result


# ---------------------------------------------------------------------------
# Read models for the API
# ---------------------------------------------------------------------------


def profile(conn, device_id: int, now: datetime | None = None) -> dict:
    end = floor_hour(now or datetime.now(timezone.utc))
    buckets = hourly_buckets(conn, device_id, end)
    # Median requests per local hour, so one unusual night doesn't reshape the
    # picture of what "typical" looks like.
    per_hour: list[list[int]] = [[] for _ in range(24)]
    for bucket in buckets:
        per_hour[bucket.local_hour].append(bucket.queries)
    activity = [statistics.median(values) if values else 0 for values in per_hour]
    total = sum(activity)
    state = conn.execute(
        "SELECT last_scored_at, last_score, last_explanation FROM device_habits WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    return {
        "status": "ready" if len(buckets) >= SAMPLES_NEEDED else "learning",
        "samples": len(buckets),
        "samples_needed": SAMPLES_NEEDED,
        "typical_active_hours": [round(value / total, 4) if total else 0.0 for value in activity],
        "last_scored_at": state["last_scored_at"] if state else None,
        "last_score": state["last_score"] if state else None,
        "last_explanation": state["last_explanation"] if state else None,
    }


def summary(conn, now: datetime | None = None) -> dict:
    end = floor_hour(now or datetime.now(timezone.utc))
    first = {
        row["device_id"]: _julian_to_datetime(row["first_jd"])
        for row in conn.execute(
            """SELECT device_id, MIN(julianday(created_at)) AS first_jd FROM traffic_logs
               WHERE device_id IS NOT NULL GROUP BY device_id"""
        ).fetchall()
    }
    ready = learning = 0
    for row in conn.execute("SELECT id FROM devices").fetchall():
        if _sample_count(first.get(row["id"]), end) >= SAMPLES_NEEDED:
            ready += 1
        else:
            learning += 1
    anomalies = conn.execute(
        """SELECT COUNT(*) FROM alerts
           WHERE title LIKE ? AND julianday(created_at) >= julianday('now', '-24 hours')""",
        (f"{ALERT_TITLE_PREFIX}%",),
    ).fetchone()[0]
    return {"devices_learning": learning, "devices_ready": ready, "anomalies_24h": anomalies}


def unresolved_habit_alerts(conn, device_id: int) -> int:
    return conn.execute(
        """SELECT COUNT(*) FROM alerts
           WHERE device_id = ? AND is_resolved = 0 AND title LIKE ?
             AND julianday(created_at) >= julianday('now', '-24 hours')""",
        (device_id, f"{ALERT_TITLE_PREFIX}%"),
    ).fetchone()[0]


# ---------------------------------------------------------------------------
# Demo: a camera that wakes up at 3 AM and uploads data
# ---------------------------------------------------------------------------

DEMO_CAMERA_MAC = "2C:AA:8E:4D:21:7C"  # 2C:AA:8E is a Wyze Labs OUI
DEMO_CAMERA_NAME = "Living room camera"
_DEMO_USUAL_DOMAINS = (
    "cloud.camera-vendor.example",
    "time.camera-vendor.example",
    "events.camera-vendor.example",
)


def latest_local_hour(now: datetime, hour: int) -> datetime:
    """The most recent fully completed UTC hour bucket whose local hour is ``hour``."""
    candidate = floor_hour(now) - _HOUR
    for _ in range(48):
        if candidate.astimezone().hour == hour:
            return candidate
        candidate -= _HOUR
    raise ValueError(f"no local hour {hour} in the last two days")


def _insert_rows(conn, rows: list[tuple]) -> None:
    conn.executemany(
        """INSERT INTO traffic_logs (
               device_id, domain, dest_ip, bytes_sent, bytes_received, was_blocked,
               threat_level, threat_reason, query_type, created_at
           ) VALUES (?, ?, NULL, ?, ?, 0, 'none', ?, 'A', ?)""",
        rows,
    )


def seed_demo_history(conn, device_id: int, anomaly_hour: datetime, end: datetime, rng: random.Random) -> None:
    """Seven days of ordinary camera behavior before ``end``, plus one 3 AM hour
    that uploads a lot of data to never-seen hosts. Every row is labeled as
    simulated so it can't be mistaken for real household traffic."""
    conn.execute(
        "DELETE FROM traffic_logs WHERE device_id = ? AND threat_reason = ?",
        (device_id, SIMULATED_REASON),
    )
    conn.execute("DELETE FROM device_habits WHERE device_id = ?", (device_id,))
    rows: list[tuple] = []

    def add(moment: datetime, domain: str, sent: int, received: int) -> None:
        rows.append((device_id, domain, sent, received, SIMULATED_REASON, moment.isoformat()))

    hour_start = anomaly_hour - 7 * 24 * _HOUR
    while hour_start < end:
        local = hour_start.astimezone().hour
        if hour_start != anomaly_hour:
            if 7 <= local <= 22:
                queries = rng.randint(3, 8) + (3 if 17 <= local <= 21 else 0)
                per_query = rng.randint(20_000, 60_000)
            else:
                queries = rng.choice((0, 1, 1))
                per_query = rng.randint(2_000, 6_000)
            for _ in range(queries):
                minute = timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                add(hour_start + minute, rng.choice(_DEMO_USUAL_DOMAINS), per_query, per_query // 4)
        else:
            add(hour_start + timedelta(minutes=2), _DEMO_USUAL_DOMAINS[0], 4_000, 1_000)
            for index in range(9):
                for _ in range(rng.randint(2, 4)):
                    minute = timedelta(minutes=rng.randint(5, 55), seconds=rng.randint(0, 59))
                    add(
                        hour_start + minute,
                        f"relay-{index + 1}.offsite-storage.example",
                        rng.randint(1_500_000, 2_200_000),
                        rng.randint(20_000, 60_000),
                    )
        hour_start += _HOUR
    _insert_rows(conn, rows)


def simulate_night_upload(conn, ip: str, now: datetime | None = None) -> tuple[dict, HabitResult | None, int | None]:
    """Run the real habit model on a staged camera that uploads data at 3 AM."""
    now = now or datetime.now(timezone.utc)
    device_id = models.upsert_device(
        conn,
        mac=DEMO_CAMERA_MAC,
        ip=ip,
        hostname=DEMO_CAMERA_NAME,
        vendor="Wyze Labs",
        model="Indoor camera",
        device_type="iot_camera",
        confidence=0.88,
        open_ports=[554],
        discovery_sources=["demo"],
    )
    anomaly_hour = latest_local_hour(now, 3)
    rng = random.Random(7)  # nosec B311: deterministic demo data, not security
    seed_demo_history(conn, device_id, anomaly_hour, floor_hour(now), rng)
    result = score_hour(conn, device_id, anomaly_hour)
    device = models.get_device(conn, device_id) or {"id": device_id, "hostname": DEMO_CAMERA_NAME}
    alert_id = None
    if result is not None:
        alert_id = record_result(
            conn, device, result, note=f"({SIMULATED_REASON}.)", dedupe=False
        )
    return device, result, alert_id
