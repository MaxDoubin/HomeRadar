"""Tests for the habit model: the Isolation Forest itself, hourly features,
plain-English explanations, the learning lifecycle, the API, and the staged
night-upload demo."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from backend.api import routes as api_routes
from backend.db import models
from backend.monitor import habits
from backend.monitor.trust_scoring import score_device

NOW = datetime(2026, 10, 20, 15, 30, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def _add_device(conn, mac="AA:BB:CC:00:00:01", hostname="Kitchen speaker"):
    return models.upsert_device(conn, mac=mac, ip="192.168.1.40", hostname=hostname, vendor="Sonos")


def _insert(conn, device_id, moment, domain="api.example", sent=1000, received=200, blocked=0):
    conn.execute(
        """INSERT INTO traffic_logs (device_id, domain, bytes_sent, bytes_received, was_blocked, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (device_id, domain, sent, received, blocked, moment.isoformat()),
    )


# --- Isolation Forest ---------------------------------------------------------


def test_average_path_length_matches_reference_values():
    assert habits.average_path_length(1) == 0.0
    assert habits.average_path_length(2) == 1.0
    assert habits.average_path_length(256) == pytest.approx(10.24, abs=0.01)


def test_forest_scores_outliers_above_inliers():
    rng = random.Random(3)
    inliers = [[rng.gauss(0, 1), rng.gauss(0, 1)] for _ in range(300)]
    forest = habits.IsolationForest(seed=11).fit(inliers)
    inlier_scores = sorted(forest.score(point) for point in inliers)
    outlier_scores = [forest.score(point) for point in ([8, 8], [-9, 7], [10, -10])]
    median_inlier = inlier_scores[len(inlier_scores) // 2]
    assert median_inlier < 0.5
    assert min(outlier_scores) > 0.65
    assert min(outlier_scores) > inlier_scores[int(len(inlier_scores) * 0.95)]


def test_forest_is_deterministic_for_a_seed():
    rows = [[float(i % 7), float(i % 5)] for i in range(100)]
    first = habits.IsolationForest(seed=5).fit(rows).score([20.0, 20.0])
    second = habits.IsolationForest(seed=5).fit(rows).score([20.0, 20.0])
    assert first == second


def test_forest_requires_two_samples_and_fit_before_score():
    with pytest.raises(ValueError):
        habits.IsolationForest().fit([[1.0]])
    with pytest.raises(RuntimeError):
        habits.IsolationForest().score([1.0])


# --- Lifecycle and features ---------------------------------------------------


def test_device_is_learning_until_enough_hours(db_path):
    with models.get_conn(db_path) as conn:
        device_id = _add_device(conn)
        end = habits.floor_hour(NOW)
        for hours_ago in range(1, 11):
            _insert(conn, device_id, end - hours_ago * HOUR + timedelta(minutes=5))
        learning = habits.profile(conn, device_id, now=NOW)
        assert learning["status"] == "learning"
        assert learning["samples"] == 10
        assert learning["samples_needed"] == habits.SAMPLES_NEEDED

        for hours_ago in range(11, 61):
            _insert(conn, device_id, end - hours_ago * HOUR + timedelta(minutes=5))
        ready = habits.profile(conn, device_id, now=NOW)
        assert ready["status"] == "ready"
        assert ready["samples"] == 60
        assert len(ready["typical_active_hours"]) == 24
        assert sum(ready["typical_active_hours"]) == pytest.approx(1.0, abs=0.01)


def test_window_is_capped_at_one_week(db_path):
    with models.get_conn(db_path) as conn:
        device_id = _add_device(conn)
        _insert(conn, device_id, NOW - timedelta(days=30))
        assert habits.profile(conn, device_id, now=NOW)["samples"] == habits.WINDOW_HOURS


def test_buckets_count_new_domains_only_in_the_hour_first_seen(db_path):
    with models.get_conn(db_path) as conn:
        device_id = _add_device(conn)
        end = habits.floor_hour(NOW)
        _insert(conn, device_id, end - 3 * HOUR, domain="a.example")
        _insert(conn, device_id, end - 2 * HOUR, domain="a.example")
        _insert(conn, device_id, end - 2 * HOUR, domain="b.example", blocked=1)
        buckets = habits.hourly_buckets(conn, device_id, end)
    assert [bucket.new_domains for bucket in buckets] == [1, 1, 0]
    assert [bucket.queries for bucket in buckets] == [1, 2, 0]
    assert buckets[1].blocked == 1


def test_learning_device_is_not_scored(db_path):
    with models.get_conn(db_path) as conn:
        device_id = _add_device(conn)
        _insert(conn, device_id, NOW - 3 * HOUR)
        assert habits.analyze_device_habits(conn, device_id, now=NOW) is None


# --- Explanations ---------------------------------------------------------------


def _quiet_night_history(anomaly_start):
    history = []
    for hours_back in range(72, 0, -1):
        bucket = habits.HourBucket(anomaly_start - hours_back * HOUR)
        if 7 <= bucket.local_hour <= 22:
            bucket.bytes, bucket.queries = 200_000, 6
            bucket.domains = {"cloud.camera.example"}
        else:
            bucket.bytes, bucket.queries = 5_000, 1
            bucket.domains = {"cloud.camera.example"}
        history.append(bucket)
    return history


def test_explanation_for_a_big_night_upload():
    anomaly_start = habits.latest_local_hour(NOW, 3)
    target = habits.HourBucket(anomaly_start, bytes=50_000_000, queries=27, new_domains=9)
    target.domains = {f"relay-{i}.example" for i in range(9)}
    reasons = habits.explain(target, _quiet_night_history(anomaly_start))
    assert len(reasons) == 2
    assert reasons[0].startswith("sent 50 MB around 3 AM, when it is usually almost idle")
    assert "contacted 9 websites it has never used before" in reasons


def test_ordinary_hour_has_no_reasons():
    anomaly_start = habits.latest_local_hour(NOW, 3)
    target = habits.HourBucket(anomaly_start, bytes=6_000, queries=1)
    target.domains = {"cloud.camera.example"}
    assert habits.explain(target, _quiet_night_history(anomaly_start)) == []


def test_hour_labels():
    assert habits.hour_label(0) == "midnight"
    assert habits.hour_label(3) == "3 AM"
    assert habits.hour_label(12) == "noon"
    assert habits.hour_label(21) == "9 PM"


# --- Scoring, alerts, dedup, trust ------------------------------------------------


def _seeded_camera(conn):
    device_id = _add_device(conn, mac="2C:AA:8E:00:00:01", hostname="Hall camera")
    anomaly = habits.latest_local_hour(NOW, 3)
    habits.seed_demo_history(conn, device_id, anomaly, habits.floor_hour(NOW), random.Random(1))
    return device_id, anomaly


def test_model_flags_the_night_upload_and_not_an_ordinary_hour(db_path):
    with models.get_conn(db_path) as conn:
        device_id, anomaly = _seeded_camera(conn)
        flagged = habits.score_hour(conn, device_id, anomaly)
        ordinary = habits.score_hour(conn, device_id, anomaly - 24 * HOUR)
    assert flagged is not None and flagged.is_anomaly
    assert flagged.score >= habits.ANOMALY_THRESHOLD
    assert ordinary is not None and not ordinary.is_anomaly
    assert ordinary.score < flagged.score


def test_record_result_dedupes_alerts_and_feeds_trust(db_path):
    with models.get_conn(db_path) as conn:
        device_id, anomaly = _seeded_camera(conn)
        result = habits.score_hour(conn, device_id, anomaly)
        device = models.get_device(conn, device_id)
        first = habits.record_result(conn, device, result)
        second = habits.record_result(conn, device, result)
        alerts = [alert for alert in models.list_alerts(conn) if alert["device_id"] == device_id]
        trust = score_device(conn, models.get_device(conn, device_id))
        state = habits.profile(conn, device_id, now=NOW)
    assert first is not None and second is None
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Unusual activity from Hall camera"
    assert alerts[0]["description"].startswith("Hall camera sent ")
    assert "out-of-character activity" in trust.factors
    assert state["last_score"] == result.score
    assert state["last_explanation"].startswith("Hall camera sent ")


def test_analyze_scores_each_completed_hour_only_once(db_path):
    with models.get_conn(db_path) as conn:
        device_id, _ = _seeded_camera(conn)
        first = habits.analyze_device_habits(conn, device_id, now=NOW)
        again = habits.analyze_device_habits(conn, device_id, now=NOW)
        later = habits.analyze_device_habits(conn, device_id, now=NOW + HOUR)
    assert first is not None
    assert again is None
    assert later is not None


# --- API ------------------------------------------------------------------------


def test_device_habits_endpoint_shape_and_404(client, db_path):
    with models.get_conn(db_path) as conn:
        device_id = _add_device(conn)
    response = client.get(f"/devices/{device_id}/habits")
    assert response.status_code == 200
    assert set(response.json()) == {
        "status", "samples", "samples_needed", "typical_active_hours",
        "last_scored_at", "last_score", "last_explanation",
    }
    assert response.json()["status"] == "learning"
    assert client.get("/devices/999999/habits").status_code == 404


def test_habits_summary_is_open_and_counts(client, db_path):
    with models.get_conn(db_path) as conn:
        _add_device(conn)
    response = client.get("/habits/summary")
    assert response.status_code == 200
    assert response.json() == {"devices_learning": 1, "devices_ready": 0, "anomalies_24h": 0}


def test_night_upload_demo_404_when_disabled(client, auth_headers, monkeypatch):
    monkeypatch.setattr(api_routes.config, "DEMO_MODE_ENABLED", False)
    response = client.post("/demo/simulate-attack", json={"kind": "night_upload"}, headers=auth_headers)
    assert response.status_code == 404


def test_night_upload_demo_runs_the_real_model(client, auth_headers, monkeypatch, db_path):
    monkeypatch.setattr(api_routes.config, "DEMO_MODE_ENABLED", True)
    response = client.post("/demo/simulate-attack", json={"kind": "night_upload"}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "night_upload"
    assert body["device"]["hostname"] == "Living room camera"
    assert body["device"]["mac"] == habits.DEMO_CAMERA_MAC
    assert body["alert"]["title"] == "Unusual activity from Living room camera"
    assert body["alert"]["description"].endswith("(Simulated for demonstration.)")
    assert body["habits"]["score"] >= habits.ANOMALY_THRESHOLD
    assert "around 3 AM" in body["habits"]["explanation"]
    assert len(body["habits"]["typical_active_hours"]) == 24

    profile = client.get(f"/devices/{body['device']['id']}/habits").json()
    assert profile["status"] == "ready"
    assert client.get("/habits/summary").json()["anomalies_24h"] == 1

    again = client.post("/demo/simulate-attack", json={"kind": "night_upload"}, headers=auth_headers)
    assert again.status_code == 200
    assert again.json()["device"]["id"] == body["device"]["id"]
    with models.get_conn(db_path) as conn:
        cameras = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE mac = ?", (habits.DEMO_CAMERA_MAC,)
        ).fetchone()[0]
        simulated = conn.execute(
            "SELECT COUNT(*) FROM traffic_logs WHERE threat_reason = ?", (habits.SIMULATED_REASON,)
        ).fetchone()[0]
    assert cameras == 1
    assert 0 < simulated < 2000
