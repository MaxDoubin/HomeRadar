"""Bedtime, tracker report, vulnerability check, and household demo seeding."""
from __future__ import annotations

import functools
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from dnslib import DNSRecord, RCODE

from backend import config
from backend.db import models
from backend.dns.blocklists import BlocklistManager
from backend.dns.policy import evaluate_policy, in_window, next_schedule_change, schedule_window
from backend.dns.proxy import DNSProxy
from backend.insights.bedtime import device_bedtime, list_bedtimes
from backend.insights.kev_sample import KEV_SAMPLE
from backend.insights.trackers import build_privacy_report, match_tracker
from backend.insights.vulnerabilities import (
    brand_for_catalog_vendor,
    brand_for_vendor,
    check_household,
    is_chip_maker,
    normalize_vendor,
)

LA = ZoneInfo("America/Los_Angeles")


@pytest.fixture
def insights_client(patched_db, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from backend.api.insights_routes import router as insights_router
    from backend.api.routes import router as api_router
    from backend.security import ApplianceSecurityMiddleware

    monkeypatch.setattr(
        "backend.api.insights_routes.get_conn", functools.partial(models.get_conn, patched_db)
    )
    app = FastAPI()
    app.include_router(api_router)
    app.include_router(insights_router)
    app.add_middleware(ApplianceSecurityMiddleware)
    with TestClient(app) as client:
        yield client


def _device(db_path, mac, ip, vendor=None, hostname=None):
    with models.get_conn(db_path) as conn:
        return models.upsert_device(conn, mac=mac, ip=ip, hostname=hostname, vendor=vendor)


def _log(db_path, device_id, domain, count=1, blocked=False):
    with models.get_conn(db_path) as conn:
        for _ in range(count):
            models.log_traffic(conn, device_id=device_id, domain=domain, was_blocked=blocked)


# --- bedtime -----------------------------------------------------------------


def test_overnight_window_wraps_midnight():
    start, end = time(21), time(7)
    assert in_window(start, end, time(23, 30))
    assert in_window(start, end, time(6, 59))
    assert not in_window(start, end, time(7))
    assert not in_window(start, end, time(12))
    assert in_window(time(13), time(15), time(14))


def test_equal_start_and_end_is_not_an_all_day_block():
    policy = {"internet_enabled": True, "block_start": "21:00", "block_end": "21:00"}
    assert schedule_window(policy) is None
    assert not evaluate_policy(policy, "example.com", datetime(2026, 1, 1, 22)).blocked


def test_next_change_closes_and_opens_window():
    start, end = time(21), time(7)
    late = datetime(2026, 3, 2, 23, 15, tzinfo=LA)
    assert next_schedule_change(start, end, late) == datetime(2026, 3, 3, 7, tzinfo=LA)
    early = datetime(2026, 3, 3, 6, 0, tzinfo=LA)
    assert next_schedule_change(start, end, early) == datetime(2026, 3, 3, 7, tzinfo=LA)
    midday = datetime(2026, 3, 3, 12, 0, tzinfo=LA)
    assert next_schedule_change(start, end, midday) == datetime(2026, 3, 3, 21, tzinfo=LA)


def test_device_bedtime_summaries():
    device = {"id": 4, "hostname": "Kids' tablet"}
    policy = {"internet_enabled": True, "block_start": "21:00", "block_end": "07:00"}
    asleep = device_bedtime(policy, device, datetime(2026, 3, 2, 22, 0, tzinfo=LA))
    assert asleep["active_now"] and asleep["summary"] == "Offline until 7:00 AM"
    awake = device_bedtime(policy, device, datetime(2026, 3, 2, 15, 0, tzinfo=LA))
    assert not awake["active_now"] and awake["summary"] == "Goes offline at 9:00 PM"
    assert awake["next_change_at"].startswith("2026-03-02T21:00:00")
    paused = device_bedtime({"internet_enabled": False}, device, datetime(2026, 3, 2, 15, tzinfo=LA))
    assert paused["active_now"] and paused["next_change_at"] is None
    assert device_bedtime({"internet_enabled": True}, device, datetime(2026, 3, 2, tzinfo=LA)) is None


def test_proxy_enforces_overnight_bedtime_in_household_timezone(patched_db, db_path, tmp_path, monkeypatch):
    device_id = _device(db_path, "AA:BB:CC:00:00:01", "10.0.0.21", hostname="tablet")
    with models.get_conn(db_path) as conn:
        models.set_device_policy(conn, device_id, block_start="21:00", block_end="07:00")
        models.set_settings(conn, {"household_timezone": "America/Los_Angeles"})

    seen = {}

    def fake_now(name=None):
        seen["timezone"] = name
        return fake_now.value

    monkeypatch.setattr("backend.dns.proxy.household_now", fake_now)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    payload = DNSRecord.question("games.example", "A").pack()
    monkeypatch.setattr(proxy, "_resolve", lambda p: DNSRecord.parse(p).reply().pack())

    fake_now.value = datetime(2026, 3, 2, 23, 30, tzinfo=LA)
    assert DNSRecord.parse(proxy._process(payload, "10.0.0.21")).header.rcode == RCODE.REFUSED
    assert seen["timezone"] == "America/Los_Angeles"

    fake_now.value = datetime(2026, 3, 3, 12, 0, tzinfo=LA)
    assert DNSRecord.parse(proxy._process(payload, "10.0.0.21")).header.rcode == RCODE.NOERROR


def test_proxy_refuses_paused_device(patched_db, db_path, tmp_path):
    device_id = _device(db_path, "AA:BB:CC:00:00:02", "10.0.0.22")
    with models.get_conn(db_path) as conn:
        models.set_device_policy(conn, device_id, internet_enabled=False)
    proxy = DNSProxy(BlocklistManager(tmp_path / "blocklist.txt"), dynamic_upstream=False)
    response = proxy._process(DNSRecord.question("any.example", "A").pack(), "10.0.0.22")
    assert DNSRecord.parse(response).header.rcode == RCODE.REFUSED


def test_bedtime_endpoint_and_timezone_update(insights_client, patched_db, db_path, auth_headers):
    device_id = _device(db_path, "AA:BB:CC:00:00:03", "10.0.0.23", hostname="Kids' tablet")
    with models.get_conn(db_path) as conn:
        models.set_device_policy(conn, device_id, block_start="21:00", block_end="07:00")
    assert insights_client.put("/bedtime/timezone", json={"timezone": "America/Los_Angeles"}).status_code == 401
    bad = insights_client.put("/bedtime/timezone", json={"timezone": "Mars/Base"}, headers=auth_headers)
    assert bad.status_code == 422
    response = insights_client.put(
        "/bedtime/timezone", json={"timezone": "America/Los_Angeles"}, headers=auth_headers
    )
    assert response.status_code == 200
    body = insights_client.get("/bedtime").json()
    assert body["timezone"] == "America/Los_Angeles" and body["timezone_source"] == "household"
    [entry] = body["devices"]
    assert entry["name"] == "Kids' tablet" and entry["next_change_at"]


def test_list_bedtimes_skips_devices_without_schedule(patched_db, db_path):
    plain = _device(db_path, "AA:BB:CC:00:00:04", "10.0.0.24")
    with models.get_conn(db_path) as conn:
        models.set_device_policy(conn, plain, blocked_domains=["example.com"])
        assert list_bedtimes(conn, datetime(2026, 3, 2, 12, tzinfo=LA))["devices"] == []


# --- trackers ----------------------------------------------------------------


def test_tracker_suffix_matching():
    assert match_tracker("googleads.g.doubleclick.net") == ("Google", "Advertising")
    assert match_tracker("LOG-INGESTION.samsungacr.com.") == ("Samsung", "TV viewing data")
    assert match_tracker("doubleclick.net")[0] == "Google"
    assert match_tracker("notdoubleclick.net") is None
    assert match_tracker("www.google.com") is None
    assert match_tracker("") is None and match_tracker(None) is None


def test_privacy_report_aggregates_by_device_and_company(patched_db, db_path):
    tv = _device(db_path, "A0:02:DC:00:00:10", "10.0.0.30", vendor="Samsung", hostname="Living room TV")
    tablet = _device(db_path, "FC:A1:83:00:00:11", "10.0.0.31", vendor="Amazon")
    _device(db_path, "AA:BB:CC:00:00:12", "10.0.0.32", hostname="clean laptop")
    _log(db_path, tv, "log-ingestion.samsungacr.com", 5)
    _log(db_path, tv, "config.samsungads.com", 2, blocked=True)
    _log(db_path, tv, "www.netflix.com", 10)
    _log(db_path, tablet, "app-measurement.com", 3)
    _log(db_path, tablet, "googleads.g.doubleclick.net", 4, blocked=True)
    _log(db_path, tv, "googleads.g.doubleclick.net", 1)
    with models.get_conn(db_path) as conn:
        report = build_privacy_report(conn, 24)
    assert [item["name"] for item in report["devices"]] == ["Living room TV", "Amazon"]
    tv_report = report["devices"][0]
    assert tv_report["tracker_requests"] == 8 and tv_report["blocked_requests"] == 2
    assert tv_report["dns_queries"] == 18
    assert tv_report["companies"][0] == {
        "company": "Samsung",
        "category": "TV viewing data",
        "requests": 7,
        "blocked": 2,
        "domains": ["config.samsungads.com", "log-ingestion.samsungacr.com"],
        "categories": ["TV viewing data", "Advertising"],
    }
    google = next(item for item in report["top_companies"] if item["company"] == "Google")
    assert google["requests"] == 8 and google["devices"] == 2
    assert report["totals"]["devices_tracked"] == 2
    assert report["totals"]["tracker_requests"] == 15


def test_privacy_report_ignores_old_rows(patched_db, db_path):
    tv = _device(db_path, "A0:02:DC:00:00:20", "10.0.0.40")
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    with models.get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO traffic_logs (device_id, domain, created_at) VALUES (?, ?, ?)",
            (tv, "doubleclick.net", old),
        )
        assert build_privacy_report(conn, 24)["devices"] == []
        assert build_privacy_report(conn, 48)["devices"][0]["tracker_requests"] == 1


def test_privacy_endpoints(insights_client, patched_db, db_path):
    tv = _device(db_path, "A0:02:DC:00:00:30", "10.0.0.50", hostname="TV")
    _log(db_path, tv, "samsungads.com", 2)
    report = insights_client.get("/privacy/report?hours=24").json()
    assert report["devices"][0]["companies"][0]["company"] == "Samsung"
    device = insights_client.get(f"/devices/{tv}/privacy").json()
    assert device["tracker_requests"] == 2 and device["name"] == "TV"
    assert insights_client.get("/devices/9999/privacy").status_code == 404
    assert insights_client.get("/privacy/report?hours=0").status_code == 422


# --- vulnerabilities ---------------------------------------------------------


@pytest.mark.parametrize(
    ("vendor", "brand"),
    [
        ("TP-LINK TECHNOLOGIES CO.,LTD.", "tplink"),
        ("tp link", "tplink"),
        ("TP-Link", "tplink"),
        ("NETGEAR, Inc.", "netgear"),
        ("D-Link International", "dlink"),
        ("ASUSTek COMPUTER INC.", "asus"),
        ("Hangzhou Hikvision Digital Technology Co.,Ltd.", "hikvision"),
        ("Cisco-Linksys, LLC", "linksys"),
        ("Cisco Systems, Inc", "cisco"),
        ("Samsung Electronics Co.,Ltd", "samsung"),
        ("Apple, Inc.", "apple"),
        ("LG Electronics", "lg"),
    ],
)
def test_vendor_normalization_matches_brands(vendor, brand):
    assert brand_for_vendor(vendor) == brand


@pytest.mark.parametrize(
    "vendor",
    [
        "Espressif Inc.",
        "Realtek Semiconductor Corp.",
        "Intel Corporate",
        "Qualcomm Inc.",
        "Hon Hai Precision Ind. Co.,Ltd.",
        "Applied Materials",
        "LG Innotek",
        "Some Unknown Maker",
        "",
        None,
    ],
)
def test_vendor_normalization_rejects_chipmakers_and_unknowns(vendor):
    assert brand_for_vendor(vendor) is None


def test_chip_maker_and_catalog_vendor_helpers():
    assert is_chip_maker("Espressif Inc.") and not is_chip_maker("NETGEAR")
    assert normalize_vendor("Zhejiang Dahua Technology Co., Ltd.") == "dahuatechnologycoltd"
    assert brand_for_catalog_vendor("TP-Link") == "tplink"
    assert brand_for_catalog_vendor("Android") is None


def test_empty_catalog_reports_not_downloaded(patched_db, db_path):
    _device(db_path, "B0:C5:54:00:00:01", "10.0.0.60", vendor="TP-Link")
    with models.get_conn(db_path) as conn:
        result = check_household(conn)
    assert result["status"] == "catalog_empty"
    assert result["catalog_size"] == 0 and result["devices"] == []
    assert "hasn't been downloaded" in result["message"]


def _store_kev(db_path, *entries):
    with models.get_conn(db_path) as conn:
        for cve, vendor, product, added in entries:
            conn.execute(
                """INSERT INTO cisa_kev (cve_id, vendor_project, product, vulnerability_name,
                       date_added, ransomware_use, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'Unknown', '2026-10-01T00:00:00+00:00')""",
                (cve, vendor, product, f"{vendor} {product} issue", added),
            )


def test_vulnerability_check_matches_brand_cautiously(insights_client, patched_db, db_path):
    router = _device(db_path, "B0:C5:54:00:00:02", "10.0.0.61", vendor="TP-LINK TECHNOLOGIES CO.,LTD.")
    plug = _device(db_path, "24:0A:C4:00:00:03", "10.0.0.62", vendor="Espressif Inc.")
    nas = _device(db_path, "00:11:32:00:00:04", "10.0.0.63", vendor="Synology Incorporated")
    _store_kev(
        db_path,
        ("CVE-2000-0001", "TP-Link", "Old Router", "2024-01-01"),
        ("CVE-2000-0002", "TP-Link", "New Router", "2025-01-01"),
        ("CVE-2000-0003", "Espressif", "Chip", "2025-01-01"),
    )
    body = insights_client.get("/vulnerabilities").json()
    assert body["status"] == "ok" and body["catalog_size"] == 3 and not body["catalog_is_sample"]
    by_id = {item["device_id"]: item for item in body["devices"]}
    assert by_id[router]["kev_count"] == 2 and by_id[router]["status"] == "catalog_matches"
    assert by_id[router]["recent"][0]["cve_id"] == "CVE-2000-0002"
    assert "products from TP-Link" in by_id[router]["advice"]
    assert "doesn't mean this device is affected" in by_id[router]["advice"]
    assert by_id[plug]["status"] == "chip_maker" and by_id[plug]["kev_count"] == 0
    assert by_id[nas]["status"] == "no_known"
    single = insights_client.get(f"/devices/{router}/vulnerabilities").json()
    assert single["device"]["kev_count"] == 2
    assert insights_client.get("/devices/9999/vulnerabilities").status_code == 404


# --- demo seeding ------------------------------------------------------------


def test_household_demo_404_when_disabled(insights_client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", False)
    assert insights_client.post("/demo/household-activity", headers=auth_headers).status_code == 404


def test_household_demo_requires_token(insights_client, monkeypatch):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    assert insights_client.post("/demo/household-activity").status_code == 401


def test_household_demo_seeds_all_three_features_idempotently(
    insights_client, auth_headers, monkeypatch, patched_db, db_path
):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    existing = _device(db_path, "50:C7:BF:00:00:09", "192.168.4.1", vendor="TP-Link", hostname="Router")
    with models.get_conn(db_path) as conn:
        conn.execute("UPDATE devices SET device_type = 'router' WHERE id = ?", (existing,))
    first = insights_client.post("/demo/household-activity", headers=auth_headers).json()
    assert first["simulated"] and first["kev_sample_added"] == len(KEV_SAMPLE)
    assert first["tracker_requests"] > 0

    second = insights_client.post("/demo/household-activity", headers=auth_headers).json()
    assert second["kev_sample_added"] == 0
    with models.get_conn(db_path) as conn:
        devices = models.list_devices(conn)
        logged = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
        kev = conn.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0]
    assert len(devices) == 3
    assert logged == second["dns_queries"]
    assert kev == len(KEV_SAMPLE)
    assert {d["ip"] for d in devices if d["hostname"] != "Router"} == {"192.168.4.60", "192.168.4.61"}

    privacy = insights_client.get("/privacy/report").json()
    assert {item["name"] for item in privacy["devices"]} == {"Living room TV", "Kids' tablet"}
    vulns = insights_client.get("/vulnerabilities").json()
    assert vulns["catalog_is_sample"] is True
    router = next(item for item in vulns["devices"] if item["name"] == "Router")
    assert router["kev_count"] == 2
    assert router["advice"].startswith("A sample of CISA's catalog lists 2")
    tv = next(item for item in vulns["devices"] if item["name"] == "Living room TV")
    assert tv["status"] == "not_in_sample" and "doesn't cover Samsung" in tv["advice"]
    bedtime = insights_client.get("/bedtime").json()
    assert [item["name"] for item in bedtime["devices"]] == ["Kids' tablet"]


def test_household_demo_keeps_real_catalog(insights_client, auth_headers, monkeypatch, patched_db, db_path):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    _store_kev(db_path, ("CVE-2000-0009", "NETGEAR", "Router", "2025-01-01"))
    body = insights_client.post("/demo/household-activity", headers=auth_headers).json()
    assert body["kev_sample_added"] == 0
    with models.get_conn(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0] == 1


def test_new_read_paths_require_token_for_remote_clients():
    from backend.security import authorization_decision

    for path in ("/bedtime", "/privacy/report", "/vulnerabilities", "/devices/1/privacy"):
        assert authorization_decision(path, local=False, token_valid=False) == (False, 401)
        assert authorization_decision(path, local=True, token_valid=False) == (True, 200)


def test_clock_validation_and_invalid_schedule_is_reported_not_hidden():
    from backend.dns.policy import is_valid_clock

    assert is_valid_clock("21:00") and is_valid_clock("07:30:00")
    assert not is_valid_clock("25:99") and not is_valid_clock("") and not is_valid_clock(None)
    policy = {"internet_enabled": True, "block_start": "25:99", "block_end": "07:00"}
    assert not evaluate_policy(policy, "example.com", datetime(2026, 1, 1, 23)).blocked
    entry = device_bedtime(policy, {"id": 1, "hostname": "tablet"}, datetime(2026, 1, 1, 23, tzinfo=LA))
    assert entry["schedule_valid"] is False and entry["next_change_at"] is None
    assert "aren't valid" in entry["summary"]


def test_timezone_resolution_order(monkeypatch):
    from backend.dns.policy import household_now, timezone_for

    monkeypatch.delenv("HOMERADAR_TIMEZONE", raising=False)
    monkeypatch.setenv("TZ", "America/Denver")
    assert timezone_for(None)[1:] == ("America/Denver", "environment")
    monkeypatch.setenv("HOMERADAR_TIMEZONE", "America/Chicago")
    assert timezone_for(None)[1] == "America/Chicago"
    assert timezone_for("America/Los_Angeles")[1:] == ("America/Los_Angeles", "household")
    assert timezone_for("Not/AZone")[1] == "America/Chicago"
    assert household_now("America/Los_Angeles").tzinfo == LA
    monkeypatch.delenv("HOMERADAR_TIMEZONE")
    monkeypatch.setenv("TZ", ":/etc/localtime")
    assert timezone_for(None)[2] == "system"


def test_household_demo_adds_router_to_empty_inventory(insights_client, auth_headers, monkeypatch, patched_db):
    monkeypatch.setattr(config, "DEMO_MODE_ENABLED", True)
    body = insights_client.post("/demo/household-activity", headers=auth_headers).json()
    assert [item["name"] for item in body["devices"]] == ["Living room TV", "Kids' tablet", "Wi-Fi router"]
    vulns = insights_client.get("/vulnerabilities").json()
    router = next(item for item in vulns["devices"] if item["name"] == "Wi-Fi router")
    assert router["brand"] == "NETGEAR" and router["kev_count"] == 2
    assert router["recent"][0]["cve_id"] == "CVE-2017-5521"
