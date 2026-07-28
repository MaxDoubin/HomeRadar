from backend.db import models
from backend.monitor.cisa_kev import parse_catalog, search_catalog, update_catalog


class _FakeJSONResponse:
    """A context-manager stand-in for `http.client.HTTPResponse` yielding JSON."""

    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, amount=-1):
        import json

        return json.dumps(self._payload).encode("utf-8")


def test_parse_cisa_kev_catalog_filters_and_maps_records():
    records = parse_catalog(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1234",
                    "vendorProject": "Example",
                    "product": "Router",
                    "vulnerabilityName": "Example issue",
                    "dateAdded": "2026-07-01",
                    "dueDate": "2026-07-22",
                    "knownRansomwareCampaignUse": "Unknown",
                    "requiredAction": "Update firmware",
                },
                {"cveID": "not-a-cve"},
            ]
        }
    )
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2026-1234"
    assert records[0]["required_action"] == "Update firmware"


def test_update_catalog_inserts_records_and_is_searchable(monkeypatch, patched_db, db_path):
    payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Acme",
                "product": "Router",
                "vulnerabilityName": "Auth bypass",
                "dateAdded": "2026-07-01",
                "dueDate": "2026-07-15",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Patch firmware",
            }
        ]
    }
    monkeypatch.setattr(
        "backend.monitor.cisa_kev.urllib.request.urlopen",
        lambda request, timeout=None: _FakeJSONResponse(payload),
    )

    with models.get_conn(db_path) as conn:
        count = update_catalog(conn, url="https://kev.example/feed.json")
    assert count == 1

    with models.get_conn(db_path) as conn:
        rows = search_catalog(conn)
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2026-0001"
    assert rows[0]["vendor_project"] == "Acme"


def test_update_catalog_updates_existing_record_in_place_on_conflict(monkeypatch, patched_db, db_path):
    first_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "OldVendor",
                "product": "Camera",
                "vulnerabilityName": "Issue",
                "dateAdded": "2026-06-01",
                "dueDate": "2026-06-15",
                "knownRansomwareCampaignUse": "Unknown",
                "requiredAction": "Old action",
            }
        ]
    }
    monkeypatch.setattr(
        "backend.monitor.cisa_kev.urllib.request.urlopen",
        lambda request, timeout=None: _FakeJSONResponse(first_payload),
    )
    with models.get_conn(db_path) as conn:
        update_catalog(conn, url="https://kev.example/feed.json")

    second_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "NewVendor",
                "product": "Camera",
                "vulnerabilityName": "Issue updated",
                "dateAdded": "2026-06-01",
                "dueDate": "2026-07-01",
                "knownRansomwareCampaignUse": "Confirmed",
                "requiredAction": "New action",
            }
        ]
    }
    monkeypatch.setattr(
        "backend.monitor.cisa_kev.urllib.request.urlopen",
        lambda request, timeout=None: _FakeJSONResponse(second_payload),
    )
    with models.get_conn(db_path) as conn:
        count = update_catalog(conn, url="https://kev.example/feed.json")
    assert count == 1

    with models.get_conn(db_path) as conn:
        rows = conn.execute("SELECT * FROM cisa_kev").fetchall()
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["vendor_project"] == "NewVendor"
    assert row["vulnerability_name"] == "Issue updated"
    assert row["required_action"] == "New action"
    assert row["ransomware_use"] == "Confirmed"
    assert row["due_date"] == "2026-07-01"


def test_search_catalog_filters_by_query_and_clamps_limit(patched_db, db_path):
    with models.get_conn(db_path) as conn:
        for index in range(3):
            conn.execute(
                """INSERT INTO cisa_kev (
                       cve_id, vendor_project, product, vulnerability_name, date_added,
                       due_date, ransomware_use, required_action, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"CVE-2026-100{index}",
                    "VendorX" if index == 0 else "OtherVendor",
                    "Widget",
                    "Some issue",
                    f"2026-07-0{index + 1}",
                    None,
                    None,
                    "",
                    "2026-07-01T00:00:00Z",
                ),
            )

    with models.get_conn(db_path) as conn:
        all_rows = search_catalog(conn)
        assert len(all_rows) == 3

        filtered = search_catalog(conn, query="VendorX")
        assert len(filtered) == 1
        assert filtered[0]["cve_id"] == "CVE-2026-1000"

        no_match = search_catalog(conn, query="NoSuchVendor")
        assert no_match == []

        clamped_low = search_catalog(conn, limit=0)
        assert len(clamped_low) == 1

        clamped_high = search_catalog(conn, limit=100_000)
        assert len(clamped_high) == 3
