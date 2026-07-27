from backend.monitor.cisa_kev import parse_catalog


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
