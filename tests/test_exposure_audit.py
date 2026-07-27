from backend.monitor.exposure_audit import assess_device


def test_exposure_audit_reports_evidence_without_claiming_vulnerability():
    findings = assess_device(
        {
            "open_ports": [23, 445],
            "device_type": "computer",
            "fingerprint_confidence": 0.9,
            "is_authorized": 1,
        }
    )
    by_key = {finding.key: finding for finding in findings}
    assert by_key["port-telnet"].severity == "critical"
    assert by_key["port-telnet"].evidence == ["TCP port 23 accepted a connection"]
    assert "CVE" not in by_key["port-telnet"].description


def test_unknown_pending_device_gets_review_findings():
    findings = assess_device(
        {
            "open_ports": [],
            "device_type": "unknown",
            "fingerprint_confidence": 0.0,
            "is_authorized": 0,
        }
    )
    assert {finding.key for finding in findings} == {
        "unknown-device",
        "pending-authorization",
    }
