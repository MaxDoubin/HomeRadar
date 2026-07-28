import XCTest
@testable import HomeRadar

/// NOTE: these tests were written by careful inspection of the Codable
/// types in `APIModels.swift` against the documented backend contract.
/// They have NOT been compiled or run -- there is no Swift toolchain in the
/// environment that authored them. An engineer must run this suite in
/// Xcode before trusting it.
final class APIModelsDecodingTests: XCTestCase {
    private let decoder = JSONDecoder()

    // MARK: - Device

    func testDeviceDecodesFullFixtureAndIgnoresUnrecognizedFingerprintKey() throws {
        let json = """
        {
          "id": 1,
          "mac": "AA:BB:CC:DD:EE:FF",
          "ip": "192.168.1.42",
          "hostname": "kitchen-cam",
          "vendor": "Acme",
          "model": "Cam 2",
          "device_type": "camera",
          "fingerprint_confidence": 0.87,
          "open_ports": [80, 554],
          "services": ["rtsp", "http"],
          "discovery_sources": ["arp", "mdns"],
          "trust_score": 62,
          "is_authorized": 1,
          "first_seen": "2026-07-01T09:00:00.000000+00:00",
          "last_seen": "2026-07-28T12:34:56.789012+00:00",
          "fingerprint": {"os": "linux", "confidence": 0.9, "nested": {"a": 1}}
        }
        """.data(using: .utf8)!

        // This is the key assertion for the "unrecognized key" requirement:
        // decoding must NOT throw even though `fingerprint` (an entire
        // nested object) isn't modeled on `Device` at all. This documents
        // Codable's default unknown-key-tolerant behavior for this type.
        let device = try decoder.decode(Device.self, from: json)

        XCTAssertEqual(device.id, 1)
        XCTAssertEqual(device.mac, "AA:BB:CC:DD:EE:FF")
        XCTAssertEqual(device.ip, "192.168.1.42")
        XCTAssertEqual(device.hostname, "kitchen-cam")
        XCTAssertEqual(device.vendor, "Acme")
        XCTAssertEqual(device.model, "Cam 2")
        XCTAssertEqual(device.deviceType, "camera")
        XCTAssertEqual(device.fingerprintConfidence, 0.87, accuracy: 0.0001)
        XCTAssertEqual(device.openPorts, [80, 554])
        XCTAssertEqual(device.services, ["rtsp", "http"])
        XCTAssertEqual(device.discoverySources, ["arp", "mdns"])
        XCTAssertEqual(device.trustScore, 62)
        XCTAssertEqual(device.isAuthorized, 1)
        XCTAssertEqual(device.firstSeen, "2026-07-01T09:00:00.000000+00:00")
        XCTAssertEqual(device.lastSeen, "2026-07-28T12:34:56.789012+00:00")
    }

    func testDeviceDecodesWithNullOptionalFields() throws {
        let json = """
        {
          "id": 2,
          "mac": "11:22:33:44:55:66",
          "ip": null,
          "hostname": null,
          "vendor": null,
          "model": null,
          "device_type": "unknown",
          "fingerprint_confidence": 0.0,
          "open_ports": [],
          "services": [],
          "discovery_sources": [],
          "trust_score": 10,
          "is_authorized": 0,
          "first_seen": "2026-07-01T09:00:00.000000+00:00",
          "last_seen": "2026-07-01T09:00:00.000000+00:00"
        }
        """.data(using: .utf8)!

        let device = try decoder.decode(Device.self, from: json)
        XCTAssertNil(device.ip)
        XCTAssertNil(device.hostname)
        XCTAssertNil(device.vendor)
        XCTAssertNil(device.model)
    }

    // MARK: - Date parsing (fractional seconds + `+00:00` offset)

    func testHomeRadarDateParsingHandlesFractionalSecondsWithOffset() {
        let raw = "2026-07-28T12:34:56.789012+00:00"
        let date = HomeRadarDateParsing.parse(raw)
        XCTAssertNotNil(date, "fractional-second, +00:00-offset timestamps must parse")
    }

    func testHomeRadarDateParsingFallsBackGracefullyOnUnparsableInput() {
        XCTAssertNil(HomeRadarDateParsing.parse("not-a-date"))
        XCTAssertNil(HomeRadarDateParsing.parse(""))
    }

    func testDeviceLastSeenDateComputedPropertyMirrorsDateParsing() throws {
        let json = """
        {
          "id": 3, "mac": "AA:AA:AA:AA:AA:AA", "ip": null, "hostname": null,
          "vendor": null, "model": null, "device_type": "unknown",
          "fingerprint_confidence": 0, "open_ports": [], "services": [],
          "discovery_sources": [], "trust_score": 0, "is_authorized": 0,
          "first_seen": "2026-07-28T12:34:56.789012+00:00",
          "last_seen": "garbage-timestamp"
        }
        """.data(using: .utf8)!

        let device = try decoder.decode(Device.self, from: json)
        XCTAssertNotNil(device.firstSeenDate)
        XCTAssertNil(device.lastSeenDate, "an unparsable timestamp must fall back to nil, never crash")
    }

    // MARK: - Alert: is_resolved int vs. AlertResolveResult: is_resolved bool

    func testAlertDecodesIsResolvedAsRawIntNotBool() throws {
        let json = """
        {
          "id": 7,
          "device_id": 1,
          "severity": "high",
          "title": "New open port detected",
          "description": "Port 23 opened on kitchen-cam",
          "is_resolved": 0,
          "created_at": "2026-07-28T08:00:00.123456+00:00"
        }
        """.data(using: .utf8)!

        let alert = try decoder.decode(Alert.self, from: json)
        XCTAssertEqual(alert.id, 7)
        XCTAssertEqual(alert.deviceId, 1)
        XCTAssertEqual(alert.severity, "high")
        XCTAssertEqual(alert.isResolved, 0, "Alert.isResolved must decode as Int, matching every raw-SQLite-row response path")
    }

    func testAlertWithNullDeviceIdAndDescriptionDecodes() throws {
        let json = """
        {
          "id": 8, "device_id": null, "severity": "low", "title": "Info",
          "description": null, "is_resolved": 1,
          "created_at": "2026-07-28T08:00:00.000000+00:00"
        }
        """.data(using: .utf8)!

        let alert = try decoder.decode(Alert.self, from: json)
        XCTAssertNil(alert.deviceId)
        XCTAssertNil(alert.description)
        XCTAssertEqual(alert.isResolved, 1)
    }

    func testAlertResolveResultDecodesIsResolvedAsGenuineBool() throws {
        let json = #"{ "id": 7, "is_resolved": true }"#.data(using: .utf8)!

        let result = try decoder.decode(AlertResolveResult.self, from: json)
        XCTAssertEqual(result.id, 7)
        XCTAssertTrue(result.isResolved, "AlertResolveResult.isResolved must decode as Bool -- the one Pydantic-backed response shape")
    }

    func testAlertResolveResultRejectsIntBodyToDocumentTheSplitIsIntentional() {
        // If the backend ever regressed and started sending an int here too,
        // this decode would throw a typeMismatch -- which is exactly the
        // failure this two-type split is designed to surface loudly instead
        // of silently misinterpreting 0/1 as false/true (they happen to
        // line up for 0/1, but this documents that Alert vs.
        // AlertResolveResult are NOT interchangeable, by design).
        let json = #"{ "id": 7, "is_resolved": 1 }"#.data(using: .utf8)!
        XCTAssertThrowsError(try decoder.decode(AlertResolveResult.self, from: json))
    }

    // MARK: - Dashboard: ignores traffic/inventory

    func testDashboardDecodesIgnoringUnknownTrafficAndInventoryKeys() throws {
        let json = """
        {
          "status": {
            "device_count": 3,
            "open_alert_count": 1,
            "security_score": 88,
            "dns_enabled": true,
            "blocklist_domains": 120
          },
          "devices": [],
          "alerts": [],
          "traffic": {"bytes_in": 123456, "bytes_out": 7890},
          "inventory": {"unknown_devices": 0}
        }
        """.data(using: .utf8)!

        let dashboard = try decoder.decode(Dashboard.self, from: json)
        XCTAssertEqual(dashboard.status.deviceCount, 3)
        XCTAssertEqual(dashboard.status.dnsEnabled, true)
        XCTAssertEqual(dashboard.status.blocklistDomains, 120)
        XCTAssertTrue(dashboard.devices.isEmpty)
        XCTAssertTrue(dashboard.alerts.isEmpty)
    }

    // MARK: - Websocket snapshot: smaller inline status shape

    func testSnapshotMessageDecodesSmallerInlineStatusShape() throws {
        let json = """
        {
          "type": "snapshot",
          "status": {"device_count": 4, "open_alert_count": 2, "security_score": 91},
          "devices": [],
          "alerts": []
        }
        """.data(using: .utf8)!

        let snapshot = try decoder.decode(SnapshotMessage.self, from: json)
        XCTAssertEqual(snapshot.type, "snapshot")
        XCTAssertEqual(snapshot.status.deviceCount, 4)
        XCTAssertEqual(snapshot.status.openAlertCount, 2)
        XCTAssertEqual(snapshot.status.securityScore, 91)
    }

    func testSnapshotStatusRejectsExtraDnsFieldsAsProofItsASmallerDistinctType() {
        // SnapshotStatus intentionally has no dns_enabled/blocklist_domains
        // properties. Extra keys are still fine to decode (Codable ignores
        // them) -- this test documents that behavior explicitly rather than
        // asserting a throw, since the whole point of a *smaller* struct is
        // that it tolerates -- rather than requires -- the REST Status's
        // extra fields being present or absent.
        let json = """
        {"device_count": 1, "open_alert_count": 0, "security_score": 100, "dns_enabled": true, "blocklist_domains": 5}
        """.data(using: .utf8)!

        XCTAssertNoThrow(try decoder.decode(SnapshotStatus.self, from: json))
    }

    // MARK: - Settings

    func testSettingsDecodesAllFields() throws {
        let json = """
        {
          "household_name": "The Smiths",
          "digest_email": "kristina@example.com",
          "dns_upstream": "1.1.1.1",
          "notifications_enabled": true,
          "dns_enabled": false,
          "setup_complete": true
        }
        """.data(using: .utf8)!

        let settings = try decoder.decode(Settings.self, from: json)
        XCTAssertEqual(settings.householdName, "The Smiths")
        XCTAssertEqual(settings.digestEmail, "kristina@example.com")
        XCTAssertEqual(settings.dnsUpstream, "1.1.1.1")
        XCTAssertTrue(settings.notificationsEnabled)
        XCTAssertFalse(settings.dnsEnabled)
        XCTAssertTrue(settings.setupComplete)
    }

    // MARK: - Pairing

    func testPairStartResultDecodes() throws {
        let json = #"{"code": "123456", "expires_in": 600}"#.data(using: .utf8)!
        let result = try decoder.decode(PairStartResult.self, from: json)
        XCTAssertEqual(result.code, "123456")
        XCTAssertEqual(result.expiresIn, 600)
    }

    func testPairClaimResultDecodes() throws {
        let json = #"{"token": "opaque-string"}"#.data(using: .utf8)!
        let result = try decoder.decode(PairClaimResult.self, from: json)
        XCTAssertEqual(result.token, "opaque-string")
    }

    // MARK: - Health (loosely modeled)

    func testHealthDecodesLeniently() throws {
        let json = """
        {"status": "ok", "uptime_seconds": 12345.6, "version": "1.2.3", "some_other_field": {"nested": true}}
        """.data(using: .utf8)!
        let health = try decoder.decode(Health.self, from: json)
        XCTAssertEqual(health.status, "ok")
        XCTAssertEqual(health.uptimeSeconds ?? 0, 12345.6, accuracy: 0.01)
        XCTAssertEqual(health.version, "1.2.3")
    }

    func testHealthDecodesEvenWhenAllModeledFieldsAreMissing() throws {
        let json = #"{"totally_unrelated": 1}"#.data(using: .utf8)!
        let health = try decoder.decode(Health.self, from: json)
        XCTAssertNil(health.status)
        XCTAssertNil(health.uptimeSeconds)
        XCTAssertNil(health.version)
    }
}
