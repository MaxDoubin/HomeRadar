import Foundation

// MARK: - Date parsing

/// Backend timestamps are ISO-8601 with fractional seconds and a `+00:00`
/// offset, e.g. `"2026-07-28T12:34:56.789012+00:00"` -- NOT a `Z` suffix. A
/// plain `ISO8601DateFormatter()` (default options) fails to parse the
/// fractional-second component and returns `nil`. Every call site that
/// needs a `Date` from a raw timestamp string should go through
/// `HomeRadarDateParsing.parse(_:)` rather than constructing its own
/// formatter, and must treat a `nil` result as "unparsable" -- display
/// "unknown" (or the raw string) instead of force-unwrapping.
enum HomeRadarDateParsing {
    private static let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    /// Fallback formatter for timestamps that arrive without a fractional
    /// seconds component (defensive -- the documented contract always
    /// includes fractional seconds, but this keeps a same-shaped string
    /// missing microseconds from crashing/failing to display entirely).
    private static let wholeSecondFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    static func parse(_ raw: String) -> Date? {
        formatter.date(from: raw) ?? wholeSecondFormatter.date(from: raw)
    }
}

// MARK: - GET /status

struct Status: Codable, Equatable {
    let deviceCount: Int
    let openAlertCount: Int
    let securityScore: Int
    let dnsEnabled: Bool
    let blocklistDomains: Int

    enum CodingKeys: String, CodingKey {
        case deviceCount = "device_count"
        case openAlertCount = "open_alert_count"
        case securityScore = "security_score"
        case dnsEnabled = "dns_enabled"
        case blocklistDomains = "blocklist_domains"
    }
}

// MARK: - Device

/// A device row as returned by `GET /devices` and embedded in
/// `GET /dashboard` and the websocket snapshot push.
///
/// Deliberately omits `fingerprint`: present in the real JSON, unused by any
/// screen this pass. `Codable`'s default decoding behavior ignores
/// unrecognized JSON keys, so no special configuration is needed (unlike
/// e.g. kotlinx.serialization, which requires `ignoreUnknownKeys = true`).
struct Device: Codable, Identifiable, Equatable {
    let id: Int
    let mac: String
    let ip: String?
    let hostname: String?
    let vendor: String?
    let model: String?
    let deviceType: String
    let fingerprintConfidence: Double
    let openPorts: [Int]
    let services: [String]
    let discoverySources: [String]
    let trustScore: Int
    let isAuthorized: Int
    let firstSeen: String
    let lastSeen: String

    enum CodingKeys: String, CodingKey {
        case id, mac, ip, hostname, vendor, model
        case deviceType = "device_type"
        case fingerprintConfidence = "fingerprint_confidence"
        case openPorts = "open_ports"
        case services
        case discoverySources = "discovery_sources"
        case trustScore = "trust_score"
        case isAuthorized = "is_authorized"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
    }

    var firstSeenDate: Date? { HomeRadarDateParsing.parse(firstSeen) }
    var lastSeenDate: Date? { HomeRadarDateParsing.parse(lastSeen) }
}

/// Device authorization states, mirroring the backend's `is_authorized` int
/// column (0 = pending, 1 = authorized, 2 = blocked).
enum DeviceAuthorizationState: Int {
    case pending = 0
    case authorized = 1
    case blocked = 2
}

// MARK: - Alert

/// An alert row as returned by `GET /alerts`, `GET /dashboard`, and the
/// websocket snapshot. On every one of those paths the backend serializes
/// straight from a SQLite row with no Pydantic model in between, so
/// `is_resolved` arrives as a raw JSON int (`0`/`1`) -- NOT a boolean.
///
/// Do NOT reuse this type for the `PATCH /alerts/{id}` response: that one
/// endpoint goes through a real Pydantic model and returns `is_resolved` as
/// a genuine JSON boolean. Use `AlertResolveResult` for that response.
struct Alert: Codable, Identifiable, Equatable {
    let id: Int
    let deviceId: Int?
    let severity: String
    let title: String
    let description: String?
    let isResolved: Int
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case deviceId = "device_id"
        case severity, title, description
        case isResolved = "is_resolved"
        case createdAt = "created_at"
    }

    var createdAtDate: Date? { HomeRadarDateParsing.parse(createdAt) }
}

/// The response body of `PATCH /alerts/{id}`, which -- unlike every other
/// alert response in this API -- goes through a real Pydantic model and
/// therefore serializes `is_resolved` as a genuine JSON boolean, not an int.
struct AlertResolveResult: Codable, Equatable {
    let id: Int
    let isResolved: Bool

    enum CodingKeys: String, CodingKey {
        case id
        case isResolved = "is_resolved"
    }
}

// MARK: - GET /dashboard

/// Omits `traffic`/`inventory`: present in the real JSON, unused this pass.
/// `Codable` simply never asks for those keys, so they're harmlessly
/// skipped during decoding.
struct Dashboard: Codable, Equatable {
    let status: Status
    let devices: [Device]
    let alerts: [Alert]
}

// MARK: - Websocket snapshot

/// The smaller status shape embedded in the websocket snapshot push. This
/// is NOT the same shape as the REST `Status` above -- it omits
/// `dns_enabled`/`blocklist_domains` -- so it gets its own type rather than
/// being conflated with `Status`.
struct SnapshotStatus: Codable, Equatable {
    let deviceCount: Int
    let openAlertCount: Int
    let securityScore: Int

    enum CodingKeys: String, CodingKey {
        case deviceCount = "device_count"
        case openAlertCount = "open_alert_count"
        case securityScore = "security_score"
    }
}

/// A full-state push frame sent over the dashboard websocket roughly every
/// 3 seconds, with no client message required to receive it.
struct SnapshotMessage: Codable, Equatable {
    let type: String
    let status: SnapshotStatus
    let devices: [Device]
    let alerts: [Alert]
}

// MARK: - GET /settings, PATCH /settings

struct Settings: Codable, Equatable {
    let householdName: String
    let digestEmail: String
    let dnsUpstream: String
    let notificationsEnabled: Bool
    let dnsEnabled: Bool
    let setupComplete: Bool

    enum CodingKeys: String, CodingKey {
        case householdName = "household_name"
        case digestEmail = "digest_email"
        case dnsUpstream = "dns_upstream"
        case notificationsEnabled = "notifications_enabled"
        case dnsEnabled = "dns_enabled"
        case setupComplete = "setup_complete"
    }
}

/// Body for `PATCH /settings`. All fields optional so only the fields the
/// user actually changed are sent -- Swift's synthesized `Encodable`
/// conformance calls `encodeIfPresent` for `Optional`-typed stored
/// properties, so a `nil` field is omitted from the JSON entirely rather
/// than encoded as `null`.
struct SettingsUpdateRequest: Encodable {
    var householdName: String?
    var digestEmail: String?
    var dnsUpstream: String?
    var notificationsEnabled: Bool?
    var dnsEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case householdName = "household_name"
        case digestEmail = "digest_email"
        case dnsUpstream = "dns_upstream"
        case notificationsEnabled = "notifications_enabled"
        case dnsEnabled = "dns_enabled"
    }
}

// MARK: - GET /health

/// `GET /health` is a loosely-structured diagnostics object. Only the
/// fields Settings actually displays are modeled here, all optional --
/// everything else in the real payload is ignored by `Codable`'s default
/// unknown-key handling, and a missing/renamed field just decodes to `nil`
/// rather than failing the whole request.
struct Health: Codable, Equatable {
    let status: String?
    let uptimeSeconds: Double?
    let version: String?

    enum CodingKeys: String, CodingKey {
        case status
        case uptimeSeconds = "uptime_seconds"
        case version
    }
}

// MARK: - Pairing

/// `POST /pair/start` response.
struct PairStartResult: Codable, Equatable {
    let code: String
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case code
        case expiresIn = "expires_in"
    }
}

/// `POST /pair/claim` request body.
struct PairClaimRequest: Encodable {
    let code: String
}

/// `POST /pair/claim` response.
struct PairClaimResult: Codable, Equatable {
    let token: String
}

// MARK: - Devices / Alerts mutation bodies

/// `PATCH /devices/{id}/authorization` request body.
struct DeviceAuthorizationRequest: Encodable {
    let state: Int
}

/// `PATCH /alerts/{id}` request body.
struct AlertResolveRequest: Encodable {
    let resolved: Bool
}
