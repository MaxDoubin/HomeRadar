import Foundation

/// Async/await REST client for the HomeRadar appliance API.
///
/// The appliance runs plain `http://` with no TLS today, so this client
/// never assumes or upgrades to `https://` -- if the caller's stored
/// address string has no scheme, `http://` is prepended; if it already has
/// one, it's left alone.
///
/// Every request is built through `attachAuth(_:)`, the single choke point
/// that sets the `X-HomeRadar-Token` header. No call site should set that
/// header ad hoc.
final class HomeRadarClient {
    enum ClientError: Error, LocalizedError {
        case invalidAddress
        case invalidResponse
        case http(status: Int, body: String?)

        var errorDescription: String? {
            switch self {
            case .invalidAddress:
                return "The appliance address isn't valid."
            case .invalidResponse:
                return "The appliance sent an unexpected response."
            case .http(let status, let body):
                return "HomeRadar returned HTTP \(status)." + (body.map { " \($0)" } ?? "")
            }
        }
    }

    private let session: URLSession
    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    /// The appliance address as the user entered/discovered it (e.g.
    /// `"homeradar.local:8000"` or a raw LAN IP:port). Mutated in place by
    /// `AppSession` when the user (re)connects.
    var baseAddress: String

    /// The current pairing token, if any. Mutated in place by `AppSession`.
    var token: String?

    init(session: URLSession = .shared, baseAddress: String = "", token: String? = nil) {
        self.session = session
        self.baseAddress = baseAddress
        self.token = token
    }

    // MARK: - Request building

    private func resolvedBaseURL() throws -> URL {
        let trimmed = baseAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ClientError.invalidAddress }
        let withScheme = trimmed.lowercased().hasPrefix("http://") || trimmed.lowercased().hasPrefix("https://")
            ? trimmed
            : "http://\(trimmed)"
        guard let url = URL(string: withScheme) else { throw ClientError.invalidAddress }
        return url
    }

    private func makeRequest(
        path: String,
        method: String = "GET",
        body: Data? = nil,
        query: [URLQueryItem]? = nil
    ) throws -> URLRequest {
        let base = try resolvedBaseURL().appendingPathComponent(path)
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false) else {
            throw ClientError.invalidAddress
        }
        if let query, !query.isEmpty {
            components.queryItems = query
        }
        guard let url = components.url else { throw ClientError.invalidAddress }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body {
            request.httpBody = body
        }
        attachAuth(&request)
        return request
    }

    /// The single choke point that attaches the pairing token to a request.
    /// Harmless to call even against endpoints that don't require auth.
    func attachAuth(_ request: inout URLRequest) {
        if let token, !token.isEmpty {
            request.setValue(token, forHTTPHeaderField: AuthToken.headerName)
        }
    }

    /// Builds the `ws://` (or `wss://` if the stored address explicitly
    /// used `https://`) URL for the dashboard websocket, including the
    /// pairing token as a `?token=` query item when one is set.
    func webSocketURL() throws -> URL {
        let http = try resolvedBaseURL()
        guard var components = URLComponents(url: http, resolvingAgainstBaseURL: false) else {
            throw ClientError.invalidAddress
        }
        components.scheme = (components.scheme?.lowercased() == "https") ? "wss" : "ws"
        components.path = components.path + "/ws"
        if let token, !token.isEmpty {
            components.queryItems = [URLQueryItem(name: "token", value: token)]
        }
        guard let url = components.url else { throw ClientError.invalidAddress }
        return url
    }

    // MARK: - Sending

    private func perform(_ request: URLRequest) async throws -> Data {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ClientError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw ClientError.http(status: http.statusCode, body: String(data: data, encoding: .utf8))
        }
        return data
    }

    private func perform<T: Decodable>(_ request: URLRequest, decoding type: T.Type) async throws -> T {
        let data = try await perform(request)
        return try Self.decoder.decode(T.self, from: data)
    }

    // MARK: - Pairing

    func pairStart() async throws -> PairStartResult {
        try await perform(makeRequest(path: "/pair/start", method: "POST"), decoding: PairStartResult.self)
    }

    func pairClaim(code: String) async throws -> PairClaimResult {
        let body = try Self.encoder.encode(PairClaimRequest(code: code))
        let request = try makeRequest(path: "/pair/claim", method: "POST", body: body)
        return try await perform(request, decoding: PairClaimResult.self)
    }

    // MARK: - Status / dashboard

    func status() async throws -> Status {
        try await perform(makeRequest(path: "/status"), decoding: Status.self)
    }

    func dashboard() async throws -> Dashboard {
        try await perform(makeRequest(path: "/dashboard"), decoding: Dashboard.self)
    }

    // MARK: - Devices

    func devices() async throws -> [Device] {
        try await perform(makeRequest(path: "/devices"), decoding: [Device].self)
    }

    func updateDeviceAuthorization(id: Int, state: Int) async throws -> Device {
        let body = try Self.encoder.encode(DeviceAuthorizationRequest(state: state))
        let request = try makeRequest(path: "/devices/\(id)/authorization", method: "PATCH", body: body)
        return try await perform(request, decoding: Device.self)
    }

    /// Triggers a manual device scan. Response shape is unused this pass --
    /// fire-and-refresh (the next websocket snapshot will reflect any
    /// newly-discovered devices) is enough.
    func triggerScan() async throws {
        _ = try await perform(makeRequest(path: "/scan", method: "POST"))
    }

    // MARK: - Alerts

    func alerts(unresolvedOnly: Bool) async throws -> [Alert] {
        let query = [URLQueryItem(name: "unresolved_only", value: unresolvedOnly ? "true" : "false")]
        let request = try makeRequest(path: "/alerts", query: query)
        return try await perform(request, decoding: [Alert].self)
    }

    func resolveAlert(id: Int, resolved: Bool) async throws -> AlertResolveResult {
        let body = try Self.encoder.encode(AlertResolveRequest(resolved: resolved))
        let request = try makeRequest(path: "/alerts/\(id)", method: "PATCH", body: body)
        return try await perform(request, decoding: AlertResolveResult.self)
    }

    // MARK: - Settings

    func settings() async throws -> Settings {
        try await perform(makeRequest(path: "/settings"), decoding: Settings.self)
    }

    func updateSettings(_ update: SettingsUpdateRequest) async throws -> Settings {
        let body = try Self.encoder.encode(update)
        let request = try makeRequest(path: "/settings", method: "PATCH", body: body)
        return try await perform(request, decoding: Settings.self)
    }

    // MARK: - Health

    func health() async throws -> Health {
        try await perform(makeRequest(path: "/health"), decoding: Health.self)
    }
}
