import XCTest
@testable import HomeRadar

/// NOTE: written by careful inspection of `HomeRadarClient.swift`. NOT
/// compiled or run -- no Swift toolchain exists in the environment that
/// authored this file. An engineer must run this suite in Xcode.
///
/// Stubs the network entirely via a custom `URLProtocol` registered on an
/// ephemeral `URLSessionConfiguration` -- no real network traffic.
final class StubURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    static var lastRequest: URLRequest?
    static var lastRequestBodyData: Data?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        StubURLProtocol.lastRequest = request
        StubURLProtocol.lastRequestBodyData = request.resolvedHTTPBody()

        guard let handler = StubURLProtocol.requestHandler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private extension URLRequest {
    /// `URLProtocol`'s `request.httpBody` is sometimes nil even for
    /// requests built with an explicit `httpBody` -- URLSession may have
    /// converted it to `httpBodyStream` by the time a custom protocol sees
    /// it. Read whichever is actually present.
    func resolvedHTTPBody() -> Data? {
        if let httpBody { return httpBody }
        guard let stream = httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let bytesRead = stream.read(&buffer, maxLength: bufferSize)
            guard bytesRead > 0 else { break }
            data.append(buffer, count: bytesRead)
        }
        return data
    }
}

final class HomeRadarClientTests: XCTestCase {
    private var session: URLSession!
    private var client: HomeRadarClient!

    override func setUp() {
        super.setUp()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        session = URLSession(configuration: configuration)
        client = HomeRadarClient(session: session, baseAddress: "homeradar.local:8000", token: "secret-token")

        StubURLProtocol.requestHandler = nil
        StubURLProtocol.lastRequest = nil
        StubURLProtocol.lastRequestBodyData = nil
    }

    override func tearDown() {
        StubURLProtocol.requestHandler = nil
        StubURLProtocol.lastRequest = nil
        StubURLProtocol.lastRequestBodyData = nil
        super.tearDown()
    }

    private func stubResponse(status: Int = 200, json: String) {
        StubURLProtocol.requestHandler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, json.data(using: .utf8)!)
        }
    }

    // MARK: - Auth header

    func testStatusRequestCarriesAuthHeaderWhenTokenPresent() async throws {
        stubResponse(json: #"{"device_count":1,"open_alert_count":0,"security_score":90,"dns_enabled":true,"blocklist_domains":10}"#)

        _ = try await client.status()

        XCTAssertEqual(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: AuthToken.headerName), "secret-token")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/status")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "GET")
    }

    func testRequestOmitsAuthHeaderWhenNoTokenSet() async throws {
        client.token = nil
        stubResponse(json: #"{"device_count":1,"open_alert_count":0,"security_score":90,"dns_enabled":true,"blocklist_domains":10}"#)

        _ = try await client.status()

        XCTAssertNil(StubURLProtocol.lastRequest?.value(forHTTPHeaderField: AuthToken.headerName))
    }

    func testAddressWithoutSchemeDefaultsToPlainHTTP() async throws {
        stubResponse(json: #"{"device_count":1,"open_alert_count":0,"security_score":90,"dns_enabled":true,"blocklist_domains":10}"#)

        _ = try await client.status()

        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.scheme, "http")
    }

    // MARK: - Devices

    func testUpdateDeviceAuthorizationSendsPatchWithStateBody() async throws {
        stubResponse(json: """
        {"id":1,"mac":"AA:BB","ip":null,"hostname":null,"vendor":null,"model":null,"device_type":"unknown","fingerprint_confidence":0,"open_ports":[],"services":[],"discovery_sources":[],"trust_score":50,"is_authorized":1,"first_seen":"2026-01-01T00:00:00.000000+00:00","last_seen":"2026-01-01T00:00:00.000000+00:00"}
        """)

        let updated = try await client.updateDeviceAuthorization(id: 1, state: 1)

        XCTAssertEqual(updated.isAuthorized, 1)
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "PATCH")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/devices/1/authorization")

        let bodyData = try XCTUnwrap(StubURLProtocol.lastRequestBodyData)
        let bodyJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
        XCTAssertEqual(bodyJSON["state"] as? Int, 1)
        XCTAssertEqual(bodyJSON.count, 1, "body must contain exactly {\"state\": 1}, nothing else")
    }

    // MARK: - Alerts

    func testResolveAlertSendsPatchWithResolvedBody() async throws {
        stubResponse(json: #"{"id":9,"is_resolved":true}"#)

        let result = try await client.resolveAlert(id: 9, resolved: true)

        XCTAssertEqual(result.id, 9)
        XCTAssertTrue(result.isResolved)
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "PATCH")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/alerts/9")

        let bodyData = try XCTUnwrap(StubURLProtocol.lastRequestBodyData)
        let bodyJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
        XCTAssertEqual(bodyJSON["resolved"] as? Bool, true)
        XCTAssertEqual(bodyJSON.count, 1, "body must contain exactly {\"resolved\": true}, nothing else")
    }

    func testAlertsRequestSendsUnresolvedOnlyQueryParameter() async throws {
        stubResponse(json: "[]")

        _ = try await client.alerts(unresolvedOnly: true)

        let url = try XCTUnwrap(StubURLProtocol.lastRequest?.url)
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(components.path, "/alerts")
        XCTAssertEqual(components.queryItems, [URLQueryItem(name: "unresolved_only", value: "true")])
    }

    // MARK: - Pairing (no auth expected/required)

    func testPairClaimSendsCodeBodyAndPOSTMethod() async throws {
        stubResponse(json: #"{"token":"opaque-string"}"#)

        let result = try await client.pairClaim(code: "123456")

        XCTAssertEqual(result.token, "opaque-string")
        XCTAssertEqual(StubURLProtocol.lastRequest?.httpMethod, "POST")
        XCTAssertEqual(StubURLProtocol.lastRequest?.url?.path, "/pair/claim")

        let bodyData = try XCTUnwrap(StubURLProtocol.lastRequestBodyData)
        let bodyJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
        XCTAssertEqual(bodyJSON["code"] as? String, "123456")
    }

    // MARK: - Error surfacing

    func testNon2xxStatusThrowsHTTPError() async {
        stubResponse(status: 400, json: #"{"detail": "invalid code"}"#)

        do {
            _ = try await client.pairClaim(code: "000000")
            XCTFail("expected an error to be thrown for HTTP 400")
        } catch HomeRadarClient.ClientError.http(let status, _) {
            XCTAssertEqual(status, 400)
        } catch {
            XCTFail("expected ClientError.http, got \(error)")
        }
    }

    func testEmptyAddressThrowsInvalidAddressBeforeSendingAnyRequest() async {
        client.baseAddress = ""
        do {
            _ = try await client.status()
            XCTFail("expected an error to be thrown for an empty address")
        } catch HomeRadarClient.ClientError.invalidAddress {
            // expected
        } catch {
            XCTFail("expected ClientError.invalidAddress, got \(error)")
        }
        XCTAssertNil(StubURLProtocol.lastRequest, "no request should have been sent for an invalid address")
    }
}
