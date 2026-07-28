import Foundation
import Network

/// A candidate HomeRadar appliance discovered via Bonjour.
struct DiscoveredAppliance: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let host: String
    let port: Int

    var addressString: String { "\(host):\(port)" }
}

/// Browses Bonjour `_http._tcp` services on the local network and surfaces
/// any whose advertised service name looks like a HomeRadar appliance.
///
/// This is a best-effort convenience for Connect step 1 -- manual address
/// entry always remains available, since not every network/appliance
/// configuration advertises Bonjour, and some households may pair over a
/// plain LAN IP that never appears here at all.
///
/// Requires `NSLocalNetworkUsageDescription` and an `NSBonjourServices`
/// entry for `_http._tcp` in Info.plist (iOS's Local Network privacy prompt).
@MainActor
final class ApplianceDiscovery: ObservableObject {
    @Published private(set) var discovered: [DiscoveredAppliance] = []
    @Published private(set) var isBrowsing: Bool = false

    private var browser: NWBrowser?
    private var resolvers: [NWConnection] = []

    func start() {
        stop()
        isBrowsing = true
        discovered = []

        let parameters = NWParameters()
        parameters.includePeerToPeer = true

        let browser = NWBrowser(for: .bonjour(type: "_http._tcp", domain: nil), using: parameters)
        self.browser = browser

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                for result in results {
                    self.resolveIfLikelyHomeRadar(result)
                }
            }
        }
        browser.stateUpdateHandler = { [weak self] state in
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch state {
                case .failed, .cancelled:
                    self.isBrowsing = false
                default:
                    break
                }
            }
        }
        browser.start(queue: .main)
    }

    func stop() {
        browser?.cancel()
        browser = nil
        isBrowsing = false
        for connection in resolvers {
            connection.cancel()
        }
        resolvers.removeAll()
    }

    /// Filters to services whose advertised name looks like a HomeRadar
    /// appliance, then resolves a host:port for display/selection. `NWBrowser`
    /// results carry an unresolved Bonjour endpoint, not a host/port directly,
    /// so a short-lived `NWConnection` is used to resolve one.
    private func resolveIfLikelyHomeRadar(_ result: NWBrowser.Result) {
        guard case let .service(name, _, _, _) = result.endpoint else { return }
        guard name.lowercased().contains("homeradar") else { return }

        let connection = NWConnection(to: result.endpoint, using: .tcp)
        resolvers.append(connection)

        connection.stateUpdateHandler = { [weak self, weak connection] state in
            Task { @MainActor [weak self, weak connection] in
                guard let self else { return }
                switch state {
                case .ready:
                    if let remote = connection?.currentPath?.remoteEndpoint,
                       case let .hostPort(host, port) = remote {
                        let candidate = DiscoveredAppliance(
                            name: name,
                            host: Self.hostString(from: host),
                            port: Int(port.rawValue)
                        )
                        if !self.discovered.contains(where: {
                            $0.host == candidate.host && $0.port == candidate.port
                        }) {
                            self.discovered.append(candidate)
                        }
                    }
                    connection?.cancel()
                    if let connection {
                        self.resolvers.removeAll { $0 === connection }
                    }
                case .failed, .cancelled:
                    connection?.cancel()
                    if let connection {
                        self.resolvers.removeAll { $0 === connection }
                    }
                default:
                    break
                }
            }
        }
        connection.start(queue: .main)
    }

    nonisolated private static func hostString(from host: NWEndpoint.Host) -> String {
        switch host {
        case .name(let name, _):
            return name
        case .ipv4(let address):
            return "\(address)"
        case .ipv6(let address):
            return "\(address)"
        @unknown default:
            return "\(host)"
        }
    }
}
