import Combine
import Foundation
import SwiftUI

@main
struct HomeRadarApp: App {
    @StateObject private var session = AppSession()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(session)
        }
    }
}

// MARK: - DashboardState

/// The live, websocket-driven state Overview/Devices/Alerts all render off
/// of. Replaced wholesale on every snapshot push -- there is no incremental
/// merge, since the server always sends a full snapshot.
struct DashboardState: Equatable {
    var deviceCount: Int
    var openAlertCount: Int
    var securityScore: Int
    var devices: [Device]
    var alerts: [Alert]

    static let empty = DashboardState(
        deviceCount: 0,
        openAlertCount: 0,
        securityScore: 0,
        devices: [],
        alerts: []
    )
}

// MARK: - AppSession

/// The single shared app-wide session: owns the appliance connection (via
/// `ConnectionStore`), the REST client, the dashboard websocket, and the
/// latest live `DashboardState`. Every screen's ViewModel reads from this
/// instance rather than opening its own connection.
@MainActor
final class AppSession: ObservableObject {
    @Published private(set) var isConnected: Bool
    @Published private(set) var dashboardState: DashboardState = .empty
    @Published private(set) var socketState: DashboardSocketState = .disconnected

    let connectionStore: ConnectionStore
    let client: HomeRadarClient
    let socket: DashboardSocket
    let notifier = LocalAlertNotifier()

    init(connectionStore: ConnectionStore = ConnectionStore()) {
        self.connectionStore = connectionStore

        let client = HomeRadarClient(baseAddress: connectionStore.address ?? "", token: connectionStore.token)
        self.client = client
        self.socket = DashboardSocket(client: client)
        self.isConnected = connectionStore.hasCredentials

        socket.onSnapshot = { [weak self] snapshot in
            guard let self else { return }
            Task { @MainActor in
                self.apply(snapshot: snapshot)
            }
        }
        socket.onStateChange = { [weak self] state in
            guard let self else { return }
            Task { @MainActor in
                self.socketState = state
            }
        }
    }

    private func apply(snapshot: SnapshotMessage) {
        dashboardState = DashboardState(
            deviceCount: snapshot.status.deviceCount,
            openAlertCount: snapshot.status.openAlertCount,
            securityScore: snapshot.status.securityScore,
            devices: snapshot.devices,
            alerts: snapshot.alerts
        )
        notifier.processIncoming(alerts: snapshot.alerts)
    }

    /// Called after a successful `POST /pair/claim` to persist the new
    /// connection and point the shared client/socket at it.
    func completeConnection(address: String, token: String) {
        connectionStore.save(address: address, token: token)
        client.baseAddress = address
        client.token = token
        isConnected = true
    }

    /// Forgets the saved appliance connection entirely (Settings ->
    /// "Forget This Appliance"), dropping back to the Connect flow.
    func disconnect() {
        socket.stop()
        connectionStore.clear()
        client.baseAddress = ""
        client.token = nil
        dashboardState = .empty
        socketState = .disconnected
        isConnected = false
    }

    /// Opens the shared dashboard websocket. Call when the tabbed root
    /// appears or the app returns to the foreground. No-op if not
    /// connected or already running.
    func startLiveUpdates() {
        guard isConnected else { return }
        socket.start()
    }

    /// Closes the shared dashboard websocket. Call when the app
    /// backgrounds.
    func stopLiveUpdates() {
        socket.stop()
    }
}
