import Combine
import Foundation
import SwiftUI

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        application.registerForRemoteNotifications()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let tokenString = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
        Task {
            await AppSession.shared.registerAPNSToken(token: tokenString)
        }
    }
}

@main
struct HomeRadarApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @ObservedObject private var session = AppSession.shared

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
    static let shared = AppSession()

    @Published private(set) var isConnected: Bool
    @Published private(set) var dashboardState: DashboardState = .empty
    @Published private(set) var socketState: DashboardSocketState = .disconnected
    /// Shown on the Connect screen after the appliance revoked this phone's token.
    @Published private(set) var pairingNotice: String?

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
        socket.onUnauthorized = { [weak self] in
            guard let self else { return }
            Task { @MainActor in
                self.handleUnpaired()
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
        pairingNotice = nil
        isConnected = true
    }

    /// Route REST failures here: a 401 means the appliance unpaired this phone.
    func handle(_ error: Error) {
        if error.isUnauthorized { handleUnpaired() }
    }

    /// The appliance revoked this phone's token: back to pairing, keeping the address.
    func handleUnpaired() {
        socket.stop()
        connectionStore.clearToken()
        client.token = nil
        dashboardState = .empty
        socketState = .disconnected
        pairingNotice = "This phone was unpaired from Home Radar. Pair again to keep getting alerts."
        isConnected = false
    }

    /// Forgets the saved appliance connection entirely (Settings ->
    /// "Forget This Appliance"), dropping back to the Connect flow.
    func disconnect() {
        pairingNotice = nil
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

    /// Registers an APNs device token with the appliance.
    func registerAPNSToken(token: String) async {
        guard connectionStore.hasCredentials else { return }
        try? await client.registerAPNSToken(token: token)
    }
}
