import SwiftUI

/// Top-level content switch: shows the Connect flow whenever no saved
/// appliance address+token exists, otherwise the 4-tab authenticated app.
struct RootView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        Group {
            if session.isConnected {
                TabbedRootView()
            } else {
                ConnectView()
            }
        }
    }
}

/// The 4-tab authenticated app: Overview, Devices, Alerts, Settings.
///
/// Opens the shared dashboard websocket while visible, closes it when the
/// app backgrounds, and reopens it on foreground -- Overview/Devices/Alerts
/// all render off the one shared live `DashboardState`; only Settings and
/// the explicit "Scan Network Now" action make direct one-off REST calls.
private struct TabbedRootView: View {
    @EnvironmentObject private var session: AppSession
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView {
            OverviewView(viewModel: OverviewViewModel(session: session))
                .tabItem { Label("Overview", systemImage: "gauge") }

            DevicesListView(viewModel: DevicesViewModel(session: session))
                .tabItem { Label("Devices", systemImage: "network") }

            AlertsView(viewModel: AlertsViewModel(session: session))
                .tabItem { Label("Alerts", systemImage: "exclamationmark.triangle") }

            SettingsView(viewModel: SettingsViewModel(session: session))
                .tabItem { Label("Settings", systemImage: "gear") }
        }
        .onAppear {
            session.startLiveUpdates()
        }
        .onChange(of: scenePhase) { newPhase in
            switch newPhase {
            case .background:
                session.stopLiveUpdates()
            case .active:
                session.startLiveUpdates()
            default:
                break
            }
        }
    }
}
