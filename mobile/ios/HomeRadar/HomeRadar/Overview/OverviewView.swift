import SwiftUI

struct OverviewView: View {
    @StateObject var viewModel: OverviewViewModel

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Circle()
                            .fill(indicatorColor)
                            .frame(width: 10, height: 10)
                        Text(connectionLabel)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                }

                Section("Security") {
                    metricRow(title: "Security Score", value: "\(viewModel.dashboardState.securityScore)")
                    metricRow(title: "Open Alerts", value: "\(viewModel.dashboardState.openAlertCount)")
                    metricRow(title: "Devices", value: "\(viewModel.dashboardState.deviceCount)")
                }

                Section {
                    Button {
                        Task { await viewModel.triggerScan() }
                    } label: {
                        if viewModel.isScanning {
                            HStack {
                                ProgressView()
                                Text("Scanning\u{2026}")
                            }
                        } else {
                            Label("Scan Network Now", systemImage: "arrow.clockwise")
                        }
                    }
                    .disabled(viewModel.isScanning)

                    if let message = viewModel.scanErrorMessage {
                        Text(message)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Overview")
        }
    }

    private var connectionLabel: String {
        switch viewModel.socketState {
        case .connected: return "Live"
        case .connecting: return "Connecting\u{2026}"
        case .disconnected: return "Disconnected"
        }
    }

    private var indicatorColor: Color {
        switch viewModel.socketState {
        case .connected: return .green
        case .connecting: return .yellow
        case .disconnected: return .red
        }
    }

    private func metricRow(title: String, value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundStyle(.secondary)
        }
    }
}
