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
                    HStack(spacing: 16) {
                        ScoreRing(score: viewModel.dashboardState.securityScore)
                            .frame(width: 80, height: 80)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Household security")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)

                            let status = viewModel.dashboardState.securityScore >= 85 ? "Looking strong" :
                                         viewModel.dashboardState.securityScore >= 65 ? "Needs attention" :
                                         "Action recommended"

                            let color: Color = viewModel.dashboardState.securityScore >= 85 ? Color(red: 57/255, green: 230/255, blue: 162/255) :
                                               viewModel.dashboardState.securityScore >= 65 ? Color(red: 245/255, green: 184/255, blue: 75/255) :
                                               Color(red: 255/255, green: 107/255, blue: 105/255)

                            Text(status)
                                .font(.headline)
                                .foregroundStyle(color)
                        }
                    }
                    .padding(.vertical, 12)

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

struct ScoreRing: View {
    let score: Int

    var color: Color {
        if score >= 85 { return Color(red: 57/255, green: 230/255, blue: 162/255) }
        if score >= 65 { return Color(red: 245/255, green: 184/255, blue: 75/255) }
        return Color(red: 255/255, green: 107/255, blue: 105/255)
    }

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(0.2), lineWidth: 6)
            Circle()
                .trim(from: 0, to: CGFloat(score) / 100)
                .stroke(color, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeInOut(duration: 1.0), value: score)
            Text("\(score)")
                .font(.title2)
                .bold()
                .foregroundStyle(color)
        }
    }
}
