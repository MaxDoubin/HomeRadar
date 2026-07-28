import Foundation
import SwiftUI

struct AlertsView: View {
    @StateObject var viewModel: AlertsViewModel

    var body: some View {
        NavigationStack {
            List {
                if let errorMessage = viewModel.errorMessage {
                    Text(errorMessage).foregroundStyle(.red)
                }
                ForEach(viewModel.alerts) { alert in
                    alertRow(alert)
                }
            }
            .navigationTitle("Alerts")
            .overlay {
                if viewModel.alerts.isEmpty {
                    emptyState
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "checkmark.shield")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("No open alerts")
                .foregroundStyle(.secondary)
        }
    }

    private func alertRow(_ alert: Alert) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                severityBadge(alert.severity)
                Text(alert.title).font(.headline)
            }

            if let description = alert.description, !description.isEmpty {
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Spacer()
                if viewModel.resolvingAlertIDs.contains(alert.id) {
                    ProgressView()
                } else {
                    Button("Resolve") {
                        Task { await viewModel.resolve(alertID: alert.id) }
                    }
                    .buttonStyle(.borderless)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func severityBadge(_ severity: String) -> some View {
        Text(severity.capitalized)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(severityColor(severity).opacity(0.15))
            .foregroundStyle(severityColor(severity))
            .clipShape(Capsule())
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "critical", "high": return .red
        case "medium": return .orange
        case "low": return .yellow
        default: return .gray
        }
    }
}
