import Foundation
import SwiftUI

struct DeviceRowView: View {
    let device: Device
    let isUpdating: Bool
    let onSetAuthorization: (Int) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(displayName)
                    .font(.headline)
                Spacer()
                authorizationBadge
            }

            if !subtitle.isEmpty {
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 12) {
                Label(device.ip ?? "unknown IP", systemImage: "network")
                Label(device.deviceType, systemImage: "tag")
                Label(lastSeenLabel, systemImage: "clock")
            }
            .font(.caption2)
            .foregroundStyle(.secondary)

            if isUpdating {
                ProgressView()
                    .padding(.top, 2)
            } else {
                Picker("Authorization", selection: Binding(
                    get: { device.isAuthorized },
                    set: { onSetAuthorization($0) }
                )) {
                    Text("Pending").tag(0)
                    Text("Authorized").tag(1)
                    Text("Blocked").tag(2)
                }
                .pickerStyle(.segmented)
                .padding(.top, 2)
            }
        }
        .padding(.vertical, 4)
    }

    private var displayName: String {
        if let hostname = device.hostname, !hostname.isEmpty {
            return hostname
        }
        return device.mac
    }

    private var subtitle: String {
        [device.vendor, device.model].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " \u{00B7} ")
    }

    /// Falls back to "unknown" rather than crashing when `last_seen` can't
    /// be parsed -- see `HomeRadarDateParsing`.
    private var lastSeenLabel: String {
        guard let date = device.lastSeenDate else { return "last seen unknown" }
        let formatter = RelativeDateTimeFormatter()
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    private var authorizationBadge: some View {
        let (text, color): (String, Color) = {
            switch device.isAuthorized {
            case DeviceAuthorizationState.authorized.rawValue: return ("Authorized", .green)
            case DeviceAuthorizationState.blocked.rawValue: return ("Blocked", .red)
            default: return ("Pending", .orange)
            }
        }()
        return Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }
}
