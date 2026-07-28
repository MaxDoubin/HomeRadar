import SwiftUI

struct DevicesListView: View {
    @StateObject var viewModel: DevicesViewModel

    var body: some View {
        NavigationStack {
            List {
                if let errorMessage = viewModel.errorMessage {
                    Text(errorMessage).foregroundStyle(.red)
                }
                ForEach(viewModel.devices) { device in
                    DeviceRowView(
                        device: device,
                        isUpdating: viewModel.updatingDeviceIDs.contains(device.id),
                        onSetAuthorization: { newState in
                            Task { await viewModel.setAuthorization(deviceID: device.id, state: newState) }
                        }
                    )
                }
            }
            .navigationTitle("Devices")
            .overlay {
                if viewModel.devices.isEmpty {
                    emptyState
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "network.slash")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("No devices yet")
                .foregroundStyle(.secondary)
        }
    }
}
