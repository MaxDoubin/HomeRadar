import Combine
import Foundation

@MainActor
final class DevicesViewModel: ObservableObject {
    @Published private(set) var devices: [Device] = []
    @Published var errorMessage: String?
    @Published private(set) var updatingDeviceIDs: Set<Int> = []

    private let session: AppSession
    private var cancellables: Set<AnyCancellable> = []

    init(session: AppSession) {
        self.session = session

        session.$dashboardState
            .map(\.devices)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] devices in self?.devices = devices }
            .store(in: &cancellables)
    }

    /// Applies an authorization change via `PATCH /devices/{id}/authorization`
    /// and optimistically merges the returned device into the local list --
    /// the next websocket snapshot (within ~3s) will reconcile it either way.
    func setAuthorization(deviceID: Int, state: Int) async {
        updatingDeviceIDs.insert(deviceID)
        errorMessage = nil
        defer { updatingDeviceIDs.remove(deviceID) }

        do {
            let updated = try await session.client.updateDeviceAuthorization(id: deviceID, state: state)
            if let index = devices.firstIndex(where: { $0.id == deviceID }) {
                devices[index] = updated
            }
        } catch {
            errorMessage = "Couldn't update that device. Try again."
        }
    }
}
