import Combine
import Foundation

/// Overview screen state, sourced entirely from the shared `AppSession`'s
/// live websocket-driven `DashboardState`. This screen makes no REST calls
/// of its own except the explicit "Scan Network Now" action.
@MainActor
final class OverviewViewModel: ObservableObject {
    @Published private(set) var dashboardState: DashboardState = .empty
    @Published private(set) var socketState: DashboardSocketState = .disconnected
    @Published private(set) var isScanning = false
    @Published var scanErrorMessage: String?

    private let session: AppSession
    private var cancellables: Set<AnyCancellable> = []

    init(session: AppSession) {
        self.session = session

        session.$dashboardState
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in self?.dashboardState = state }
            .store(in: &cancellables)

        session.$socketState
            .receive(on: DispatchQueue.main)
            .sink { [weak self] state in self?.socketState = state }
            .store(in: &cancellables)
    }

    func triggerScan() async {
        isScanning = true
        scanErrorMessage = nil
        defer { isScanning = false }
        do {
            try await session.client.triggerScan()
        } catch {
            scanErrorMessage = "Couldn't start a scan. Check the connection."
        }
    }
}
