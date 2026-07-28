import Combine
import Foundation

@MainActor
final class AlertsViewModel: ObservableObject {
    @Published private(set) var alerts: [Alert] = []
    @Published var errorMessage: String?
    @Published private(set) var resolvingAlertIDs: Set<Int> = []

    private let session: AppSession
    private var cancellables: Set<AnyCancellable> = []

    init(session: AppSession) {
        self.session = session

        session.$dashboardState
            .map(\.alerts)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] alerts in self?.alerts = alerts }
            .store(in: &cancellables)
    }

    func resolve(alertID: Int) async {
        resolvingAlertIDs.insert(alertID)
        errorMessage = nil
        defer { resolvingAlertIDs.remove(alertID) }

        do {
            let result = try await session.client.resolveAlert(id: alertID, resolved: true)
            if result.isResolved {
                alerts.removeAll { $0.id == alertID }
            }
        } catch {
            errorMessage = "Couldn't resolve that alert. Try again."
        }
    }
}
