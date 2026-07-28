import Combine
import Foundation

@MainActor
final class SettingsViewModel: ObservableObject {
    @Published var householdName: String = ""
    @Published var digestEmail: String = ""
    @Published var dnsUpstream: String = ""
    @Published var notificationsEnabled: Bool = false
    @Published var dnsEnabled: Bool = false

    @Published private(set) var isLoading = false
    @Published var errorMessage: String?
    @Published var statusMessage: String?

    private let session: AppSession

    init(session: AppSession) {
        self.session = session
    }

    func load() async {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }
        do {
            let settings = try await session.client.settings()
            apply(settings)
        } catch {
            errorMessage = "Couldn't load settings."
        }
    }

    private func apply(_ settings: Settings) {
        householdName = settings.householdName
        digestEmail = settings.digestEmail
        dnsUpstream = settings.dnsUpstream
        dnsEnabled = settings.dnsEnabled
        notificationsEnabled = settings.notificationsEnabled
        session.notifier.notificationsEnabled = settings.notificationsEnabled
    }

    func save() async {
        errorMessage = nil
        statusMessage = nil
        let update = SettingsUpdateRequest(
            householdName: householdName,
            digestEmail: digestEmail,
            dnsUpstream: dnsUpstream,
            notificationsEnabled: notificationsEnabled,
            dnsEnabled: dnsEnabled
        )
        do {
            let settings = try await session.client.updateSettings(update)
            apply(settings)
            statusMessage = "Saved."
        } catch {
            errorMessage = "Couldn't save settings."
        }
    }

    /// Called when the user flips the notifications toggle on. Requests OS
    /// notification authorization right here -- NOT unconditionally at app
    /// launch -- and reverts the toggle if the user declines.
    func requestNotificationAuthorizationIfNeeded() async {
        guard notificationsEnabled else {
            session.notifier.notificationsEnabled = false
            return
        }
        let granted = await session.notifier.requestAuthorization()
        notificationsEnabled = granted
        session.notifier.notificationsEnabled = granted
        if !granted {
            errorMessage = "Enable notifications for HomeRadar in iOS Settings to receive alerts."
        }
    }

    func forgetAppliance() {
        session.disconnect()
    }
}
