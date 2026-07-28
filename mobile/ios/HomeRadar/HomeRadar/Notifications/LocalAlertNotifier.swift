// TODO(v2, needs Apple Developer Program credentials + APNs push
// certificate): register for remote notifications and wire an APNs
// device-token upload endpoint here. This pass only supports LOCAL
// notifications fired while the app process is alive and the dashboard
// websocket connection is open (foreground, or brief background execution
// right after backgrounding) -- there is no true background/killed-app push
// in this pass.

import Foundation
import UserNotifications

/// Turns live dashboard snapshots into local alert notifications.
///
/// Wraps the pure `AlertDiffer` diff logic: every snapshot is fed through
/// the differ regardless of whether notifications are actually enabled, so
/// the seen-set stays consistent even if the user flips the Settings
/// toggle off and back on later (re-enabling must not cause a backlog of
/// notifications for alerts that already existed before the user paused
/// them). Whether a notification is actually *presented* is gated on
/// `notificationsEnabled`.
final class LocalAlertNotifier {
    /// Mirrors the Settings screen's notifications toggle. `false` by
    /// default -- notifications are opt-in, and the OS permission prompt is
    /// only triggered from Settings, never unconditionally at launch.
    var notificationsEnabled: Bool = false

    private var differ = AlertDiffer()
    private let center: UNUserNotificationCenter

    init(center: UNUserNotificationCenter = .current()) {
        self.center = center
    }

    /// Feed every websocket snapshot's alert list through here. Fires
    /// exactly one local notification per newly-appeared alert ID when
    /// `notificationsEnabled` is true; otherwise just advances the seen set.
    func processIncoming(alerts: [Alert]) {
        let newlyAppeared = differ.newlyAppeared(in: alerts)
        guard notificationsEnabled, !newlyAppeared.isEmpty else { return }
        for alert in newlyAppeared {
            fire(for: alert)
        }
    }

    private func fire(for alert: Alert) {
        let content = UNMutableNotificationContent()
        content.title = "HomeRadar Alert"
        content.body = alert.title
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "homeradar.alert.\(alert.id)",
            content: content,
            trigger: nil
        )
        center.add(request)
    }

    /// Requests OS notification authorization. Called from the Settings
    /// screen when the user turns the notifications toggle on -- never
    /// fired unconditionally at app launch. Returns whether authorization
    /// was actually granted, so the caller can revert the toggle if not.
    func requestAuthorization() async -> Bool {
        do {
            return try await center.requestAuthorization(options: [.alert, .sound, .badge])
        } catch {
            return false
        }
    }
}
