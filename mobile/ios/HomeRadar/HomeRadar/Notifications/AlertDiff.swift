import Foundation

/// Pure, testable diff logic behind local alert notifications.
///
/// On the very first snapshot this differ ever sees, it seeds its
/// already-seen set from every alert present and reports zero "newly
/// appeared" alerts. Without this rule, pairing with (or relaunching into)
/// an appliance that already has open alerts would immediately fire a
/// notification storm for alerts the household has already seen elsewhere
/// (the web dashboard, a previous app session, etc).
///
/// On every subsequent call, any alert ID present in the snapshot that is
/// not yet in the seen set is reported exactly once, then added to the
/// seen set so it is never refired. An alert disappearing from a later
/// snapshot (resolved, evicted, or otherwise no longer present) is simply
/// left in the seen set -- no crash, no special-casing required -- and if
/// an alert with that same ID were ever to reappear, it would correctly be
/// treated as already-seen rather than refired.
struct AlertDiffer {
    private(set) var seenAlertIDs: Set<Int> = []
    private var initialized = false

    mutating func newlyAppeared(in alerts: [Alert]) -> [Alert] {
        guard initialized else {
            initialized = true
            seenAlertIDs = Set(alerts.map(\.id))
            return []
        }

        var result: [Alert] = []
        for alert in alerts where !seenAlertIDs.contains(alert.id) {
            seenAlertIDs.insert(alert.id)
            result.append(alert)
        }
        return result
    }
}
