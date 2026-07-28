package com.homeradar.core.state

import com.homeradar.core.model.Alert
import com.homeradar.core.model.Dashboard
import com.homeradar.core.model.SnapshotMessage

/**
 * Plain Kotlin (no coroutines, no Android) holder for the most recently seen
 * dashboard state, plus the alert-diffing logic used to decide which alerts
 * are newly-appeared and should trigger a notification.
 *
 * Mirrors the web dashboard's `seenAlerts`/`alertsInitialized` pattern
 * (see `frontend/src/App.jsx`): the first snapshot after (re)connecting
 * establishes a baseline with no notifications, and only alerts that show up
 * afterward are reported as "new".
 */
class DashboardState {

    var latestDashboard: Dashboard? = null
        private set

    var latestSnapshot: SnapshotMessage? = null
        private set

    private val seenAlertIds: MutableSet<Int> = mutableSetOf()
    private var initialized: Boolean = false

    fun updateDashboard(dashboard: Dashboard) {
        latestDashboard = dashboard
    }

    fun updateSnapshot(snapshot: SnapshotMessage) {
        latestSnapshot = snapshot
    }

    /**
     * Diffs [alerts] against the alert IDs already seen.
     *
     * - On the very first call ever, seeds the seen set from every unresolved
     *   alert in [alerts] and returns an empty list: nothing should notify
     *   for state that already existed when we first connected/reconnected.
     * - On every subsequent call, returns the subset of [alerts] that are
     *   unresolved (`is_resolved == 0`) AND not yet in the seen set, adds
     *   those IDs to the seen set, and returns them as "newly appeared,
     *   should notify" alerts.
     *
     * An alert that disappears from the list entirely (e.g. it was resolved
     * and dropped off an unresolved-only feed) is simply left in the seen
     * set forever -- it causes no error on this or any later call.
     */
    fun applySnapshot(alerts: List<Alert>): List<Alert> {
        if (!initialized) {
            initialized = true
            alerts.filter { it.is_resolved == 0 }.forEach { seenAlertIds.add(it.id) }
            return emptyList()
        }

        val newlyAppeared = alerts.filter { it.is_resolved == 0 && it.id !in seenAlertIds }
        newlyAppeared.forEach { seenAlertIds.add(it.id) }
        return newlyAppeared
    }
}
