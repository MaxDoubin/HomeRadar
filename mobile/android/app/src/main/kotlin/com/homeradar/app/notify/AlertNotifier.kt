package com.homeradar.app.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.homeradar.core.model.Alert

/**
 * Turns the output of `com.homeradar.core.state.DashboardState.applySnapshot(...)`
 * into real local notifications.
 *
 * This only fires while the app process is alive and the dashboard websocket
 * (see [com.homeradar.app.DashboardViewModel]) is connected -- there is no
 * notification if the app is fully killed or the phone has been offline for a
 * while. That's a deliberate scope cut for this pass, matching the parallel
 * iOS build:
 *
 * TODO(v2, needs a Firebase project + FCM server key): register for FCM and
 * wire a device-token upload endpoint here for real background push.
 */
object AlertNotifier {

    const val CHANNEL_ID: String = "homeradar_alerts"
    private const val CHANNEL_NAME = "HomeRadar Alerts"
    private const val CHANNEL_DESCRIPTION = "New security alerts detected on your home network"

    /** Safe to call more than once (e.g. across process restarts) -- creating an existing channel is a no-op. */
    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = CHANNEL_DESCRIPTION
            }
            val manager = context.getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    /**
     * Posts one notification per alert. Callers should pass in exactly the
     * list returned by `DashboardState.applySnapshot(...)` -- an empty list
     * (the common case, no new alerts since the last snapshot) posts nothing.
     */
    fun notifyNewAlerts(context: Context, alerts: List<Alert>) {
        if (alerts.isEmpty()) return

        val manager = NotificationManagerCompat.from(context)
        alerts.forEach { alert ->
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(alert.title)
                .setContentText(alert.description ?: alert.severity)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
            try {
                manager.notify(alert.id, notification)
            } catch (_: SecurityException) {
                // POST_NOTIFICATIONS not granted (Android 13+) -- drop silently rather than crash.
            }
        }
    }
}
