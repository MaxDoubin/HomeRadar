package com.homeradar.app

import android.app.Application
import com.homeradar.app.notify.AlertNotifier

/**
 * Application subclass; its only job this pass is making sure the alert
 * notification channel exists before anything might try to post to it.
 */
class HomeRadarApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AlertNotifier.ensureChannel(this)
    }
}
