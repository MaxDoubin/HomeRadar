package com.homeradar.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.homeradar.app.alerts.AlertsScreen
import com.homeradar.app.connect.ConnectScreen
import com.homeradar.app.devices.DevicesScreen
import com.homeradar.app.overview.OverviewScreen
import com.homeradar.app.settings.SettingsScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    HomeRadarRoot()
                }
            }
        }
    }
}

/** Bottom-nav destinations, in the same order used across the whole HomeRadar mobile effort. */
private enum class Tab(val label: String, val icon: ImageVector) {
    OVERVIEW("Overview", Icons.Filled.Home),
    DEVICES("Devices", Icons.Filled.Devices),
    ALERTS("Alerts", Icons.Filled.Notifications),
    SETTINGS("Settings", Icons.Filled.Settings),
}

/**
 * Root of the UI: shows [ConnectScreen] whenever no saved address+token
 * exists yet, otherwise the four-tab bottom-nav UI. A plain `when` over
 * [ConnectionState] and a `when` over [Tab] -- deliberately no
 * Navigation-Compose, this app doesn't need it.
 */
@Composable
private fun HomeRadarRoot(viewModel: DashboardViewModel = viewModel()) {
    val connectionState by viewModel.connectionState.collectAsStateWithLifecycle()
    val pairingNotice by viewModel.pairingNotice.collectAsStateWithLifecycle()

    when (connectionState) {
        is ConnectionState.Loading -> {
            // Reading the saved address is effectively instant (local DataStore); nothing to show.
        }
        is ConnectionState.NotConnected -> ConnectScreen(
            notice = pairingNotice,
            onConnected = { viewModel.refresh() },
        )
        is ConnectionState.Connected -> ConnectedTabs(viewModel)
    }
}

@Composable
private fun ConnectedTabs(viewModel: DashboardViewModel) {
    var selectedTab by remember { mutableStateOf(Tab.OVERVIEW) }
    RequestNotificationPermission()

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            when (selectedTab) {
                Tab.OVERVIEW -> OverviewScreen(viewModel)
                Tab.DEVICES -> DevicesScreen(viewModel)
                Tab.ALERTS -> AlertsScreen(viewModel)
                Tab.SETTINGS -> SettingsScreen(viewModel)
            }
        }
    }
}

/**
 * Android 13+ needs a runtime grant before alert notifications can appear.
 * Asked once the phone is paired, when the request makes sense; if the user
 * declines, alerts still show in the app and Settings explains how to turn
 * notifications on later.
 */
@Composable
private fun RequestNotificationPermission() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}
