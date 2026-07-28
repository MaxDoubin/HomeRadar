package com.homeradar.app.overview

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.homeradar.app.DashboardViewModel

/**
 * Read-only summary tab: security score, device count, open alert count, and
 * whether the dashboard websocket is currently connected. Entirely driven by
 * [DashboardViewModel.uiState] -- makes no REST calls of its own.
 */
@Composable
fun OverviewScreen(viewModel: DashboardViewModel) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Column(modifier = Modifier
        .fillMaxSize()
        .padding(16.dp)) {
        Text("Overview", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))

        AssistChip(
            onClick = {},
            label = { Text(if (uiState.socketConnected) "Live" else "Reconnecting…") },
        )
        Spacer(Modifier.height(16.dp))

        StatCard(label = "Security score", value = uiState.securityScore.toString())
        Spacer(Modifier.height(8.dp))
        StatCard(label = "Devices", value = uiState.deviceCount.toString())
        Spacer(Modifier.height(8.dp))
        StatCard(label = "Open alerts", value = uiState.openAlertCount.toString())
    }
}

@Composable
private fun StatCard(label: String, value: String) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(value, style = MaterialTheme.typography.headlineMedium)
        }
    }
}
