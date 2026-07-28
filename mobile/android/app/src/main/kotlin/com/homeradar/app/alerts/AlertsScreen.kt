package com.homeradar.app.alerts

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.homeradar.app.DashboardViewModel
import com.homeradar.core.model.Alert

/**
 * Alert list driven by [DashboardViewModel.uiState] (the dashboard
 * websocket's last snapshot), with a "Resolve" action per unresolved alert
 * (`PATCH /alerts/{id}`).
 */
@Composable
fun AlertsScreen(viewModel: DashboardViewModel) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val sorted = remember(uiState.alerts) {
        // Unresolved first, newest first within each group.
        uiState.alerts.sortedWith(
            compareBy<Alert> { it.is_resolved }.thenByDescending { it.created_at },
        )
    }

    Column(modifier = Modifier
        .fillMaxSize()
        .padding(16.dp)) {
        Text("Alerts", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))

        if (sorted.isEmpty()) {
            Text("No alerts.")
        } else {
            LazyColumn {
                items(sorted, key = { it.id }) { alert ->
                    AlertRow(
                        alert = alert,
                        isResolving = alert.id in uiState.resolvingAlertIds,
                        onResolve = { viewModel.setAlertResolved(alert.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun AlertRow(alert: Alert, isResolving: Boolean, onResolve: () -> Unit) {
    ListItem(
        headlineContent = { Text(alert.title) },
        supportingContent = { alert.description?.let { Text(it) } },
        trailingContent = {
            when {
                alert.is_resolved != 0 -> Text("Resolved")
                isResolving -> CircularProgressIndicator(modifier = Modifier.height(20.dp))
                else -> OutlinedButton(onClick = onResolve) { Text("Resolve") }
            }
        },
    )
}
