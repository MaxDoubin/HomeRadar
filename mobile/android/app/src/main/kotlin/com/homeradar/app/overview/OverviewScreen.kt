package com.homeradar.app.overview

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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

        ScoreRing(score = uiState.securityScore)
        Spacer(Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            StatCard(
                label = "Devices",
                value = uiState.deviceCount.toString(),
                modifier = Modifier.weight(1f)
            )
            StatCard(
                label = "Open alerts",
                value = uiState.openAlertCount.toString(),
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun ScoreRing(score: Int) {
    val animatedProgress by animateFloatAsState(targetValue = score / 100f, label = "score_ring")
    val scoreColor = when {
        score >= 85 -> Color(0xFF39E6A2) // Green
        score >= 65 -> Color(0xFFF5B84B) // Amber
        else -> Color(0xFFFF6B69) // Red
    }

    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(modifier = Modifier.size(80.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(
                    progress = { 1f },
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    strokeWidth = 6.dp
                )
                CircularProgressIndicator(
                    progress = { animatedProgress },
                    modifier = Modifier.fillMaxSize(),
                    color = scoreColor,
                    strokeWidth = 6.dp
                )
                Text(
                    text = score.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = scoreColor
                )
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text("Household security", style = MaterialTheme.typography.bodyMedium)
                val statusText = when {
                    score >= 85 -> "Looking strong"
                    score >= 65 -> "Needs attention"
                    else -> "Action recommended"
                }
                Text(statusText, style = MaterialTheme.typography.titleMedium, color = scoreColor)
            }
        }
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    ElevatedCard(modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(value, style = MaterialTheme.typography.headlineMedium)
        }
    }
}
