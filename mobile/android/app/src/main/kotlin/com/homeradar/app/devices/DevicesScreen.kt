package com.homeradar.app.devices

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.homeradar.app.DashboardViewModel
import com.homeradar.core.model.Device

/**
 * Device list driven by [DashboardViewModel.uiState] (the dashboard
 * websocket's last snapshot), with an authorize/block/reset action per row
 * (`PATCH /devices/{id}/authorization`). The full Device Detail screen
 * (policy editor, trust breakdown, findings, per-device traffic) is still
 * out of scope for this pass -- just the basic control action.
 */
@Composable
fun DevicesScreen(viewModel: DashboardViewModel) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Column(modifier = Modifier
        .fillMaxSize()
        .padding(16.dp)) {
        Text("Devices", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))

        if (uiState.devices.isEmpty()) {
            Text("No devices seen yet.")
        } else {
            LazyColumn {
                items(uiState.devices, key = { it.id }) { device ->
                    DeviceRow(
                        device = device,
                        isUpdating = device.id in uiState.updatingDeviceIds,
                        onSetAuthorization = { state -> viewModel.setDeviceAuthorization(device.id, state) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun DeviceRow(device: Device, isUpdating: Boolean, onSetAuthorization: (Int) -> Unit) {
    ListItem(
        headlineContent = { Text(device.hostname ?: device.mac) },
        supportingContent = {
            Column {
                Text(listOfNotNull(device.vendor, device.ip, device.device_type).joinToString(" · "))
                Spacer(Modifier.height(4.dp))
                if (isUpdating) {
                    CircularProgressIndicator(modifier = Modifier.height(20.dp))
                } else {
                    AuthorizationPicker(state = device.is_authorized, onSelect = onSetAuthorization)
                }
            }
        },
    )
}

@Composable
private fun AuthorizationPicker(state: Int, onSelect: (Int) -> Unit) {
    val options = listOf(0 to "Pending", 1 to "Authorized", 2 to "Blocked")
    SingleChoiceSegmentedButtonRow {
        options.forEachIndexed { index, (value, label) ->
            SegmentedButton(
                selected = state == value,
                onClick = { onSelect(value) },
                shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
            ) { Text(label) }
        }
    }
}
