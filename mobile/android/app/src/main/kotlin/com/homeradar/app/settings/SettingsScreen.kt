package com.homeradar.app.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.homeradar.app.DashboardViewModel
import kotlinx.coroutines.launch

/**
 * The one screen (besides the "scan network" action) that makes direct
 * one-off `HomeRadarClient` REST calls: `getSettings()` on load,
 * `patchSettings(...)` on save, and `postScan()` for the manual scan button.
 */
@Composable
fun SettingsScreen(viewModel: DashboardViewModel) {
    val scope = rememberCoroutineScope()

    var isLoading by remember { mutableStateOf(true) }
    var isSaving by remember { mutableStateOf(false) }
    var isScanning by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }

    var householdName by remember { mutableStateOf("") }
    var digestEmail by remember { mutableStateOf("") }
    var dnsUpstream by remember { mutableStateOf("") }
    var notificationsEnabled by remember { mutableStateOf(true) }
    var dnsEnabled by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        isLoading = true
        try {
            val loaded = viewModel.requireClient().getSettings()
            householdName = loaded.household_name
            digestEmail = loaded.digest_email
            dnsUpstream = loaded.dns_upstream
            notificationsEnabled = loaded.notifications_enabled
            dnsEnabled = loaded.dns_enabled
        } catch (t: Throwable) {
            statusMessage = "Could not load settings: ${t.message}"
        } finally {
            isLoading = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        if (isLoading) {
            CircularProgressIndicator()
        } else {
            OutlinedTextField(
                value = householdName,
                onValueChange = { householdName = it },
                label = { Text("Household name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = digestEmail,
                onValueChange = { digestEmail = it },
                label = { Text("Digest email") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = dnsUpstream,
                onValueChange = { dnsUpstream = it },
                label = { Text("DNS upstream") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Notifications enabled")
                Switch(
                    checked = notificationsEnabled,
                    onCheckedChange = { notificationsEnabled = it },
                )
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("DNS filtering enabled")
                Switch(checked = dnsEnabled, onCheckedChange = { dnsEnabled = it })
            }

            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    isSaving = true
                    statusMessage = null
                    scope.launch {
                        try {
                            viewModel.requireClient().patchSettings(
                                mapOf(
                                    "household_name" to householdName,
                                    "digest_email" to digestEmail,
                                    "dns_upstream" to dnsUpstream,
                                    "notifications_enabled" to notificationsEnabled,
                                    "dns_enabled" to dnsEnabled,
                                ),
                            )
                            statusMessage = "Saved"
                        } catch (t: Throwable) {
                            statusMessage = "Could not save: ${t.message}"
                        } finally {
                            isSaving = false
                        }
                    }
                },
                enabled = !isSaving,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (isSaving) "Saving…" else "Save settings")
            }

            Spacer(Modifier.height(24.dp))
            HorizontalDivider()
            Spacer(Modifier.height(24.dp))

            Button(
                onClick = {
                    isScanning = true
                    statusMessage = null
                    scope.launch {
                        try {
                            viewModel.requireClient().postScan()
                            statusMessage = "Scan started"
                        } catch (t: Throwable) {
                            statusMessage = "Could not start scan: ${t.message}"
                        } finally {
                            isScanning = false
                        }
                    }
                },
                enabled = !isScanning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (isScanning) "Scanning…" else "Scan network now")
            }
        }

        statusMessage?.let {
            Spacer(Modifier.height(16.dp))
            Text(it)
        }
    }
}
