package com.homeradar.app.settings

import android.content.Intent
import android.provider.Settings as AndroidSettings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.homeradar.app.DashboardViewModel
import kotlinx.coroutines.launch
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The one screen (besides the "scan network" action) that makes direct
 * one-off `HomeRadarClient` REST calls: `getSettings()` on load,
 * `patchSettings(...)` on save, and `postScan()` for the manual scan button.
 */
@Composable
fun SettingsScreen(viewModel: DashboardViewModel) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    var isLoading by remember { mutableStateOf(true) }
    var isSaving by remember { mutableStateOf(false) }
    var isScanning by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var confirmForget by remember { mutableStateOf(false) }

    var householdName by remember { mutableStateOf("") }
    var digestEmail by remember { mutableStateOf("") }
    var dnsUpstream by remember { mutableStateOf("") }
    var notificationsEnabled by remember { mutableStateOf(true) }
    var dnsEnabled by remember { mutableStateOf(false) }
    var phoneNotificationsAllowed by remember {
        mutableStateOf(NotificationManagerCompat.from(context).areNotificationsEnabled())
    }

    // Re-check after the user returns from the system notification settings.
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        phoneNotificationsAllowed = NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

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
            viewModel.onApiError(t)
            statusMessage = "Could not load settings: ${t.message}"
        } finally {
            isLoading = false
        }
    }

    if (confirmForget) {
        AlertDialog(
            onDismissRequest = { confirmForget = false },
            title = { Text("Forget this appliance?") },
            text = { Text("This phone will stop receiving Home Radar alerts until you pair it again.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmForget = false
                    viewModel.forgetAppliance()
                }) { Text("Forget") }
            },
            dismissButton = {
                TextButton(onClick = { confirmForget = false }) { Text("Cancel") }
            },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
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
            // DNS filtering is switched on the appliance itself, so this is status only.
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
            ) {
                Text("DNS filtering")
                Text(if (dnsEnabled) "On" else "Off (set on the appliance)")
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Alerts on this phone")
                if (phoneNotificationsAllowed) {
                    Text("On")
                } else {
                    TextButton(onClick = {
                        context.startActivity(
                            Intent(AndroidSettings.ACTION_APP_NOTIFICATION_SETTINGS)
                                .putExtra(AndroidSettings.EXTRA_APP_PACKAGE, context.packageName)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }) { Text("Off. Turn on") }
                }
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
                                ),
                            )
                            statusMessage = "Saved"
                        } catch (t: Throwable) {
                            viewModel.onApiError(t)
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
                            val result = viewModel.requireClient().postScan()
                            val found = runCatching {
                                result.jsonObject["devices_found"]?.jsonPrimitive?.intOrNull
                            }.getOrNull()
                            statusMessage = when (found) {
                                null -> "Scan complete"
                                1 -> "Scan complete: found 1 device"
                                else -> "Scan complete: found $found devices"
                            }
                        } catch (t: Throwable) {
                            viewModel.onApiError(t)
                            statusMessage = "Could not scan: ${t.message}"
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

            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = { confirmForget = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Forget appliance")
            }
        }

        statusMessage?.let {
            Spacer(Modifier.height(16.dp))
            Text(it)
        }
    }
}
