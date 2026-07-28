package com.homeradar.app.connect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.homeradar.core.net.HomeRadarClient
import com.homeradar.core.net.TokenProvider
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

private enum class ConnectStep { ADDRESS, PAIR, SUCCESS }

/** Pairing itself needs no auth header -- this is only used for the one-off claim call. */
private object NoTokenProvider : TokenProvider {
    override fun currentToken(): String? = null
}

/**
 * Three-step "connect to an appliance" flow, shown instead of the tab UI
 * whenever no saved address+token exists yet:
 *  1. enter or discover the appliance address
 *  2. enter the pairing code shown on the appliance and claim it
 *  3. confirm success
 *
 * [onConnected] is called once the token has been saved, so the caller
 * (`DashboardViewModel`) can re-check its connection state and switch to the
 * tab UI.
 */
@Composable
fun ConnectScreen(onConnected: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val connectionStore = remember { ConnectionStore(context) }

    var step by remember { mutableStateOf(ConnectStep.ADDRESS) }
    var address by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var isScanning by remember { mutableStateOf(false) }
    var isSubmitting by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var discovered by remember { mutableStateOf(listOf<DiscoveredHost>()) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Connect to HomeRadar", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(24.dp))

        when (step) {
            ConnectStep.ADDRESS -> AddressStep(
                address = address,
                onAddressChange = { address = it; errorMessage = null },
                isScanning = isScanning,
                discovered = discovered,
                onScan = {
                    scope.launch {
                        isScanning = true
                        errorMessage = null
                        discovered = emptyList()
                        withTimeoutOrNull(4_000) {
                            discoverHomeRadarHosts(context).collect { host ->
                                discovered = discovered + host
                            }
                        }
                        isScanning = false
                    }
                },
                onPickDiscovered = { address = it },
                onNext = {
                    if (address.isBlank()) {
                        errorMessage = "Enter an address first"
                    } else {
                        scope.launch { connectionStore.saveAddress(address.trim()) }
                        step = ConnectStep.PAIR
                    }
                },
            )

            ConnectStep.PAIR -> PairStep(
                code = code,
                onCodeChange = { code = it; errorMessage = null },
                isSubmitting = isSubmitting,
                onBack = { step = ConnectStep.ADDRESS },
                onPair = {
                    scope.launch {
                        isSubmitting = true
                        errorMessage = null
                        try {
                            val baseUrl = normalizeApplianceAddress(address)
                            val pairingClient = HomeRadarClient(baseUrl, NoTokenProvider)
                            val result = pairingClient.claimPairingCode(code.trim())
                            connectionStore.saveToken(result.token)
                            step = ConnectStep.SUCCESS
                        } catch (t: Throwable) {
                            errorMessage = "Could not pair: ${t.message ?: "unknown error"}"
                        } finally {
                            isSubmitting = false
                        }
                    }
                },
            )

            ConnectStep.SUCCESS -> SuccessStep(onContinue = onConnected)
        }

        errorMessage?.let {
            Spacer(Modifier.height(16.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun AddressStep(
    address: String,
    onAddressChange: (String) -> Unit,
    isScanning: Boolean,
    discovered: List<DiscoveredHost>,
    onScan: () -> Unit,
    onPickDiscovered: (String) -> Unit,
    onNext: () -> Unit,
) {
    OutlinedTextField(
        value = address,
        onValueChange = onAddressChange,
        label = { Text("Appliance address") },
        placeholder = { Text("homeradar.local:8000") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(12.dp))
    OutlinedButton(
        onClick = onScan,
        enabled = !isScanning,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(Icons.Filled.Search, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text(if (isScanning) "Scanning..." else "Scan network for HomeRadar")
    }

    if (discovered.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        LazyColumn {
            items(discovered, key = { it.address }) { host ->
                OutlinedButton(
                    onClick = { onPickDiscovered(host.address) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                ) {
                    Text("${host.name} (${host.address})")
                }
            }
        }
    }

    Spacer(Modifier.height(20.dp))
    Button(onClick = onNext, modifier = Modifier.fillMaxWidth()) {
        Text("Next")
    }
}

@Composable
private fun PairStep(
    code: String,
    onCodeChange: (String) -> Unit,
    isSubmitting: Boolean,
    onBack: () -> Unit,
    onPair: () -> Unit,
) {
    Text("Enter the pairing code shown on your HomeRadar appliance.")
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
        value = code,
        onValueChange = onCodeChange,
        label = { Text("Pairing code") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(20.dp))
    Button(
        onClick = onPair,
        enabled = !isSubmitting && code.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(if (isSubmitting) "Pairing..." else "Pair")
    }
    TextButton(onClick = onBack) {
        Text("Back")
    }
}

@Composable
private fun SuccessStep(onContinue: () -> Unit) {
    Text("Paired successfully!", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(20.dp))
    Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) {
        Text("Continue")
    }
}
