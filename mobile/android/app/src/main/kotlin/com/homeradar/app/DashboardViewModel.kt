package com.homeradar.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import com.homeradar.app.connect.ConnectionStore
import com.homeradar.app.connect.normalizeApplianceAddress
import com.homeradar.app.notify.AlertNotifier
import com.homeradar.core.model.Alert
import com.homeradar.core.model.Device
import com.homeradar.core.net.DashboardSocket
import com.homeradar.core.net.HomeRadarClient
import com.homeradar.core.net.nextBackoffMillis
import com.homeradar.core.state.DashboardState
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch

/** Whether the app has a saved appliance address + pairing token yet. */
sealed interface ConnectionState {
    data object Loading : ConnectionState
    data object NotConnected : ConnectionState
    data class Connected(val baseUrl: String) : ConnectionState
}

/** Everything the Overview/Devices/Alerts tabs read, all fed from the dashboard websocket. */
data class DashboardUiState(
    val deviceCount: Int = 0,
    val openAlertCount: Int = 0,
    val securityScore: Int = 0,
    val devices: List<Device> = emptyList(),
    val alerts: List<Alert> = emptyList(),
    val socketConnected: Boolean = false,
    /** Device IDs with an authorization change in flight, for a per-row spinner. */
    val updatingDeviceIds: Set<Int> = emptySet(),
    /** Alert IDs currently being resolved, for a per-row spinner. */
    val resolvingAlertIds: Set<Int> = emptySet(),
)

/**
 * Owns the one shared [HomeRadarClient] + [DashboardSocket] + [DashboardState]
 * for the whole app. Overview/Devices/Alerts read [uiState] for their data
 * (fed by the dashboard websocket, not polling), but Devices/Alerts still
 * trigger direct one-off writes here (authorize/block a device, resolve an
 * alert) -- the socket has no write side, only Settings/"scan network" were
 * ever meant to be REST-only in the sense of not being socket-driven.
 */
class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val connectionStore = ConnectionStore(application)
    private val dashboardState = DashboardState()

    private var client: HomeRadarClient? = null
    private var socket: DashboardSocket? = null
    private var reconnectJob: Job? = null
    private var snapshotJob: Job? = null
    private var connectivityJob: Job? = null

    /** The last address we know is paired, kept even while the socket is torn down while backgrounded. */
    private var lastBaseUrl: String? = null

    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.Loading)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    private val processLifecycleObserver = object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
            // Foregrounded again: reopen the socket for whatever address we already had, if any.
            lastBaseUrl?.let { baseUrl -> if (socket == null) startSocket(baseUrl) }
        }

        override fun onStop(owner: LifecycleOwner) {
            // Backgrounded: stop pinging the appliance until we're back in the foreground.
            teardownSocket()
        }
    }

    init {
        ProcessLifecycleOwner.get().lifecycle.addObserver(processLifecycleObserver)
        viewModelScope.launch {
            connectionStore.addressFlow.collect { address -> refreshConnectionState(address) }
        }
    }

    /** Call after `ConnectScreen` finishes pairing (address+token are both now saved). */
    fun refresh() {
        viewModelScope.launch {
            refreshConnectionState(connectionStore.addressFlow.firstOrNull())
        }
    }

    /** The shared client for one-off REST calls (Settings screen, "scan network" action). */
    fun requireClient(): HomeRadarClient =
        client ?: error("requireClient() called before a connection was established")

    /**
     * Authorize/block/reset a device (`state`: 0=pending, 1=authorized,
     * 2=blocked). The next websocket snapshot will supersede this with the
     * server's real state; the local optimistic update just avoids a UI
     * flash back to the old value in the meantime.
     */
    fun setDeviceAuthorization(deviceId: Int, state: Int) {
        val homeRadarClient = client ?: return
        if (deviceId in _uiState.value.updatingDeviceIds) return
        _uiState.value = _uiState.value.copy(updatingDeviceIds = _uiState.value.updatingDeviceIds + deviceId)
        viewModelScope.launch {
            try {
                val updated = homeRadarClient.patchDeviceAuthorization(deviceId, state)
                _uiState.value = _uiState.value.copy(
                    devices = _uiState.value.devices.map { if (it.id == deviceId) updated else it },
                )
            } catch (_: Exception) {
                // Left as-is; the next socket snapshot will reconcile the real state.
            } finally {
                _uiState.value = _uiState.value.copy(updatingDeviceIds = _uiState.value.updatingDeviceIds - deviceId)
            }
        }
    }

    /** Resolve (or unresolve) an alert. */
    fun setAlertResolved(alertId: Int, resolved: Boolean = true) {
        val homeRadarClient = client ?: return
        if (alertId in _uiState.value.resolvingAlertIds) return
        _uiState.value = _uiState.value.copy(resolvingAlertIds = _uiState.value.resolvingAlertIds + alertId)
        viewModelScope.launch {
            try {
                val result = homeRadarClient.patchAlertResolved(alertId, resolved)
                _uiState.value = _uiState.value.copy(
                    alerts = _uiState.value.alerts.map {
                        if (it.id == alertId) it.copy(is_resolved = if (result.is_resolved) 1 else 0) else it
                    },
                )
            } catch (_: Exception) {
                // Left as-is; the next socket snapshot will reconcile the real state.
            } finally {
                _uiState.value = _uiState.value.copy(resolvingAlertIds = _uiState.value.resolvingAlertIds - alertId)
            }
        }
    }

    private fun refreshConnectionState(address: String?) {
        val token = connectionStore.currentToken()
        if (address.isNullOrBlank() || token.isNullOrBlank()) {
            lastBaseUrl = null
            teardownSocket()
            client = null
            _connectionState.value = ConnectionState.NotConnected
            return
        }

        val baseUrl = normalizeApplianceAddress(address)
        lastBaseUrl = baseUrl
        _connectionState.value = ConnectionState.Connected(baseUrl)
        client = HomeRadarClient(baseUrl, connectionStore)
        if (socket == null) startSocket(baseUrl)
    }

    private fun startSocket(baseUrl: String) {
        teardownSocket()
        val newSocket = DashboardSocket(baseUrl, connectionStore)
        socket = newSocket
        observeSnapshots(newSocket)
        observeConnectivity(newSocket)
        reconnectJob = viewModelScope.launch {
            var backoff = 0L
            newSocket.connect()
            // The first emission from a freshly-created StateFlow is always the initial
            // `false` from before any connect attempt resolved -- drop it so it isn't
            // mistaken for a real disconnect and doesn't trigger an immediate extra retry.
            newSocket.connected.drop(1).collect { connected ->
                if (connected) {
                    backoff = 0L
                } else {
                    backoff = nextBackoffMillis(backoff)
                    delay(backoff)
                    newSocket.connect()
                }
            }
        }
    }

    private fun observeSnapshots(socket: DashboardSocket) {
        snapshotJob?.cancel()
        snapshotJob = viewModelScope.launch {
            socket.snapshots.collect { snapshot ->
                if (snapshot != null) {
                    dashboardState.updateSnapshot(snapshot)
                    val newlyAppeared = dashboardState.applySnapshot(snapshot.alerts)

                    _uiState.value = _uiState.value.copy(
                        deviceCount = snapshot.status.device_count,
                        openAlertCount = snapshot.status.open_alert_count,
                        securityScore = snapshot.status.security_score,
                        devices = snapshot.devices,
                        alerts = snapshot.alerts,
                    )

                    if (newlyAppeared.isNotEmpty()) {
                        AlertNotifier.notifyNewAlerts(getApplication(), newlyAppeared)
                    }
                }
            }
        }
    }

    private fun observeConnectivity(socket: DashboardSocket) {
        connectivityJob?.cancel()
        connectivityJob = viewModelScope.launch {
            socket.connected.collect { connected ->
                _uiState.value = _uiState.value.copy(socketConnected = connected)
            }
        }
    }

    private fun teardownSocket() {
        reconnectJob?.cancel()
        reconnectJob = null
        snapshotJob?.cancel()
        snapshotJob = null
        connectivityJob?.cancel()
        connectivityJob = null
        socket?.close()
        socket = null
        _uiState.value = _uiState.value.copy(socketConnected = false)
    }

    override fun onCleared() {
        super.onCleared()
        ProcessLifecycleOwner.get().lifecycle.removeObserver(processLifecycleObserver)
        teardownSocket()
    }
}
