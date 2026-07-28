package com.homeradar.core.net

import com.homeradar.core.model.HomeRadarJson
import com.homeradar.core.model.SnapshotMessage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.decodeFromString
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/** Pure exponential backoff schedule for websocket reconnect attempts. */
const val INITIAL_BACKOFF_MILLIS: Long = 2_500
const val MAX_BACKOFF_MILLIS: Long = 15_000

fun nextBackoffMillis(previousMillis: Long): Long {
    if (previousMillis < INITIAL_BACKOFF_MILLIS) return INITIAL_BACKOFF_MILLIS
    val doubled = previousMillis * 2
    return if (doubled > MAX_BACKOFF_MILLIS) MAX_BACKOFF_MILLIS else doubled
}

/** Build the real dashboard WebSocket path without embedding credentials. */
fun buildWsUrl(baseUrl: String, path: String = "/ws"): String =
    baseUrl.trimEnd('/') + path

/**
 * Listens to dashboard snapshots. The pairing token is attached as a WebSocket
 * upgrade header so it never appears in URLs, access logs, or crash reports.
 */
class DashboardSocket(
    private val baseUrl: String,
    private val tokenProvider: TokenProvider,
    private val httpClient: OkHttpClient = OkHttpClient(),
) : WebSocketListener() {

    private val _snapshots = MutableStateFlow<SnapshotMessage?>(null)
    val snapshots: StateFlow<SnapshotMessage?> = _snapshots.asStateFlow()

    private val _connected = MutableStateFlow(false)
    val connected: StateFlow<Boolean> = _connected.asStateFlow()

    private var webSocket: WebSocket? = null

    fun connect(path: String = "/ws") {
        val request = Request.Builder().url(buildWsUrl(baseUrl, path)).apply {
            tokenProvider.currentToken()?.takeIf { it.isNotBlank() }?.let {
                header(AUTH_HEADER_NAME, it)
            }
        }.build()
        webSocket = httpClient.newWebSocket(request, this)
    }

    fun close() {
        webSocket?.close(NORMAL_CLOSURE_CODE, null)
        webSocket = null
        _connected.value = false
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        _connected.value = true
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        runCatching { HomeRadarJson.decodeFromString<SnapshotMessage>(text) }
            .onSuccess { _snapshots.value = it }
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        _connected.value = false
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        _connected.value = false
    }

    private companion object {
        const val NORMAL_CLOSURE_CODE = 1000
    }
}
