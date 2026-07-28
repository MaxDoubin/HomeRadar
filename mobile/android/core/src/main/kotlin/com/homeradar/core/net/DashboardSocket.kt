package com.homeradar.core.net

import com.homeradar.core.model.HomeRadarJson
import com.homeradar.core.model.SnapshotMessage
import kotlinx.serialization.decodeFromString
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener

/**
 * Pure exponential backoff schedule for websocket reconnect attempts.
 *
 * Given the delay used for the previous attempt (or 0 / any value < the
 * starting delay for the very first attempt), returns the delay to use next:
 * starts at 2500ms, doubles each call, caps at 15000ms. So a fresh sequence
 * of calls produces 2500 -> 5000 -> 10000 -> 15000 -> 15000 -> ...
 *
 * This function is intentionally stateless -- callers reset back to the
 * start of the sequence simply by not calling it again until the next
 * disconnect (i.e. after any successful connection, forget the previous
 * value and start over from [INITIAL_BACKOFF_MILLIS] on the next failure).
 */
const val INITIAL_BACKOFF_MILLIS: Long = 2_500
const val MAX_BACKOFF_MILLIS: Long = 15_000

fun nextBackoffMillis(previousMillis: Long): Long {
    if (previousMillis < INITIAL_BACKOFF_MILLIS) return INITIAL_BACKOFF_MILLIS
    val doubled = previousMillis * 2
    return if (doubled > MAX_BACKOFF_MILLIS) MAX_BACKOFF_MILLIS else doubled
}

/**
 * Listens to the HomeRadar dashboard websocket and decodes each text frame as
 * a [SnapshotMessage], publishing the latest one via [snapshots]. Consumers
 * (e.g. a ViewModel-style wrapper in the `:app` module, added later) collect
 * the flow; this class has no Android dependency of its own.
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

    fun connect(path: String = "/ws/dashboard") {
        val wsUrl = baseUrl.trimEnd('/') + path
        val requestBuilder = Request.Builder().url(wsUrl)
        tokenProvider.currentToken()?.let { requestBuilder.header(AUTH_HEADER_NAME, it) }
        webSocket = httpClient.newWebSocket(requestBuilder.build(), this)
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
        val snapshot = HomeRadarJson.decodeFromString<SnapshotMessage>(text)
        _snapshots.value = snapshot
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
