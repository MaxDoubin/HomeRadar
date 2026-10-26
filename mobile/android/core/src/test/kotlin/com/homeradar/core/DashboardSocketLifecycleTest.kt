package com.homeradar.core

import com.homeradar.core.net.DashboardSocket
import com.homeradar.core.net.HomeRadarApiException
import com.homeradar.core.net.HomeRadarClient
import com.homeradar.core.net.SCAN_READ_TIMEOUT_SECONDS
import com.homeradar.core.net.SocketDisconnect
import com.homeradar.core.net.TOKEN_REJECTED_CLOSE_CODE
import com.homeradar.core.net.TokenProvider
import com.homeradar.core.net.isUnauthorized
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class DashboardSocketLifecycleTest {

    private lateinit var server: MockWebServer
    private val token = object : TokenProvider {
        override fun currentToken(): String = "tok"
    }

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    private fun baseUrl() = server.url("/").toString()

    @Test
    fun `server close with 4401 is reported as a rejected token and drops connected`() = runBlocking {
        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.close(TOKEN_REJECTED_CLOSE_CODE, "Pairing token was revoked")
                }
            }),
        )
        val socket = DashboardSocket(baseUrl(), token)
        val disconnect = async(start = CoroutineStart.UNDISPATCHED) { socket.disconnects.first() }
        socket.connect()

        val result = withTimeout(5_000) { disconnect.await() }
        assertEquals(TOKEN_REJECTED_CLOSE_CODE, result.closeCode)
        assertTrue(result.tokenRejected)
        assertFalse(socket.connected.value)
    }

    @Test
    fun `refused upgrade is reported as a handshake refusal, not a definitive rejection`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(403))
        val socket = DashboardSocket(baseUrl(), token)
        val disconnect = async(start = CoroutineStart.UNDISPATCHED) { socket.disconnects.first() }
        socket.connect()

        val result = withTimeout(5_000) { disconnect.await() }
        assertEquals(403, result.httpStatus)
        assertTrue(result.handshakeRefused)
        assertFalse(result.tokenRejected)
    }

    @Test
    fun `every failed attempt emits, so a reconnect loop keeps retrying`() = runBlocking {
        val deadPort = ServerSocket(0).use { it.localPort }
        val socket = DashboardSocket("http://127.0.0.1:$deadPort", token)
        val failures = async(start = CoroutineStart.UNDISPATCHED) { socket.disconnects.take(3).toList() }

        repeat(3) {
            socket.connect()
            delay(300)
        }

        val results = withTimeout(10_000) { failures.await() }
        assertEquals(3, results.size)
        results.forEach { assertFalse(it.tokenRejected) }
    }

    @Test
    fun `closing the socket ourselves does not emit a disconnect`() = runBlocking {
        server.enqueue(
            MockResponse().withWebSocketUpgrade(object : WebSocketListener() {
                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    webSocket.close(code, null)
                }
            }),
        )
        val socket = DashboardSocket(baseUrl(), token)
        val disconnect = async(start = CoroutineStart.UNDISPATCHED) {
            withTimeoutOrNull(1_500) { socket.disconnects.first() }
        }
        socket.connect()
        withTimeout(5_000) { socket.connected.first { it } }
        socket.close()

        assertNull(disconnect.await())
        assertFalse(socket.connected.value)
    }

    @Test
    fun `disconnect classification`() {
        assertTrue(SocketDisconnect(closeCode = 4401).tokenRejected)
        assertTrue(SocketDisconnect(httpStatus = 401).tokenRejected)
        assertFalse(SocketDisconnect(closeCode = 1000).tokenRejected)
        assertFalse(SocketDisconnect(httpStatus = 403).tokenRejected)
        assertTrue(SocketDisconnect(httpStatus = 403).handshakeRefused)
        assertFalse(SocketDisconnect().tokenRejected)
    }

    @Test
    fun `only a 401 api error counts as unpaired`() {
        assertTrue(HomeRadarApiException(401, "").isUnauthorized)
        assertFalse(HomeRadarApiException(403, "").isUnauthorized)
        assertFalse(HomeRadarApiException(500, "").isUnauthorized)
        assertFalse(IllegalStateException("x").isUnauthorized)
    }

    @Test
    fun `scan requests get a long read timeout while other calls keep the default`() {
        val client = HomeRadarClient(baseUrl(), token)
        assertEquals(SCAN_READ_TIMEOUT_SECONDS * 1_000, client.scanHttpClient.readTimeoutMillis.toLong())
    }
}
