package com.homeradar.core

import com.homeradar.core.net.AUTH_HEADER_NAME
import com.homeradar.core.net.HomeRadarClient
import com.homeradar.core.net.TokenProvider
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class HomeRadarClientRequestTest {

    private lateinit var server: MockWebServer

    private class FixedTokenProvider(private val token: String?) : TokenProvider {
        override fun currentToken(): String? = token
    }

    @BeforeEach
    fun startServer() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun stopServer() {
        server.shutdown()
    }

    private fun clientWithToken(token: String?): HomeRadarClient =
        HomeRadarClient(baseUrl = server.url("/").toString(), tokenProvider = FixedTokenProvider(token))

    @Test
    fun `getStatus sends a GET to status with the auth header present`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"device_count":3,"open_alert_count":1,"security_score":88,"dns_enabled":true,"blocklist_domains":120}"""
            )
        )
        val client = clientWithToken("secret-token")

        val status = client.getStatus()

        assertEquals(3, status.device_count)
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/status", request.path)
        assertEquals("secret-token", request.getHeader(AUTH_HEADER_NAME))
    }

    @Test
    fun `requests omit the auth header entirely when the token provider returns null`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"device_count":0,"open_alert_count":0,"security_score":100,"dns_enabled":false,"blocklist_domains":0}"""
            )
        )
        val client = clientWithToken(null)

        client.getStatus()

        val request = server.takeRequest()
        assertNull(request.getHeader(AUTH_HEADER_NAME))
    }

    @Test
    fun `getDashboard sends a GET to dashboard`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                    "status": {"device_count":1,"open_alert_count":0,"security_score":90,"dns_enabled":true,"blocklist_domains":5},
                    "devices": [],
                    "alerts": []
                }
                """.trimIndent()
            )
        )
        val client = clientWithToken("t")

        val dashboard = client.getDashboard()

        assertEquals(1, dashboard.status.device_count)
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/dashboard", request.path)
    }

    @Test
    fun `getDevices sends a GET to devices`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                [
                    {"id":1,"mac":"aa:bb:cc:dd:ee:ff","device_type":"router","trust_score":90,"is_authorized":1,
                     "first_seen":"2026-07-01T09:00:00.000000+00:00","last_seen":"2026-07-28T12:00:00.000000+00:00"}
                ]
                """.trimIndent()
            )
        )
        val client = clientWithToken("t")

        val devices = client.getDevices()

        assertEquals(1, devices.size)
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/devices", request.path)
    }

    @Test
    fun `patchDeviceAuthorization sends PATCH with a state body matching AuthorizationUpdate`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {"id":1,"mac":"aa:bb:cc:dd:ee:ff","device_type":"router","trust_score":90,"is_authorized":1,
                 "first_seen":"2026-07-01T09:00:00.000000+00:00","last_seen":"2026-07-28T12:00:00.000000+00:00"}
                """.trimIndent()
            )
        )
        val client = clientWithToken("t")

        val device = client.patchDeviceAuthorization(1, 1)

        assertEquals(1, device.is_authorized)
        val request = server.takeRequest()
        assertEquals("PATCH", request.method)
        assertEquals("/devices/1/authorization", request.path)
        assertEquals("""{"state":1}""", request.body.readUtf8())
        assertEquals("t", request.getHeader(AUTH_HEADER_NAME))
    }

    @Test
    fun `getAlerts appends the unresolved_only query param`() = runBlocking {
        server.enqueue(MockResponse().setBody("[]"))
        val client = clientWithToken("t")

        client.getAlerts(unresolvedOnly = true)

        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/alerts?unresolved_only=true", request.path)
    }

    @Test
    fun `patchAlertResolved sends PATCH with a resolved body matching AlertUpdate`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"id":42,"is_resolved":true}"""))
        val client = clientWithToken("t")

        val result = client.patchAlertResolved(42, resolved = true)

        assertEquals(42, result.id)
        assertEquals(true, result.is_resolved)
        val request = server.takeRequest()
        assertEquals("PATCH", request.method)
        assertEquals("/alerts/42", request.path)
        assertEquals("""{"resolved":true}""", request.body.readUtf8())
    }

    @Test
    fun `getSettings sends a GET to settings`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {"household_name":"Gee household","digest_email":"kristina@geefoundation.org",
                 "dns_upstream":"1.1.1.1","notifications_enabled":true,"dns_enabled":true,"setup_complete":true}
                """.trimIndent()
            )
        )
        val client = clientWithToken("t")

        val settings = client.getSettings()

        assertEquals("Gee household", settings.household_name)
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/settings", request.path)
    }

    @Test
    fun `patchSettings sends PATCH with only the provided keys`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {"household_name":"New name","digest_email":"kristina@geefoundation.org",
                 "dns_upstream":"1.1.1.1","notifications_enabled":false,"dns_enabled":true,"setup_complete":true}
                """.trimIndent()
            )
        )
        val client = clientWithToken("t")

        val settings = client.patchSettings(mapOf("household_name" to "New name", "notifications_enabled" to false))

        assertEquals("New name", settings.household_name)
        val request = server.takeRequest()
        assertEquals("PATCH", request.method)
        assertEquals("/settings", request.path)
        val body = request.body.readUtf8()
        assertEquals(true, body.contains(""""household_name":"New name""""))
        assertEquals(true, body.contains(""""notifications_enabled":false"""))
    }

    @Test
    fun `postScan sends a POST to scan`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"devices_found":2,"devices":[]}"""))
        val client = clientWithToken("t")

        val result = client.postScan()

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/scan", request.path)
        assertEquals(true, result.toString().contains("devices_found"))
    }

    @Test
    fun `claimPairingCode sends a POST with a code body and decodes the token`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"token":"abc123"}"""))
        val client = clientWithToken(null)

        val result = client.claimPairingCode("123456")

        assertEquals("abc123", result.token)
        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/pair/claim", request.path)
        assertEquals("""{"code":"123456"}""", request.body.readUtf8())
    }
}
