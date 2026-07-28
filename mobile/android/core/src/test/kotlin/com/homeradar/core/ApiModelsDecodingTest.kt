package com.homeradar.core

import com.homeradar.core.model.Alert
import com.homeradar.core.model.AlertResolveResult
import com.homeradar.core.model.Device
import com.homeradar.core.model.HomeRadarJson
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime

class ApiModelsDecodingTest {

    // (a) Alert.is_resolved is a raw JSON int (0/1) on every GET/list/dashboard/websocket path.
    @Test
    fun `Alert decodes is_resolved as a raw int, not a boolean`() {
        val fixture = """
            {
                "id": 42,
                "device_id": 7,
                "severity": "high",
                "title": "New device joined the network",
                "description": "Unrecognized MAC address seen for the first time",
                "is_resolved": 0,
                "created_at": "2026-07-28T12:34:56.789012+00:00"
            }
        """.trimIndent()

        val alert = HomeRadarJson.decodeFromString<Alert>(fixture)

        assertEquals(0, alert.is_resolved)
        assertEquals(42, alert.id)
        assertEquals("high", alert.severity)
    }

    // (b) PATCH /alerts/{id} specifically returns is_resolved as a real JSON boolean,
    // via a genuinely different Pydantic-backed response shape.
    @Test
    fun `AlertResolveResult decodes is_resolved as a real boolean`() {
        val fixture = """{"id": 42, "is_resolved": true}"""

        val result = HomeRadarJson.decodeFromString<AlertResolveResult>(fixture)

        assertEquals(42, result.id)
        assertEquals(true, result.is_resolved)
    }

    // (c) Device JSON with an extra, undeclared "fingerprint" object decodes successfully
    // because the shared Json instance has ignoreUnknownKeys = true.
    @Test
    fun `Device tolerates an unmodeled fingerprint field thanks to ignoreUnknownKeys`() {
        val fixture = deviceFixtureWithFingerprint()

        val device = HomeRadarJson.decodeFromString<Device>(fixture)

        assertEquals(1, device.id)
        assertEquals("aa:bb:cc:dd:ee:ff", device.mac)
        assertEquals("router", device.device_type)
    }

    // Negative-control regression guard: the SAME fixture, decoded with a Json instance
    // that does NOT set ignoreUnknownKeys, must throw. This proves the flag on
    // HomeRadarJson is genuinely load-bearing, not decorative.
    @Test
    fun `the same fixture throws SerializationException without ignoreUnknownKeys`() {
        val fixture = deviceFixtureWithFingerprint()
        val strictJson = Json { ignoreUnknownKeys = false }

        assertThrows(SerializationException::class.java) {
            strictJson.decodeFromString<Device>(fixture)
        }
    }

    // Timestamps are modeled as plain String at the decode boundary, but a later UI
    // layer is expected to parse them with OffsetDateTime -- verify that format
    // compatibility empirically rather than assuming it.
    @Test
    fun `first_seen-style timestamps parse with OffsetDateTime`() {
        val timestamp = "2026-07-28T12:34:56.789012+00:00"

        val parsed = OffsetDateTime.parse(timestamp)

        assertEquals(2026, parsed.year)
        assertEquals(7, parsed.monthValue)
        assertEquals(28, parsed.dayOfMonth)
        assertEquals(12, parsed.hour)
        assertEquals(0, parsed.offset.totalSeconds)
    }

    private fun deviceFixtureWithFingerprint(): String = """
        {
            "id": 1,
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.1",
            "hostname": "gateway",
            "vendor": "Acme Networking",
            "model": "Router 3000",
            "device_type": "router",
            "fingerprint_confidence": 0.92,
            "open_ports": [80, 443],
            "services": ["http", "https"],
            "discovery_sources": ["arp", "mdns"],
            "trust_score": 95,
            "is_authorized": 1,
            "first_seen": "2026-07-01T09:00:00.000000+00:00",
            "last_seen": "2026-07-28T12:34:56.789012+00:00",
            "fingerprint": {"foo": "bar"}
        }
    """.trimIndent()
}
