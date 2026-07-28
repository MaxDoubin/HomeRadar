package com.homeradar.core

import com.homeradar.core.net.INITIAL_BACKOFF_MILLIS
import com.homeradar.core.net.MAX_BACKOFF_MILLIS
import com.homeradar.core.net.buildWsUrl
import com.homeradar.core.net.nextBackoffMillis
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class DashboardSocketReconnectTest {

    @Test
    fun `backoff sequence from a fresh start is 2500, 5000, 10000, 15000, capped at 15000`() {
        var delay = 0L
        delay = nextBackoffMillis(delay)
        assertEquals(2_500L, delay)
        delay = nextBackoffMillis(delay)
        assertEquals(5_000L, delay)
        delay = nextBackoffMillis(delay)
        assertEquals(10_000L, delay)
        delay = nextBackoffMillis(delay)
        assertEquals(15_000L, delay)
        delay = nextBackoffMillis(delay)
        assertEquals(15_000L, delay)
    }

    @Test
    fun `constants match the documented starting point and cap`() {
        assertEquals(2_500L, INITIAL_BACKOFF_MILLIS)
        assertEquals(15_000L, MAX_BACKOFF_MILLIS)
    }

    @Test
    fun `a fresh sequence restarts at the initial delay after success`() {
        var delay = nextBackoffMillis(0L)
        delay = nextBackoffMillis(delay)
        delay = nextBackoffMillis(delay)
        delay = nextBackoffMillis(delay)
        assertEquals(15_000L, delay)
        assertEquals(2_500L, nextBackoffMillis(0L))
    }

    @Test
    fun `websocket url uses the backend path and never contains a token`() {
        assertEquals("http://host:8000/ws", buildWsUrl("http://host:8000"))
        assertEquals("http://host:8000/ws", buildWsUrl("http://host:8000/"))
        assertEquals("http://host:8000/live", buildWsUrl("http://host:8000", path = "/live"))
        assertFalse(buildWsUrl("http://host:8000").contains("token="))
    }
}
