package com.homeradar.core

import com.homeradar.core.net.INITIAL_BACKOFF_MILLIS
import com.homeradar.core.net.MAX_BACKOFF_MILLIS
import com.homeradar.core.net.nextBackoffMillis
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure test of nextBackoffMillis() -- no real socket or timer involved, so
 * this runs in milliseconds.
 */
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

        // Still capped on further calls.
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
    fun `a fresh sequence restarts at the initial delay after any successful connection`() {
        // Simulate: backoff grew to the cap, then the caller reconnected successfully
        // and simply stops calling nextBackoffMillis until the next failure -- the
        // function itself holds no state, so the next sequence starts over cleanly.
        var delay = nextBackoffMillis(0L)
        delay = nextBackoffMillis(delay)
        delay = nextBackoffMillis(delay)
        delay = nextBackoffMillis(delay)
        assertEquals(15_000L, delay)

        val restarted = nextBackoffMillis(0L)
        assertEquals(2_500L, restarted)
    }
}
