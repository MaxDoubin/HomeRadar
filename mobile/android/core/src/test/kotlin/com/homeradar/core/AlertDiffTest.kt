package com.homeradar.core

import com.homeradar.core.model.Alert
import com.homeradar.core.state.DashboardState
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AlertDiffTest {

    private fun alert(id: Int, resolved: Int = 0): Alert = Alert(
        id = id,
        device_id = 1,
        severity = "medium",
        title = "Alert $id",
        description = null,
        is_resolved = resolved,
        created_at = "2026-07-28T12:00:00.000000+00:00",
    )

    @Test
    fun `the very first call returns empty regardless of what's in it`() {
        val state = DashboardState()

        val result = state.applySnapshot(listOf(alert(1), alert(2), alert(3)))

        assertTrue(result.isEmpty())
    }

    @Test
    fun `a second call with one brand-new unresolved alert returns exactly that one`() {
        val state = DashboardState()
        state.applySnapshot(listOf(alert(1), alert(2)))

        val result = state.applySnapshot(listOf(alert(1), alert(2), alert(3)))

        assertEquals(listOf(3), result.map { it.id })
    }

    @Test
    fun `a third call repeating the same id returns empty, no refire`() {
        val state = DashboardState()
        state.applySnapshot(listOf(alert(1), alert(2)))
        state.applySnapshot(listOf(alert(1), alert(2), alert(3)))

        val result = state.applySnapshot(listOf(alert(1), alert(2), alert(3)))

        assertTrue(result.isEmpty())
    }

    @Test
    fun `an alert that later disappears from the list doesn't error on the next call`() {
        val state = DashboardState()
        state.applySnapshot(listOf(alert(1), alert(2), alert(3)))
        state.applySnapshot(listOf(alert(1), alert(2), alert(3)))

        // Alert 3 got resolved and dropped from the unresolved feed entirely.
        val result = state.applySnapshot(listOf(alert(1), alert(2)))

        assertTrue(result.isEmpty())

        // And a genuinely new alert afterward still fires correctly.
        val next = state.applySnapshot(listOf(alert(1), alert(2), alert(4)))
        assertEquals(listOf(4), next.map { it.id })
    }

    @Test
    fun `resolved alerts present on the initial snapshot never notify later`() {
        val state = DashboardState()
        // id 5 is already resolved on the very first snapshot -- it should never
        // be treated as "new" even though it wasn't added to the seen set.
        state.applySnapshot(listOf(alert(1), alert(5, resolved = 1)))

        val result = state.applySnapshot(listOf(alert(1), alert(5, resolved = 1)))

        assertTrue(result.isEmpty())
    }
}
